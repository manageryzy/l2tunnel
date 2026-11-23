/* Linux laboratory endpoint for pinned upstream C KCP, in one owned network namespace. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <lz4.h>
#include <openssl/evp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "ikcp.h"

enum { FRAME = 1514, WIRE = 1472, PREFIX = 5, TAG = 16, INNER = WIRE-PREFIX-TAG,
       KHEAD = 24, MSS = INNER-KHEAD, WINDOW = 8192, CREDIT = 4*1024*1024,
       MIN_WINDOW = 128, MAX_WINDOW = 16384,
       SLOTS = 4*MAX_WINDOW, HISTORY = 8192, TRACE_CAP = 262144,
       /* Largest encoded body (tag 2: 3+1514; tag 10 is always shorter). */
       BODY = FRAME+3,
       /* Pacing debits actual IPv4/UDP datagrams. A queued segment may later
        * leave alone, so its reservation includes its KCP header, the 21-byte
        * envelope and 28 IPv4/UDP bytes. */
       IPUDP = 28, SEG_COST = KHEAD+PREFIX+TAG+IPUDP,
       MAX_NATIVE_QUEUE = 65536 };

/* Optional benchmark parameters. Every default reproduces the original
 * unpaced, message-mode endpoint exactly. */
static struct {
    int window, nocwnd, flush_us, max_wait_us, udp_buffer, sample_ms;
    bool stream, reserve_fixed;
    double pace_bytes_per_s, pace_burst_ms;
    unsigned native_queue;
} opt = {WINDOW, 1, 0, -1, 0, 0, false, false, 0, 2, 0};

typedef unsigned long long count_t;
struct record { uint16_t size, pending; };
struct part { uint32_t sn, record; uint16_t size, frg; bool open; };
struct native_slot { uint16_t size; unsigned char data[FRAME]; };
static struct {
    double credit, min_credit;
    uint64_t last_us;
    count_t flushes;
    struct native_slot *queue;
    unsigned head, tail, peak;
    count_t queued_frames;
    unsigned char assembly[BODY+MSS];
    int assembled;
    uint64_t next_sample_us;
} x;
static bool extended(void) {
    return opt.window != WINDOW || opt.nocwnd != 1 || opt.flush_us || opt.max_wait_us >= 0 ||
           opt.udp_buffer || opt.sample_ms || opt.stream || opt.pace_bytes_per_s > 0 || opt.native_queue;
}
struct state {
    ikcpcb *kcp;
    EVP_CIPHER_CTX *tx, *rx;
    unsigned char keys[2][32];
    unsigned side;
    int udp, tap;
    bool compress;
    uint32_t pn, rx_high, history[HISTORY], next_sn, emitted, una, next_record;
    struct part parts[SLOTS];
    struct record records[SLOTS];
    unsigned credit, peak, pieces;
    unsigned char held[FRAME];
    int held_size;
    count_t accepted_frames, injected_frames, accepted_bytes, injected_bytes, lz4_frames;
    count_t sock_packets, socket_drops, sock_udp_bytes, local_input_packets, replay_drops, bad_tags;
    count_t push_fresh, push_repeat, ack, probe, report, fresh_bytes, repeat_bytes;
    count_t blocked_tap_writes;
    int sendbuf, recvbuf, max_udp_outq;
    count_t max_flush_packets, max_flush_udp_bytes;
};
static struct state s;
enum reason { NONE, FRESH, FAST, TIMEOUT, UNKNOWN };
enum outcome { PAID, REFUSED, INPUT };
struct trace_row {
    uint64_t begin_ns, end_ns;
    uint32_t current, pn, sn, ts, una, prior_deadline, deadline, rto, xmit;
    unsigned short wnd, bytes, ip_bytes;
    unsigned char cmd, frg, outcome, reason;
};
struct trace_history { uint32_t sn, deadline, xmit; };
static struct {
    struct trace_row *rows;
    struct trace_history *history;
    const struct IQUEUEHEAD *cursor;
    FILE *file;
    size_t count;
    count_t dropped, timeouts, unknown, mismatched_updates;
} trace;
static count_t callback_retries;
static volatile sig_atomic_t stopped;

static void fail(const char *reason) { fprintf(stderr, "%s (%s)\n", reason, strerror(errno)); exit(2); }
static void ensure(bool ok, const char *reason) { if (!ok) fail(reason); }
static uint64_t observation_ns(void) {
    struct timespec t;
    ensure(clock_gettime(CLOCK_MONOTONIC, &t) == 0, "trace monotonic clock");
    return (uint64_t)t.tv_sec*1000000000u + (uint64_t)t.tv_nsec;
}
static uint32_t clock_ms(void) {
    struct timespec t;
    ensure(clock_gettime(CLOCK_MONOTONIC, &t) == 0, "monotonic clock");
    return (uint32_t)((uint64_t)t.tv_sec*1000 + t.tv_nsec/1000000);
}
static uint64_t clock_us(void) {
    struct timespec t;
    ensure(clock_gettime(CLOCK_MONOTONIC, &t) == 0, "monotonic clock");
    return (uint64_t)t.tv_sec*1000000u + (uint64_t)t.tv_nsec/1000u;
}
static unsigned be16(const unsigned char *p) { return ((unsigned)p[0]<<8) | p[1]; }
static void set16(unsigned char *p, unsigned n) { p[0] = n>>8; p[1] = n; }
static uint32_t le32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static void terminate(int signum) { (void)signum; stopped = 1; }

static int encode(const unsigned char *frame, int n, unsigned char *body) {
    ensure(n >= 14 && n <= FRAME, "TAP frame extent");
    if (s.compress) {
        int size = LZ4_compress_default((const char *)frame, (char *)body+5, n, n-3);
        if (size > 0) {
            body[0] = 10; set16(body+1, size); set16(body+3, n);
            s.lz4_frames++;
            return size+5;
        }
    }
    body[0] = 2; set16(body+1, n); memcpy(body+3, frame, n);
    return n+3;
}
static int decode(const unsigned char *body, int n, unsigned char *frame) {
    ensure(n >= 3, "short KCP message");
    int size = be16(body+1);
    if (body[0] == 2 && size >= 14 && size <= FRAME && size+3 == n) {
        memcpy(frame, body+3, size);
        return size;
    }
    if (s.compress && body[0] == 10 && n >= 5 && size+5 == n) {
        int native = be16(body+3);
        ensure(native >= 14 && native <= FRAME && size+2 < native &&
               LZ4_decompress_safe((const char *)body+5, (char *)frame, size, native) == native,
               "invalid LZ4 block");
        return native;
    }
    fail("invalid native body");
    return 0;
}

/* Each original encoded message stays charged until every fragment has positive
 * confirmation at this sender. Sequence mapping is checked against real C PUSHes. */
/* Optional stream mode (`--stream`): upstream ikcp_send first extends the
 * unsent tail segment of snd_queue up to MSS, then appends new frg=0 segments.
 * The ledger mirrors that rule; the outgoing PUSH validator still checks every
 * C-assigned SN and size. A shared segment can hold parts of two frames, so
 * credit retires per confirmed segment byte count instead of per message. */
static int stream_tail_room(void) {
    if (!opt.stream || iqueue_is_empty(&s.kcp->snd_queue)) return 0;
    const struct IKCPSEG *old = iqueue_entry(s.kcp->snd_queue.prev, const struct IKCPSEG, node);
    const struct part *t = &s.parts[(s.next_sn-1) % SLOTS];
    ensure(s.next_sn > s.emitted && t->open && t->sn == s.next_sn-1 && t->size == old->len,
           "stream ledger tail differs from C snd_queue");
    return old->len < (uint32_t)MSS ? MSS-(int)old->len : 0;
}
static void admit_stream(int bytes, int room) {
    int extend = bytes < room ? bytes : room, left = bytes-extend;
    ensure(s.credit+bytes <= CREDIT, "source credit bound");
    if (extend) s.parts[(s.next_sn-1) % SLOTS].size += extend;
    unsigned total = left > 0 ? (unsigned)(left+MSS-1)/MSS : 0;
    for (unsigned i=0; i<total; i++) {
        uint32_t sn = s.next_sn++;
        struct part *p = &s.parts[sn % SLOTS];
        ensure(!p->open, "segment ledger bound");
        int rest = left-(int)i*MSS;
        *p = (struct part){sn, 0, rest < MSS ? rest : MSS, 0, true};
    }
    s.pieces += total; s.credit += bytes;
    if (s.credit > s.peak) s.peak = s.credit;
}
static void admit(int bytes) {
    unsigned total = (bytes+MSS-1)/MSS, id = s.next_record++;
    struct record *r = &s.records[id % SLOTS];
    ensure(r->pending == 0 && s.credit+bytes <= CREDIT, "source credit bound");
    r->size = bytes; r->pending = total;
    for (unsigned i=0; i<total; i++) {
        uint32_t sn = s.next_sn++;
        struct part *p = &s.parts[sn % SLOTS];
        ensure(!p->open, "segment ledger bound");
        int left = bytes-(int)i*MSS;
        *p = (struct part){sn, id, left < MSS ? left : MSS, total-i-1, true};
    }
    s.pieces += total; s.credit += bytes;
    if (s.credit > s.peak) s.peak = s.credit;
}
static void confirm(uint32_t sn) {
    struct part *p = &s.parts[sn % SLOTS];
    if (!p->open || p->sn != sn) return;
    p->open = false;
    s.pieces--;
    if (opt.stream) { s.credit -= p->size; return; }
    struct record *r = &s.records[p->record % SLOTS];
    ensure(r->pending != 0, "duplicate credit retirement");
    if (--r->pending == 0) s.credit -= r->size;
}

struct roles { unsigned fresh, retry, ack, probe, report, fresh_bytes, retry_bytes; };
static struct roles segments(const unsigned char *p, unsigned left, bool outgoing) {
    struct roles roles = {0};
    while (left) {
        ensure(left >= KHEAD, "truncated KCP header");
        uint32_t sn = le32(p+12), una = le32(p+16), size = le32(p+20);
        ensure(size <= left-KHEAD, "truncated KCP body");
        if (!outgoing) {
            ensure(una <= s.emitted && (p[4] != 82 || sn < s.emitted), "ACK of unsent SN");
            while (s.una < una) confirm(s.una++);
            if (p[4] == 82) confirm(sn);
        } else if (p[4] == 81) {
            if (sn >= s.emitted) {
                struct part *e = &s.parts[sn % SLOTS];
                ensure(sn == s.emitted && e->open && e->sn == sn && e->frg == p[5] && e->size == size,
                       "C PUSH differs from admitted segmentation");
                s.emitted++; roles.fresh++; roles.fresh_bytes += size;
            } else { roles.retry++; roles.retry_bytes += size; }
        } else if (p[4] == 82) roles.ack++;
        else if (p[4] == 83) roles.probe++;
        else if (p[4] == 84) roles.report++;
        else fail("unknown upstream KCP command");
        p += KHEAD+size; left -= KHEAD+size;
    }
    return roles;
}

/* The pinned engine visits snd_buf in SN order in each flush. No lookup runs
 * on an idle update. Prior deadlines come from the actual upstream segment,
 * including updates following a local output refusal. */
static void explain_push(struct trace_row *row) {
    const struct IQUEUEHEAD *head = &s.kcp->snd_buf;
    if (!trace.cursor) trace.cursor = head->next;
    while (trace.cursor != head) {
        const struct IKCPSEG *seg = iqueue_entry(trace.cursor, const struct IKCPSEG, node);
        if (seg->sn > row->sn) break;
        trace.cursor = trace.cursor->next;
        if (seg->sn != row->sn) continue;
        struct trace_history *old = &trace.history[row->sn % SLOTS];
        row->deadline = seg->resendts;
        row->rto = seg->rto;
        row->xmit = seg->xmit;
        if (seg->xmit == 1) row->reason = FRESH;
        else if (old->sn == row->sn && old->xmit + 1 == seg->xmit) {
            row->prior_deadline = old->deadline;
            /* Same half-range ordering as upstream _itimediff. Flush tests
             * expiry before fastack, and fastlimit uses pre-increment xmit. */
            if (row->current - old->deadline < UINT32_C(0x80000000)) {
                row->reason = TIMEOUT;
                trace.timeouts++;
            } else if (s.kcp->fastresend > 0 &&
                       (s.kcp->fastlimit <= 0 || old->xmit <= (unsigned)s.kcp->fastlimit)) {
                row->reason = FAST;
            }
        }
        *old = (struct trace_history){seg->sn, seg->resendts, seg->xmit};
        break;
    }
    if (row->reason == NONE) { row->reason = UNKNOWN; trace.unknown++; }
}
static void trace_packet(const unsigned char *p, unsigned size, uint32_t pn,
                         enum outcome result, uint64_t begin, uint64_t end) {
    unsigned left = size;
    while (left) {
        /* Called only after the instrument's existing segment validator. */
        struct trace_row row = {
            .begin_ns=begin, .end_ns=end, .current=s.kcp->current, .pn=pn, .cmd=p[4], .frg=p[5],
            .wnd=(unsigned short)(p[6] | ((unsigned)p[7]<<8)), .ts=le32(p+8), .sn=le32(p+12),
            .una=le32(p+16), .bytes=(unsigned short)le32(p+20), .ip_bytes=(unsigned short)(size+49),
            .outcome=result
        };
        if (result!=INPUT && row.cmd==81) explain_push(&row);
        if (trace.count < TRACE_CAP) trace.rows[trace.count++] = row;
        else trace.dropped++;
        left -= KHEAD+row.bytes;
        p += KHEAD+row.bytes;
    }
}
static void open_trace(const char *path) {
    int fd = open(path, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
    ensure(fd >= 0 && (trace.file=fdopen(fd,"w")) != NULL, "create private trace");
    trace.rows = calloc(TRACE_CAP, sizeof(*trace.rows));
    trace.history = calloc(SLOTS, sizeof(*trace.history));
    ensure(trace.rows && trace.history, "bounded KCP trace allocation");
}
static void publish_trace(void) {
    if (!trace.file) return;
    const char *outcomes[] = {"paid","refused","input"};
    const char *reasons[] = {"none","fresh","fast","timeout","unknown"};
    fputs("begin_ns,end_ns,outcome,reason,current,pn,cmd,frg,wnd,ts,sn,una,bytes,ip_bytes,xmit,prior_deadline,deadline,rto\n",trace.file);
    for (size_t i=0; i<trace.count; i++) {
        const struct trace_row *r=&trace.rows[i];
        fprintf(trace.file,"%llu,%llu,%s,%s,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
                (count_t)r->begin_ns,(count_t)r->end_ns,outcomes[r->outcome],reasons[r->reason],
                r->current,r->pn,r->cmd,r->frg,r->wnd,r->ts,r->sn,r->una,r->bytes,r->ip_bytes,
                r->xmit,r->prior_deadline,r->deadline,r->rto);
    }
    ensure(!ferror(trace.file) && fclose(trace.file)==0,"write bounded KCP trace");
    free(trace.history); free(trace.rows);
}

/* A fresh 32-byte AEAD key per direction per run. The five clear routing/PN
 * bytes are authenticated. A direction never reuses a nonce or wraps its PN. */
static bool protect(bool seal, unsigned char *wire, int size, unsigned char *plain) {
    EVP_CIPHER_CTX *ctx = seal ? s.tx : s.rx;
    unsigned char nonce[12] = {0};
    int len = 0, tail = 0;
    memcpy(nonce+8, wire+1, 4);
    ensure(EVP_CipherInit_ex(ctx, EVP_chacha20_poly1305(), NULL, s.keys[seal ? s.side : 1-s.side],
                             nonce, seal) == 1, "AEAD initialize");
    ensure(EVP_CipherUpdate(ctx, NULL, &len, wire, PREFIX) == 1, "AEAD associated header");
    unsigned char *out = seal ? wire+PREFIX : plain;
    ensure(EVP_CipherUpdate(ctx, out, &len, seal ? plain : wire+PREFIX, size) == 1 && len == size,
           "AEAD payload");
    if (!seal) ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG, wire+PREFIX+size) == 1, "AEAD set tag");
    if (EVP_CipherFinal_ex(ctx, out+len, &tail) != 1) return false;
    ensure(!tail, "unexpected AEAD tail");
    if (seal) ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG, wire+PREFIX+size) == 1, "AEAD get tag");
    return true;
}
static int output(const char *p, int size, ikcpcb *kcp, void *user) {
    (void)kcp; (void)user;
    uint64_t begin = trace.file ? observation_ns() : 0;
    ensure(size > 0 && size <= INNER && s.pn < UINT32_MAX, "KCP output extent/packet number");
    struct roles roles = segments((const unsigned char *)p, size, true);
    callback_retries += roles.retry;
    unsigned char wire[WIRE]; uint32_t pn = htonl(++s.pn);
    wire[0] = 1; memcpy(wire+1, &pn, 4);
    ensure(protect(true, wire, size, (unsigned char *)p), "AEAD seal");
    int extent = size+PREFIX+TAG;
    ssize_t sent;
    do { sent = send(s.udp, wire, extent, MSG_DONTWAIT); } while (sent < 0 && errno == EINTR);
    if (sent < 0 && (errno == EAGAIN || errno == ENOBUFS)) {
        if (trace.file) trace_packet((const unsigned char *)p,size,s.pn,REFUSED,begin,observation_ns());
        s.socket_drops++; return 0;
    }
    ensure(sent == extent, "UDP send");
    if (trace.file) trace_packet((const unsigned char *)p,size,s.pn,PAID,begin,observation_ns());
    s.sock_packets++; s.sock_udp_bytes += sent;
    if (opt.pace_bytes_per_s > 0) {
        /* Every accepted datagram, including ACKs and retries, debits credit.
         * Retry bursts can drive it negative: this is admission pacing, not a
         * physical rate ceiling. */
        x.credit -= (double)sent + IPUDP;
        if (x.credit < x.min_credit) x.min_credit = x.credit;
    }
    s.push_fresh += roles.fresh; s.push_repeat += roles.retry;
    s.fresh_bytes += roles.fresh_bytes; s.repeat_bytes += roles.retry_bytes;
    s.ack += roles.ack; s.probe += roles.probe; s.report += roles.report;
    return 0;
}
static void udp_input(void) {
    for (int i=0; i<64; i++) {
        unsigned char wire[WIRE], plain[INNER];
        ssize_t n = recv(s.udp, wire, sizeof(wire), MSG_DONTWAIT|MSG_TRUNC);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) return;
        ensure(n >= 0, "UDP receive");
        uint64_t begin = trace.file ? observation_ns() : 0;
        if (n < PREFIX+TAG+KHEAD || n > WIRE || wire[0] != 1 ||
            !protect(false, wire, n-PREFIX-TAG, plain)) { s.bad_tags++; continue; }
        uint32_t seq; memcpy(&seq, wire+1, 4); seq = ntohl(seq);
        if (!seq || (s.rx_high >= HISTORY && seq <= s.rx_high-HISTORY) ||
            s.history[seq % HISTORY] == seq) { s.replay_drops++; continue; }
        s.history[seq % HISTORY] = seq;
        if (seq > s.rx_high) s.rx_high = seq;
        int size = n-PREFIX-TAG;
        ensure(ikcp_input(s.kcp,(char *)plain,size) == 0, "upstream KCP input");
        uint64_t end = trace.file ? observation_ns() : 0;
        segments(plain, size, false);
        if (trace.file) trace_packet(plain,size,seq,INPUT,begin,end);
        ensure(s.pieces == (unsigned)ikcp_waitsnd(s.kcp), "send credit differs from C waitsnd");
        s.local_input_packets++;
    }
}
/* Optional token bucket (`--pace-mbit`): refilled from the monotonic clock and
 * capped at `--pace-burst-ms` of rate. */
static void pace_refill(void) {
    if (opt.pace_bytes_per_s <= 0) return;
    uint64_t now = clock_us();
    x.credit += (double)(now-x.last_us)*opt.pace_bytes_per_s/1e6;
    x.last_us = now;
    double cap = opt.pace_bytes_per_s*opt.pace_burst_ms/1000.0;
    if (x.credit > cap) x.credit = cap;
}
/* Reservation for data already queued in snd_queue but not yet sent. The
 * default `queued` form charges actual queued segment lengths, which keeps
 * small reverse ACK frames admissible; `fixed` charges a full packet per queued
 * segment plus one frame. */
static double queued_cost(void) {
    if (opt.reserve_fixed) return (double)s.kcp->nsnd_que*1500+1600;
    double cost = 0;
    for (const struct IQUEUEHEAD *p = s.kcp->snd_queue.next; p != &s.kcp->snd_queue; p = p->next)
        cost += iqueue_entry(p, const struct IKCPSEG, node)->len + SEG_COST;
    return cost+120;
}
static bool pace_allows(void) {
    return opt.pace_bytes_per_s <= 0 || x.credit > queued_cost();
}
static bool can_read_tap(void) {
    return s.credit+FRAME+3 <= CREDIT && ikcp_waitsnd(s.kcp)+2 <= opt.window && pace_allows();
}
static void submit(const unsigned char *frame, int n) {
    unsigned char body[BODY];
    int size = encode(frame, n, body), room = stream_tail_room();
    ensure(ikcp_send(s.kcp, (char *)body, size) >= 0, "upstream KCP admission");
    if (opt.stream) admit_stream(size, room); else admit(size);
    s.accepted_frames++; s.accepted_bytes += n;
}
static void tap_input(void) {
    for (int i=0; i<64 && can_read_tap(); i++) {
        unsigned char frame[FRAME+1];
        ssize_t n = read(s.tap, frame, sizeof(frame));
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) return;
        ensure(n >= 14 && n <= FRAME, "native read");
        submit(frame, n);
    }
}
/* Optional bounded native ingress ring (`--native-queue N`): drains TAP
 * independently of KCP admission so a small kernel TAP queue does not drop
 * frames while credit, window or pacing hold admission. Frames waiting here
 * are not yet accepted and are reported as terminal debt. */
static bool native_queue_full(void) { return x.tail-x.head >= opt.native_queue; }
static void tap_enqueue(void) {
    for (int i=0; i<256 && !native_queue_full(); i++) {
        struct native_slot *slot = &x.queue[x.tail % opt.native_queue];
        unsigned char frame[FRAME+1];
        ssize_t n = read(s.tap, frame, sizeof(frame));
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) return;
        ensure(n >= 14 && n <= FRAME, "native read");
        memcpy(slot->data, frame, n); slot->size = (uint16_t)n;
        x.tail++; x.queued_frames++;
        if (x.tail-x.head > x.peak) x.peak = x.tail-x.head;
    }
}
static void native_admit(void) {
    for (int i=0; i<64 && x.head != x.tail && can_read_tap(); i++) {
        struct native_slot *slot = &x.queue[x.head % opt.native_queue];
        submit(slot->data, slot->size);
        x.head++;
    }
}
/* Stream receive: KCP returns segment-sized pieces of one ordered byte stream.
 * The existing self-delimiting body headers (tag 2 length, tag 10 compressed
 * length) frame it; each complete body is validated by decode(). */
static int stream_body_extent(void) {
    const unsigned char *b = x.assembly;
    if (x.assembled < 3) return 0;
    if (b[0] == 2) {
        int size = be16(b+1);
        ensure(size >= 14 && size <= FRAME, "invalid stream raw body length");
        return size+3;
    }
    ensure(s.compress && b[0] == 10, "invalid stream body tag");
    if (x.assembled < 5) return 0;
    int size = be16(b+1);
    ensure(size > 0 && size+5 <= BODY, "invalid stream LZ4 body length");
    return size+5;
}
static bool stream_complete(void) {
    int extent = stream_body_extent();
    return extent && x.assembled >= extent;
}
static bool stream_next_frame(void) {
    for (;;) {
        int extent = stream_body_extent();
        if (extent && x.assembled >= extent) {
            s.held_size = decode(x.assembly, extent, s.held);
            x.assembled -= extent;
            memmove(x.assembly, x.assembly+extent, x.assembled);
            return true;
        }
        int n = ikcp_peeksize(s.kcp);
        if (n < 0) return false;
        ensure(n <= MSS && x.assembled+n <= (int)sizeof(x.assembly) &&
               ikcp_recv(s.kcp, (char *)x.assembly+x.assembled, n) == n,
               "upstream KCP stream delivery");
        x.assembled += n;
    }
}
static void tap_output(void) {
    for (int i=0; i<64; i++) {
        if (!s.held_size && opt.stream) {
            if (!stream_next_frame()) return;
        } else if (!s.held_size) {
            int n = ikcp_peeksize(s.kcp);
            if (n < 0) return;
            unsigned char body[FRAME+3];
            ensure(n <= (int)sizeof(body) && ikcp_recv(s.kcp, (char *)body, sizeof(body)) == n,
                   "upstream KCP message delivery");
            s.held_size = decode(body, n, s.held);
        }
        ssize_t n = write(s.tap, s.held, s.held_size);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) { s.blocked_tap_writes++; return; }
        ensure(n == s.held_size, "native complete write");
        s.injected_frames++; s.injected_bytes += n; s.held_size = 0;
    }
}

static void sockaddr_for(unsigned side, struct sockaddr_in *addr) {
    *addr = (struct sockaddr_in){.sin_family=AF_INET, .sin_port=htons(24440+side)};
    ensure(inet_pton(AF_INET, side ? "192.0.2.6" : "192.0.2.2", &addr->sin_addr)==1, "IPv4 literal");
}
static void devices(void) {
    struct stat host, here;
    ensure(stat("/proc/1/ns/net", &host)==0 && stat("/proc/self/ns/net", &here)==0 &&
           (host.st_ino!=here.st_ino || host.st_dev!=here.st_dev), "owned network namespace required");
    s.tap = open("/dev/net/tun", O_RDWR|O_NONBLOCK|O_CLOEXEC);
    ensure(s.tap >= 0, "open TUN driver");
    struct ifreq iface = {.ifr_flags=IFF_TAP|IFF_NO_PI};
    strcpy(iface.ifr_name, "tun0");
    ensure(ioctl(s.tap, TUNSETIFF, &iface)==0, "attach owned tun0 TAP");
    s.udp = socket(AF_INET, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
    struct sockaddr_in local, peer;
    sockaddr_for(s.side, &local); sockaddr_for(1-s.side, &peer);
    ensure(s.udp >= 0 && bind(s.udp, (void *)&local, sizeof(local))==0 &&
           connect(s.udp, (void *)&peer, sizeof(peer))==0, "owned connected UDP tuple");
}

static void stats(const char *path) {
    char buf[1024];
    ensure(snprintf(buf, sizeof(buf), "%s.pending", path) < (int)sizeof(buf), "stats pathname");
    FILE *f = fopen(buf, "w");
    ensure(f != NULL, "stats open");
    fprintf(f, "{\"accepted_frames\":%llu,\"injected_frames\":%llu,\"native_read_bytes\":%llu,"
            "\"native_written_bytes\":%llu,\"sent_lz4_frames\":%llu,\"socket_datagrams\":%llu,"
            "\"socket_udp_payload_bytes\":%llu,\"local_socket_drops\":%llu,\"udp_accepted\":%llu,"
            "\"bad_tags_or_extent\":%llu,\"replays\":%llu,\"fresh_push\":%llu,\"retry_push\":%llu,"
            "\"fresh_push_bytes\":%llu,\"retry_push_bytes\":%llu,\"ack_segments\":%llu,"
            "\"window_probes\":%llu,\"window_reports\":%llu,\"encoder_credit\":%u,"
            "\"send_buffer_bytes\":%d,\"receive_buffer_bytes\":%d,\"max_kernel_outq_bytes_after_flush\":%d,"
            "\"max_socket_datagrams_per_update\":%llu,\"max_udp_bytes_per_update\":%llu,"
            "\"peak_encoder_credit\":%u,\"waitsnd\":%d,\"rcv_queue\":%u,\"rcv_buf\":%u,"
            "\"pending_tap_frame\":%d,\"pending_ack_segments\":%u,\"tap_write_blocked\":%llu,",
            s.accepted_frames,s.injected_frames,s.accepted_bytes,s.injected_bytes,s.lz4_frames,
            s.sock_packets,s.sock_udp_bytes,s.socket_drops,s.local_input_packets,s.bad_tags,s.replay_drops,
            s.push_fresh,s.push_repeat,s.fresh_bytes,s.repeat_bytes,s.ack,s.probe,s.report,s.credit,
            s.sendbuf,s.recvbuf,s.max_udp_outq,s.max_flush_packets,s.max_flush_udp_bytes,s.peak,
            ikcp_waitsnd(s.kcp),s.kcp->nrcv_que,s.kcp->nrcv_buf,!!s.held_size,s.kcp->ackcount,s.blocked_tap_writes);
    if (extended())
        fprintf(f,"\"extensions\":{\"window\":%d,\"nocwnd\":%d,\"stream\":%s,\"pace_bytes_per_s\":%.0f,"
                "\"pace_burst_ms\":%g,\"pace_reserve\":\"%s\",\"pace_credit\":%.0f,\"min_pace_credit\":%.0f,"
                "\"native_queue_capacity\":%u,\"native_queue_frames\":%u,\"native_queue_peak\":%u,"
                "\"native_queue_read_frames\":%llu,\"stream_reassembly_bytes\":%d,\"flush_interval_us\":%d,"
                "\"explicit_flushes\":%llu,\"max_wait_us\":%d,\"requested_udp_buffer_bytes\":%d,"
                "\"sample_interval_ms\":%d,\"rx_srtt_ms\":%d,\"rx_rto_ms\":%d,\"snd_queue\":%u},",
                opt.window,opt.nocwnd,opt.stream ? "true" : "false",opt.pace_bytes_per_s,opt.pace_burst_ms,
                opt.reserve_fixed ? "fixed" : "queued",x.credit,x.min_credit,opt.native_queue,x.tail-x.head,
                x.peak,x.queued_frames,x.assembled,opt.flush_us,x.flushes,opt.max_wait_us,opt.udp_buffer,
                opt.sample_ms,s.kcp->rx_srtt,s.kcp->rx_rto,s.kcp->nsnd_que);
    fprintf(f,"\"engine_retry_callbacks\":%llu,\"engine_timeout_pushes\":%u,"
            "\"kcp_trace\":{\"enabled\":%s,\"capacity\":%u,\"rows\":%zu,\"dropped\":%llu,"
            "\"unknown_pushes\":%llu,\"timeout_mismatched_updates\":%llu}}\n",
            callback_retries,s.kcp->xmit,trace.file ? "true" : "false",trace.file ? TRACE_CAP : 0,
            trace.count,trace.dropped,trace.unknown,trace.mismatched_updates);
    ensure(!ferror(f) && fclose(f)==0 && rename(buf,path)==0, "stats commit");
}

/* The unprivileged socket fixture accepts only inherited AF_UNIX datagram FDs. */
static int fixture_fd(const char *text) {
    char *end;
    long fd = strtol(text, &end, 10);
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr), optlen = sizeof(int);
    int type;
    ensure(*text && !*end && fd >= 3 && fd <= 65535 &&
           getsockname(fd, (struct sockaddr *)&addr, &len) == 0 && addr.ss_family == AF_UNIX &&
           getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &optlen) == 0 && type == SOCK_DGRAM &&
           fcntl(fd, F_SETFL, O_NONBLOCK) == 0, "local datagram FD fixture");
    return fd;
}
static const char USAGE[] =
    "usage: endpoint a|b raw|lz4 KEYFILE STATS [--unix-fixture TAP_FD UDP_FD] [--trace-kcp CSV]"
    " [--window 128..16384] [--nocwnd 0|1] [--stream] [--pace-mbit R] [--pace-burst-ms MS]"
    " [--pace-reserve queued|fixed] [--native-queue FRAMES] [--flush-us US] [--max-wait-us US]"
    " [--udp-buffer-bytes N] [--sample-ms MS]";
static long integer(const char *text, long low, long high) {
    char *end;
    errno = 0;
    long value = strtol(text, &end, 10);
    ensure(*text && !*end && !errno && value >= low && value <= high, USAGE);
    return value;
}
static double decimal(const char *text, double low, double high) {
    char *end;
    errno = 0;
    double value = strtod(text, &end);
    ensure(*text && !*end && !errno && value >= low && value <= high, USAGE);
    return value;
}
/* Optional sample line on stdout, one per `--sample-ms`; bounded by run length. */
static void sample(void) {
    if (!opt.sample_ms) return;
    uint64_t now = clock_us();
    if (now < x.next_sample_us) return;
    printf("{\"at_us\":%llu,\"udp_payload_bytes\":%llu,\"packets\":%llu,\"srtt_ms\":%d,\"rto_ms\":%d,"
           "\"waiting\":%d,\"snd_queue\":%u,\"timeout_retransmits\":%u,\"pace_credit\":%.0f,"
           "\"native_queue_frames\":%u}\n",
           (count_t)now,s.sock_udp_bytes,s.sock_packets,s.kcp->rx_srtt,s.kcp->rx_rto,ikcp_waitsnd(s.kcp),
           s.kcp->nsnd_que,s.kcp->xmit,x.credit,x.tail-x.head);
    fflush(stdout);
    x.next_sample_us = now+(uint64_t)opt.sample_ms*1000u;
}
/* One engine pass (timer update or explicit flush) with the same trace and
 * per-flush socket accounting. */
static void engine(bool update, uint32_t now) {
    count_t previous = s.sock_packets, previous_bytes = s.sock_udp_bytes;
    uint32_t old_xmit = s.kcp->xmit;
    count_t old_timeouts = trace.timeouts;
    if (trace.file) trace.cursor = NULL;
    if (update) ikcp_update(s.kcp,now);
    else { ikcp_flush(s.kcp); x.flushes++; }
    if (trace.file && trace.timeouts-old_timeouts != (uint32_t)(s.kcp->xmit-old_xmit))
        trace.mismatched_updates++;
    if (s.sock_packets > previous) {
        count_t batch = s.sock_packets-previous, bytes = s.sock_udp_bytes-previous_bytes;
        if (batch > s.max_flush_packets) s.max_flush_packets = batch;
        if (bytes > s.max_flush_udp_bytes) s.max_flush_udp_bytes = bytes;
        int outq;
        ensure(ioctl(s.udp,TIOCOUTQ,&outq)==0, "read kernel transmit queue after flush");
        if (outq > s.max_udp_outq) s.max_udp_outq = outq;
    }
}
int main(int argc, char **argv) {
    const char *trace_path = NULL;
    const char *fixture_tap = NULL, *fixture_udp = NULL;
    ensure(argc >= 5 && (!strcmp(argv[1],"a") || !strcmp(argv[1],"b")) &&
           (!strcmp(argv[2],"raw") || !strcmp(argv[2],"lz4")), USAGE);
    for (int i=5; i<argc; i++) {
        const char *name = argv[i];
        bool more = i+1 < argc;
        if (!strcmp(name,"--unix-fixture") && i+2 < argc) { fixture_tap=argv[++i]; fixture_udp=argv[++i]; }
        else if (!strcmp(name,"--trace-kcp") && more) trace_path=argv[++i];
        else if (!strcmp(name,"--window") && more) opt.window=(int)integer(argv[++i],MIN_WINDOW,MAX_WINDOW);
        else if (!strcmp(name,"--nocwnd") && more) opt.nocwnd=(int)integer(argv[++i],0,1);
        else if (!strcmp(name,"--stream")) opt.stream=true;
        else if (!strcmp(name,"--pace-mbit") && more) opt.pace_bytes_per_s=decimal(argv[++i],0.001,100000)*1e6/8;
        else if (!strcmp(name,"--pace-burst-ms") && more) opt.pace_burst_ms=decimal(argv[++i],0.1,1000);
        else if (!strcmp(name,"--pace-reserve") && more) {
            const char *v=argv[++i];
            ensure(!strcmp(v,"queued") || !strcmp(v,"fixed"), USAGE);
            opt.reserve_fixed=!strcmp(v,"fixed");
        }
        else if (!strcmp(name,"--native-queue") && more) opt.native_queue=(unsigned)integer(argv[++i],1,MAX_NATIVE_QUEUE);
        else if (!strcmp(name,"--flush-us") && more) opt.flush_us=(int)integer(argv[++i],100,1000000);
        else if (!strcmp(name,"--max-wait-us") && more) opt.max_wait_us=(int)integer(argv[++i],0,1000000);
        else if (!strcmp(name,"--udp-buffer-bytes") && more) opt.udp_buffer=(int)integer(argv[++i],4096,256*1024*1024);
        else if (!strcmp(name,"--sample-ms") && more) opt.sample_ms=(int)integer(argv[++i],10,60000);
        else fail(USAGE);
    }
    bool fixture = fixture_tap != NULL;
    s.side = argv[1][0]=='b'; s.compress = !strcmp(argv[2],"lz4");
    int key = open(argv[3], O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    struct stat kst;
    ensure(key >= 0 && fstat(key,&kst)==0 && S_ISREG(kst.st_mode) && !(kst.st_mode&077) &&
           kst.st_size==(off_t)sizeof(s.keys) && read(key,s.keys,sizeof(s.keys))==(ssize_t)sizeof(s.keys),
           "two private one-run directional keys required");
    close(key);
    if (trace_path) open_trace(trace_path);
    if (opt.native_queue) ensure((x.queue = calloc(opt.native_queue, sizeof(*x.queue))) != NULL,
                                 "bounded native queue allocation");
    if (fixture) { s.tap=fixture_fd(fixture_tap); s.udp=fixture_fd(fixture_udp); }
    else devices();
    if (opt.udp_buffer)
        ensure(setsockopt(s.udp,SOL_SOCKET,SO_SNDBUF,&opt.udp_buffer,sizeof(int))==0 &&
               setsockopt(s.udp,SOL_SOCKET,SO_RCVBUF,&opt.udp_buffer,sizeof(int))==0, "set socket buffer limits");
    socklen_t optlen = sizeof(int);
    ensure(getsockopt(s.udp,SOL_SOCKET,SO_SNDBUF,&s.sendbuf,&optlen)==0 &&
           getsockopt(s.udp,SOL_SOCKET,SO_RCVBUF,&s.recvbuf,&optlen)==0, "read socket buffer limits");
    s.tx = EVP_CIPHER_CTX_new(); s.rx = EVP_CIPHER_CTX_new();
    s.kcp = ikcp_create(0x4c325443,NULL);
    ensure(s.tx && s.rx && s.kcp, "allocate endpoints");
    ikcp_setoutput(s.kcp, output);
    ensure(ikcp_setmtu(s.kcp,INNER)==0 && ikcp_wndsize(s.kcp,opt.window,opt.window)==0 &&
           ikcp_nodelay(s.kcp,1,10,2,opt.nocwnd)==0, "upstream configuration");
    s.kcp->stream = opt.stream;
    signal(SIGTERM, terminate); signal(SIGINT, terminate);
    puts("Ready"); fflush(stdout);
    uint32_t last = clock_ms();
    x.last_us = clock_us();
    uint64_t last_flush = x.last_us;
    while (!stopped) {
        uint32_t now = clock_ms();
        pace_refill();
        engine(true, now);
        if (opt.flush_us) {
            uint64_t now_us = clock_us();
            if (now_us-last_flush >= (uint64_t)opt.flush_us) { engine(false, now); last_flush = now_us; }
        }
        tap_output();
        if (opt.native_queue) native_admit();
        sample();
        if (now-last >= 200) { stats(argv[4]); last = now; }
        int wait = (int32_t)(ikcp_check(s.kcp,now)-now);
        bool tap_ready = s.held_size != 0 || ikcp_peeksize(s.kcp) >= 0 || (opt.stream && stream_complete());
        bool want_read = opt.native_queue ? !native_queue_full() : can_read_tap();
        struct pollfd ps[]={{s.udp,POLLIN,0},{s.tap,(want_read?POLLIN:0)|(tap_ready?POLLOUT:0),0}};
        int rc;
        if (opt.max_wait_us < 0) rc = poll(ps, 2, wait < 0 ? 0 : wait);
        else {
            long long micros = wait < 0 ? 0 : (long long)wait*1000;
            if (micros > opt.max_wait_us) micros = opt.max_wait_us;
            struct timespec timeout = {.tv_sec=micros/1000000, .tv_nsec=(micros%1000000)*1000};
            rc = ppoll(ps, 2, &timeout, NULL);
        }
        if (rc<0 && errno==EINTR) continue;
        ensure(rc>=0 && !((ps[0].revents|ps[1].revents)&(POLLERR|POLLHUP|POLLNVAL)), "poll endpoints");
        if (ps[0].revents&POLLIN) udp_input();
        if (ps[1].revents&POLLIN) { if (opt.native_queue) tap_enqueue(); else tap_input(); }
        if (opt.native_queue) { pace_refill(); native_admit(); }
    }
    stats(argv[4]); publish_trace(); ikcp_release(s.kcp); EVP_CIPHER_CTX_free(s.tx); EVP_CIPHER_CTX_free(s.rx);
    free(x.queue); close(s.udp); close(s.tap);
    return 0;
}
