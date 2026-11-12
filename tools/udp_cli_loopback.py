#!/usr/bin/env python3
"""Unprivileged loopback check of the CLI base UDP path through the shared service.

Starts a real serve and connect process on 127.0.0.1 with point-to-point VXLAN
devices, so no TAP/TUN, namespace or privilege is needed. It verifies member
authentication, the printed effective carrier profile, datagram profiling and
exact Ethernet frames in both directions for half and full duplex. It is a
functional check only: no impairment, throughput or native device behaviour.
Usage: udp_cli_loopback.py PATH_TO_L2TUNNELD
"""
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

binary = sys.argv[1]
work = pathlib.Path(tempfile.mkdtemp(prefix='l2tunnel-udp-cli-'))
run = lambda *a: subprocess.run(a, check=True, capture_output=True)
run(binary, 'keygen', '--private', str(work/'member.der'), '--public', str(work/'member.pub'))
run('openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(work/'server.pem'),'-out',str(work/'cert.pem'),'-days','1','-subj','/CN=lab.invalid','-addext','subjectAltName=DNS:lab.invalid','-addext','basicConstraints=critical,CA:FALSE')
run('openssl','x509','-in',str(work/'cert.pem'),'-outform','DER','-out',str(work/'cert.der'))
run('openssl','pkcs8','-topk8','-nocrypt','-in',str(work/'server.pem'),'-outform','DER','-out',str(work/'server.der'))
ok = True
base = 21000 + os.getpid() % 5000
for n, duplex in enumerate(('half', 'full')):
    p = [base + n*20 + i for i in range(12)]
    tcp, ua, ub, ra, rb, va, xa, vb, xb = p[:9]
    common = ['--layer','tap','--duplex',duplex,'--compression','off','--delivery-window','bdp','--forward-mbps','100','--reverse-mbps','10','--bootstrap-rtt-ms','70','--bdp-headroom-percent','125','--inflight-max-bytes','4194304','--inflight-max-records','8192','--carrier','udp','--udp-cover','quic-like','--udp-protection','aead','--path-mtu','1400','--profile-ms','200','--vni','7']
    def lanes(local, peer, rl, rp):
        o = ['--udp-bind',f'127.0.0.1:{local}','--udp-peer',f'127.0.0.1:{peer}']
        if duplex == 'half': o += ['--udp-reverse-bind',f'127.0.0.1:{rl}','--udp-reverse-peer',f'127.0.0.1:{rp}']
        return o
    slog = open(work/f'{duplex}-server.log','w'); clog = open(work/f'{duplex}-client.log','w')
    server = subprocess.Popen([binary,'serve','--listen',f'127.0.0.1:{tcp}','--cert',str(work/'cert.der'),'--key',str(work/'server.der'),'--allow-key',str(work/'member.pub'),'--vxlan-bind',f'127.0.0.1:{vb}','--vxlan-peer',f'127.0.0.1:{xb}',*common,*lanes(ub,ua,rb,ra)],stdout=slog,stderr=subprocess.STDOUT)
    time.sleep(0.5)
    client = subprocess.Popen([binary,'connect','--remote',f'127.0.0.1:{tcp}','--ca',str(work/'cert.der'),'--server-name','lab.invalid','--identity',str(work/'member.der'),'--vxlan-bind',f'127.0.0.1:{va}','--vxlan-peer',f'127.0.0.1:{xa}',*common,*lanes(ua,ub,ra,rb)],stdout=clog,stderr=subprocess.STDOUT)
    try:
        sa = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sa.bind(('127.0.0.1', xa)); sa.settimeout(0.3)
        sb = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sb.bind(('127.0.0.1', xb)); sb.settimeout(0.3)
        frame = lambda tag, size: bytes([2,0,0,0,0,2, 2,0,0,0,0,1]) + b'\x88\xb5' + bytes([tag]) * size
        vx = lambda f: struct.pack('!II', 0x08000000, 7 << 8) + f
        sent_ab = [frame(i, 46 + 150*i) for i in range(1, 9)]
        sent_ba = [frame(100+i, 1400 - 100*i) for i in range(1, 9)]
        got_ab, got_ba = [], []
        deadline = time.time() + 8
        while time.time() < deadline and (len(got_ab) < 8 or len(got_ba) < 8):
            if server.poll() is not None or client.poll() is not None: break
            for f in sent_ab[len(got_ab):len(got_ab)+1]: sa.sendto(vx(f), ('127.0.0.1', va))
            for f in sent_ba[len(got_ba):len(got_ba)+1]: sb.sendto(vx(f), ('127.0.0.1', vb))
            for sock, got, want in ((sb, got_ab, sent_ab), (sa, got_ba, sent_ba)):
                try:
                    data, _ = sock.recvfrom(4096)
                    if len(got) < 8 and data == vx(want[len(got)]): got.append(data)
                except socket.timeout: pass
        time.sleep(0.3)
        good = len(got_ab) == 8 and len(got_ba) == 8 and server.poll() is None and client.poll() is None
    finally:
        for proc in (client, server): proc.terminate()
        for proc in (client, server): proc.wait(timeout=5)
        sa.close(); sb.close(); slog.close(); clog.close()
    logs = {side: (work/f'{duplex}-{side}.log').read_text() for side in ('server','client')}
    for side, text in logs.items():
        for marker in ('Authenticated', 'Carrier: UDP with retained TCP/TLS', 'Recovery banks', '"event":"datagram_profile"'):
            if marker not in text: good = False; print(f'{duplex} {side}: missing {marker!r}')
    if 'Listening on' not in logs['server']: good = False; print('server never printed Listening')
    print(f'{duplex}: forwarded A->B {len(got_ab)}/8, B->A {len(got_ba)}/8, {"OK" if good else "FAILED"}')
    if not good:
        ok = False
        for side, text in logs.items(): print(f'--- {side}\n' + text[-1500:])
shutil.rmtree(work, ignore_errors=True)
if ok:
    print('CLI base UDP loopback passed for half and full duplex.')
sys.exit(0 if ok else 1)
