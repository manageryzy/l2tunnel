"""Optional local arbitration of fresh, physical repair and named repair work."""
from collections import OrderedDict, deque
from dataclasses import dataclass


@dataclass
class Job:
    path: int
    role: str
    bucket: int
    stage: str = "queued"


class SharedService:
    def __init__(self, direction):
        self.d = direction
        n = direction.cfg.n
        self.queues = [[OrderedDict() for _ in range(3)] for _ in range(n)]
        self.owners = {}
        self.frozen = {}
        self.debt = {}
        self.turn = [0]*n
        self.wake = False
        self.running = False
        self.requests = deque()
        self.standalone_due = False

    @staticmethod
    def bucket(role):
        if role == "fresh":
            return 0
        return 1 if role == "physical" else 2

    @staticmethod
    def token(path, key, role):
        # Extra negotiated response copies are independent paid work.
        return (*key, path if role == "named_copy" else None)

    def push(self, path, key, role):
        token = self.token(path, key, role)
        job = self.owners.get(token)
        if job:
            if role == "named" and job.bucket == 0 and job.stage == "queued":
                if self.d.arq[path].credit():
                    del self.queues[job.path][0][token]
                    job.path = path
                    job.bucket = 2
                    self.queues[path][2][token] = job
                    self.d.counts["a3_adopted_unstaged_fresh"] += 1
                    self.kick(path)
            elif role == "physical" and job.path != path:
                self.debt.setdefault(key, set()).add(path)
            self.d.counts["shared_unpaid_intents"] += 1
            self.d.counts["shared_with_" + job.stage] += 1
            return job.path
        job = Job(path, role, self.bucket(role))
        self.owners[token] = job
        self.queues[path][self.bucket(role)][token] = job
        self.kick(path)
        return path

    def control(self, kind, payload):
        self.requests.append((kind, payload))
        self.kick()

    def runnable(self, path):
        lane = self.d.lanes[path]
        return (self.d.arq[path].credit() and (any(self.queues[path]) or lane.ready is not None
                or lane.closed or (lane.deadline is not None and lane.deadline <= self.d.sim.now)))

    def kick(self, path=None):
        if self.wake or self.running:
            return
        if self.requests or self.standalone_due or (self.runnable(path) if path is not None else
                                          any(self.runnable(p) for p in range(self.d.cfg.n))):
            self.wake = True
            self.d.sim.at(self.d.sim.now, self.drive)

    def drive(self):
        self.wake = False
        self.running = True
        for _ in range(16):
            paid = False
            for path in range(self.d.cfg.n):
                if self.runnable(path):
                    paid |= self.visit(path)
            if self.requests:
                self.d.control_now(*self.requests.popleft())
                paid = True
            elif self.standalone_due:
                receiver = self.d.peer
                if receiver.ack_ready():
                    ack, payment = receiver.pending_ack()
                    self.d.control_now("ack", ack)
                    receiver.ack_sent(payment)
                    paid = True
                self.standalone_due = receiver.ack_ready()
            if not paid:
                break
        self.running = False
        self.kick()

    def visit(self, path):
        lane = self.d.lanes[path]
        queues = self.queues[path]
        for _ in range(64):
            order = ((self.turn[path] + i) % 3 for i in range(3))
            pick = next((i for i in order if queues[i]), None)
            if pick is None:
                break
            token, job = next(iter(queues[pick].items()))
            gid, ordinal, _ = token
            group = self.d.tx.get(gid)
            if group is None or (job.role == "physical" and self.covered(path, gid, ordinal)):
                del queues[pick][token]
                self.finish(token)
                continue
            if not self.d.enqueue_now(path, (gid, ordinal, group.parts[ordinal]), job.role):
                break
            del queues[pick][token]
            job.stage = "batched"
            self.turn[path] = (pick + 1) % 3
        # An already-due mutable head may collect entries in this pass. Its
        # original deadline is observed before returning to the event loop.
        if lane.ready is not None or lane.closed or (lane.deadline is not None and lane.deadline <= self.d.sim.now):
            return self.d.flush(path)
        return False

    def covered(self, path, gid, ordinal):
        return bool(self.d.arq[path].covered.get(gid, 0) & (1 << ordinal))

    def freeze(self, path, pn, entries, roles):
        tokens = []
        for (gid, ordinal, _), role in zip(entries, roles):
            if role == "spare":
                continue
            token = self.token(path, (gid, ordinal), role)
            if token in self.owners:
                self.owners[token].stage = "frozen"
                tokens.append(token)
        if tokens:
            self.frozen[path, pn] = tokens

    def paid(self, path, pn):
        for token in self.frozen.pop((path, pn), ()):
            self.finish(token)

    def finish(self, token):
        self.owners.pop(token, None)
        gid, ordinal, extra = token
        if extra is not None:
            return
        paths = self.debt.pop((gid, ordinal), ())
        for path in sorted(paths):
            if gid in self.d.tx and not self.covered(path, gid, ordinal):
                self.push(path, (gid, ordinal), "physical")

    def retired(self, gids):
        for key in list(self.debt):
            if key[0] in gids:
                del self.debt[key]
        for token, job in list(self.owners.items()):
            if token[0] in gids and job.stage == "queued":
                del self.queues[job.path][job.bucket][token]
                del self.owners[token]
