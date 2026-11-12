#!/usr/bin/env python3
"""Finite checksum-verified TCP payload probe for an already isolated lab."""
import argparse
from contextlib import nullcontext
import hashlib
import json
import random
import select
import socket
import time
from pathlib import Path

MAXIMUM = 1024 * 1024
PROGRESS_BYTES = 32768


def receive(stream, count, deadline=None):
    output = bytearray()
    while len(output) < count:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('progress record deadline exhausted')
            stream.settimeout(remaining)
        chunk = stream.recv(count - len(output))
        if not chunk:
            raise EOFError('short TCP payload')
        output.extend(chunk)
    return bytes(output)


def progress_record(stream, count, previous, checksum, deadline):
    """Strict bounded progress; the caller renews time only after valid advance."""
    kind = receive(stream, 1, deadline)
    if kind == b'P':
        current = int.from_bytes(receive(stream, 4, deadline), 'big')
        if previous >= count or current != min(previous + PROGRESS_BYTES, count):
            raise ValueError('invalid, duplicate or nonmonotonic payload progress')
        return current, False
    if kind == b'F' and previous == count:
        if receive(stream, 32, deadline) != checksum:
            raise ValueError('end-to-end payload checksum mismatch')
        return previous, True
    raise ValueError('unexpected progress record or premature final checksum')


def save_progress(records, current, started, journal):
    record = {'received_bytes': current, 'at_seconds': time.monotonic() - started}
    records.append(record)
    if journal is not None:
        journal.write(json.dumps(record) + '\n')
        journal.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=['listen', 'send'])
    parser.add_argument('address')
    parser.add_argument('--port', type=int, default=29001)
    parser.add_argument('--bytes', type=int, default=65536)
    parser.add_argument('--chunk-delay', type=float, default=0)
    parser.add_argument('--started-file', type=Path)
    parser.add_argument('--progress', action='store_true')
    parser.add_argument('--progress-file', type=Path)
    args = parser.parse_args()
    if not 1 <= args.bytes <= MAXIMUM:
        parser.error('bytes outside bounded probe range')
    if not 0 <= args.chunk_delay <= 0.1:
        parser.error('chunk delay outside bounded probe range')
    if args.progress_file is not None and (not args.progress or args.role != 'send'):
        parser.error('progress-file requires the progress sender')
    started = time.monotonic()
    overall_deadline = started + 180
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock, (args.progress_file.open('x') if args.progress_file is not None else nullcontext()) as journal:
        sock.settimeout(45)
        if args.role == 'listen':
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((args.address, args.port))
            sock.listen(1)
            print('Listening', flush=True)
            connection, _ = sock.accept()
            with connection:
                connection.settimeout(45)
                count = int.from_bytes(receive(connection, 4), 'big')
                if not 1 <= count <= MAXIMUM:
                    raise ValueError('peer exceeded probe byte bound')
                if args.progress:
                    digest = hashlib.sha256()
                    completed = 0
                    while completed < count:
                        digest.update(receive(connection, min(PROGRESS_BYTES, count - completed), min(overall_deadline, time.monotonic() + 45)))
                        completed = min(completed + PROGRESS_BYTES, count)
                        connection.settimeout(min(45, max(0.001, overall_deadline - time.monotonic())))
                        connection.sendall(b'P' + completed.to_bytes(4, 'big'))
                    connection.sendall(b'F' + digest.digest())
                else:
                    checksum = hashlib.sha256(receive(connection, count)).digest()
                    connection.sendall(checksum)
        else:
            payload = random.Random(0x12AA).randbytes(args.bytes)
            checksum = hashlib.sha256(payload).digest()
            sock.connect((args.address, args.port))
            sock.sendall(len(payload).to_bytes(4, 'big'))
            progress = []
            received = 0
            complete = False
            progress_deadline = min(overall_deadline, started + 45)
            for offset in range(0, len(payload), 4096):
                if args.progress:
                    remaining = min(overall_deadline, progress_deadline) - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('remote payload progress deadline exhausted')
                    sock.settimeout(remaining)
                sock.sendall(payload[offset:offset + 4096])
                if offset == 0 and args.started_file is not None:
                    with args.started_file.open('x') as marker:
                        marker.write('first payload chunk sent\n')
                if args.chunk_delay:
                    time.sleep(args.chunk_delay)
                if args.progress:
                    while not complete and select.select([sock], [], [], 0)[0]:
                        received, complete = progress_record(sock, len(payload), received, checksum, progress_deadline)
                        if not complete:
                            save_progress(progress, received, started, journal)
                            progress_deadline = min(overall_deadline, time.monotonic() + 45)
            if args.progress:
                while not complete:
                    received, complete = progress_record(sock, len(payload), received, checksum, progress_deadline)
                    if not complete:
                        save_progress(progress, received, started, journal)
                        progress_deadline = min(overall_deadline, time.monotonic() + 45)
            elif receive(sock, 32) != checksum:
                raise ValueError('end-to-end payload checksum mismatch')
            result = {'status': 'passed', 'bytes': len(payload), 'sha256': checksum.hex(), 'elapsed_seconds': time.monotonic() - started}
            if args.progress:
                result.update({'protocol': 'progress32k-v1', 'progress': progress, 'overall_timeout_seconds': 180, 'no_progress_timeout_seconds': 45})
            print(json.dumps(result))


if __name__ == '__main__':
    main()
