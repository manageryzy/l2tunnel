#!/usr/bin/env python3
"""Bounded native TCP flow-slot churn probe for an already isolated namespace."""
import argparse
import hashlib
import json
import random
import socket
import time

from tcp_probe import receive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=['listen', 'send'])
    parser.add_argument('address')
    parser.add_argument('--source-address')
    parser.add_argument('--port', type=int, default=29002)
    parser.add_argument('--source-port', type=int, default=31000)
    parser.add_argument('--flows', type=int, default=12)
    args = parser.parse_args()
    if not 1 <= args.flows <= 64 or not 1 <= args.source_port <= 65535 - args.flows:
        parser.error('flow/port range exceeds finite probe bounds')
    if args.role == 'send' and args.source_address is None:
        parser.error('sender needs an explicit source address')
    started = time.monotonic()
    flows = []
    if args.role == 'listen':
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.settimeout(45)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((args.address, args.port))
            listener.listen(2)
            print('Listening', flush=True)
            for index in range(args.flows):
                connection, peer = listener.accept()
                with connection:
                    connection.settimeout(45)
                    if peer[1] != args.source_port + index:
                        raise ValueError('unexpected source-port sequence')
                    payload = receive(connection, 4096)
                    connection.sendall(hashlib.sha256(payload).digest())
                    if connection.recv(1):
                        raise ValueError('unexpected trailing probe bytes')
    else:
        for index in range(args.flows):
            payload = random.Random(0x12AA + index).randbytes(4096)
            digest = hashlib.sha256(payload).digest()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
                stream.settimeout(45)
                stream.bind((args.source_address, args.source_port + index))
                stream.connect((args.address, args.port))
                stream.sendall(payload)
                stream.shutdown(socket.SHUT_WR)
                if receive(stream, 32) != digest or stream.recv(1):
                    raise ValueError('flow payload checksum or EOF mismatch')
            flows.append({'source_port': args.source_port + index, 'bytes': len(payload),
                          'sha256': digest.hex()})
        print(json.dumps({'status': 'passed', 'flows': flows,
                          'elapsed_seconds': time.monotonic() - started}))


if __name__ == '__main__':
    main()
