#!/usr/bin/env python3
"""Record finite CPU secure-record round trips from an explicitly prebuilt binary."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import signal
import statistics
import subprocess
import sys
import threading
import time

# Importing the source-hash helper must not write a cache outside fresh output.
sys.dont_write_bytecode = True
if __package__:
    from . import record_check
else:
    import record_check

SCOPE = 'local CPU seal-cover-parse-open round trips; no network or native devices'
CAPTURE_BYTES = 1 << 20
APPEARANCES = {'quic_like': 13, 'media_like': 14}
PROTECTIONS = {'chacha20_poly1305': 16, 'hmac_sha256': 32}
BODIES = (64, 512, 1340)
CASE_FIELDS = {
    'appearance', 'protection', 'body_bytes', 'iterations', 'elapsed_ns',
    'payload_bytes', 'packet_bytes', 'modeled_ipv4_wire_bytes',
    'ns_per_round_trip', 'payload_round_trip_gbit_per_second',
}
SUMMARY_METRICS = ('elapsed_ns', 'ns_per_round_trip', 'payload_round_trip_gbit_per_second')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON object key')
        result[key] = value
    return result


def _constant(_value):
    raise ValueError('nonfinite JSON constant')


def _integer(value, name, *, positive=False):
    if type(value) is not int or (positive and value <= 0):
        raise ValueError(f'{name} must be an integer' + (' greater than zero' if positive else ''))
    return value


def _metric(value, expected, tolerance, name):
    if type(value) not in (int, float):
        raise ValueError(f'{name} must be a finite number')
    try:
        valid = math.isfinite(value) and value >= 0 and math.isclose(
            value, expected, rel_tol=1e-12, abs_tol=tolerance)
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError(f'{name} is nonfinite, negative or inconsistent with counters')


def validate_result(raw: bytes, iterations: int) -> dict:
    """Validate the exact finite example schema and current packet accounting."""
    result = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_constant)
    if type(result) is not dict or set(result) != {'scope', 'cases'} or result['scope'] != SCOPE:
        raise ValueError('unexpected benchmark result schema or scope')
    cases = result['cases']
    if type(cases) is not list or len(cases) != 12:
        raise ValueError('exactly 12 benchmark cases are required')
    expected = {(appearance, protection, body) for appearance in APPEARANCES
                for protection in PROTECTIONS for body in BODIES}
    seen = set()
    for case in cases:
        if type(case) is not dict or set(case) != CASE_FIELDS:
            raise ValueError('unexpected benchmark case schema')
        appearance, protection = case['appearance'], case['protection']
        if type(appearance) is not str or type(protection) is not str:
            raise ValueError('appearance and protection must be strings')
        body = _integer(case['body_bytes'], 'body_bytes', positive=True)
        identity = appearance, protection, body
        if identity not in expected or identity in seen:
            raise ValueError('unknown or duplicate benchmark case')
        seen.add(identity)
        if _integer(case['iterations'], 'iterations', positive=True) != iterations:
            raise ValueError('iteration count differs from requested count')
        elapsed = _integer(case['elapsed_ns'], 'elapsed_ns', positive=True)
        payload = iterations * body
        packet = body + 9 + 10 + PROTECTIONS[protection] + APPEARANCES[appearance]
        for name, value in [('payload_bytes', payload), ('packet_bytes', packet),
                            ('modeled_ipv4_wire_bytes', iterations * (packet + 28))]:
            if _integer(case[name], name, positive=True) != value:
                raise ValueError(f'{name} differs from exact current accounting')
        try:
            ns_per_round_trip = elapsed / iterations
            gbit = payload * 8 / elapsed
        except OverflowError as error:
            raise ValueError('elapsed counter cannot produce finite metrics') from error
        _metric(case['ns_per_round_trip'], ns_per_round_trip, 0.000500001, 'ns_per_round_trip')
        _metric(case['payload_round_trip_gbit_per_second'], gbit, 0.000000500001,
                'payload_round_trip_gbit_per_second')
    if seen != expected:
        raise ValueError('missing benchmark case')
    return result


def _capture(pipe, path: Path, metadata: dict):
    digest = hashlib.sha256()
    retained = hashlib.sha256()
    total, stored = 0, 0
    try:
        with path.open('xb') as destination:
            while block := pipe.read(65536):
                digest.update(block)
                total += len(block)
                prefix = block[:max(0, CAPTURE_BYTES - stored)]
                destination.write(prefix)
                retained.update(prefix)
                stored += len(prefix)
    except OSError as error:
        metadata['error'] = str(error)
        # Drain the trusted child's pipe even if preserving output failed.
        while block := pipe.read(65536):
            digest.update(block)
            total += len(block)
    finally:
        pipe.close()
    metadata.update(total_bytes=total, retained_bytes=stored, truncated=total > stored,
                    sha256=digest.hexdigest(), retained_sha256=retained.hexdigest())


def _terminate(process):
    try:
        if os.name == 'posix':
            # The process owns this newly created session/group. This also closes
            # inherited pipes held by its descendants after the direct child exits.
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass


def _attempt(binary: Path, output: Path, index: int, iterations: int, timeout: float) -> dict:
    prefix = f'repetition-{index:02d}'
    stdout, stderr = output / f'{prefix}.stdout', output / f'{prefix}.stderr'
    command = [str(binary), str(iterations)]
    outcome = {'repetition': index, 'command': command, 'status': 'failed',
               'returncode': None, 'timed_out': False, 'errors': [],
               'stdout': {'path': stdout.name}, 'stderr': {'path': stderr.name}, 'result': None}
    outcome['started_utc'] = datetime.now(timezone.utc).isoformat()
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(command, cwd=output, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=os.name == 'posix')
    except OSError as error:
        outcome['errors'].append(f'invocation failed: {error}')
        for path, metadata in [(stdout, outcome['stdout']), (stderr, outcome['stderr'])]:
            path.write_bytes(b'')
            metadata.update(total_bytes=0, retained_bytes=0, truncated=False,
                            sha256=hashlib.sha256(b'').hexdigest(),
                            retained_sha256=hashlib.sha256(b'').hexdigest())
    else:
        threads = [threading.Thread(target=_capture, args=(pipe, path, metadata), daemon=True)
                   for pipe, path, metadata in [(process.stdout, stdout, outcome['stdout']),
                                                (process.stderr, stderr, outcome['stderr'])]]
        for thread in threads:
            thread.start()
        try:
            outcome['returncode'] = process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            outcome['timed_out'] = True
            outcome['errors'].append('per-repetition timeout exceeded')
            _terminate(process)
            outcome['returncode'] = process.wait()
        for thread in threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread in threads):
            if not outcome['timed_out']:
                outcome['timed_out'] = True
                outcome['errors'].append('per-repetition timeout exceeded while draining output')
            _terminate(process)
            for thread in threads:
                thread.join(timeout=1)
            if any(thread.is_alive() for thread in threads):
                outcome['errors'].append('output pipes did not drain after termination')
        if outcome['returncode'] != 0:
            outcome['errors'].append('benchmark exited unsuccessfully')
        if any(stream.get('truncated') or stream.get('error')
               for stream in (outcome['stdout'], outcome['stderr'])):
            outcome['errors'].append('raw process output exceeded capture bound or could not be retained')
        if not outcome['errors']:
            try:
                outcome['result'] = validate_result(stdout.read_bytes(), iterations)
            except (ValueError, UnicodeError, OverflowError, OSError, RecursionError) as error:
                outcome['errors'].append(f'invalid benchmark result: {error}')
        if not outcome['errors']:
            outcome['status'] = 'passed'
    outcome['finished_utc'] = datetime.now(timezone.utc).isoformat()
    (output / f'{prefix}.json').write_text(json.dumps(outcome, indent=2, allow_nan=False) + '\n')
    return outcome


def _summaries(attempts: list[dict], repetitions: int) -> list[dict]:
    summaries = []
    for appearance in APPEARANCES:
        for protection in PROTECTIONS:
            for body in BODIES:
                cases = [case for attempt in attempts if attempt['status'] == 'passed'
                         for case in attempt['result']['cases']
                         if (case['appearance'], case['protection'], case['body_bytes'])
                         == (appearance, protection, body)]
                metrics = {}
                for metric in SUMMARY_METRICS:
                    values = [case[metric] for case in cases]
                    metrics[metric] = ({'min': min(values), 'median': statistics.median(values),
                                        'max': max(values)} if values else None)
                summaries.append({'appearance': appearance, 'protection': protection,
                                  'body_bytes': body, 'samples': len(cases),
                                  'complete': len(cases) == repetitions, 'metrics': metrics})
    return summaries


def _identity(binary: Path) -> tuple[dict, list[str]]:
    result, errors = {'binary_sha256': None, 'source_hashes': None}, []
    try:
        if not binary.is_file():
            raise OSError('binary is not a regular file')
        with binary.open('rb') as source:
            result['binary_sha256'] = hashlib.file_digest(source, 'sha256').hexdigest()
    except OSError as error:
        errors.append(f'binary identity failed: {error}')
    try:
        result['source_hashes'] = record_check.hashes()
    except OSError as error:
        errors.append(f'source identity failed: {error}')
    return result, errors


def record(binary: Path, output: Path, iterations: int, repetitions: int = 3,
           timeout_seconds: float = 120) -> dict:
    """Run every requested attempt, preserving failure and observed source identity."""
    if type(iterations) is not int or not 1 <= iterations <= 1_000_000:
        raise ValueError('iterations must be within 1..1000000')
    if type(repetitions) is not int or not 1 <= repetitions <= 20:
        raise ValueError('repetitions must be within 1..20')
    if type(timeout_seconds) not in (float, int) or not math.isfinite(timeout_seconds) or not 0.01 <= timeout_seconds <= 3600:
        raise ValueError('timeout-seconds must be finite and within 0.01..3600')
    binary, output = binary.resolve(), output.resolve()
    output.mkdir(mode=0o700, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    before, errors = _identity(binary)
    attempts = [_attempt(binary, output, index, iterations, timeout_seconds)
                for index in range(1, repetitions + 1)]
    after, after_errors = _identity(binary)
    errors.extend(after_errors)
    before_sources, after_sources = before['source_hashes'], after['source_hashes']
    changed = (sorted(path for path in before_sources.keys() | after_sources.keys()
                      if before_sources.get(path) != after_sources.get(path))
               if before_sources is not None and after_sources is not None else None)
    binary_stable = before['binary_sha256'] is not None and before['binary_sha256'] == after['binary_sha256']
    source_stable = changed == []
    if not binary_stable:
        errors.append('binary identity missing or changed during recording')
    if not source_stable:
        errors.append('source identity missing or changed during recording')
    passed = not errors and all(attempt['status'] == 'passed' for attempt in attempts)
    receipt = {
        'schema_version': 1, 'status': 'passed' if passed else 'failed', 'scope': SCOPE,
        'limitations': 'CPU round-trip operations only; modeled IPv4 bytes are format accounting; no network, native, ISP/QoS or throughput guarantee',
        'started_utc': started, 'finished_utc': datetime.now(timezone.utc).isoformat(),
        'binary': str(binary), 'iterations': iterations, 'repetitions': repetitions,
        'timeout_seconds': timeout_seconds, 'stream_capture_bytes': CAPTURE_BYTES,
        'platform': {'system': platform.system(), 'release': platform.release(),
                     'machine': platform.machine(), 'python': platform.python_version()},
        'binary_stable_during_recording': binary_stable,
        'source_stable_during_recording': source_stable, 'changed_during_recording': changed,
        'identity_before': before, 'identity_after': after, 'errors': errors,
        'attempts': attempts, 'summary': _summaries(attempts, repetitions),
    }
    (output / 'performance.json').write_text(json.dumps(receipt, indent=2, allow_nan=False) + '\n')
    return receipt


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--iterations', required=True, type=int)
    parser.add_argument('--repetitions', type=int, default=3)
    parser.add_argument('--timeout-seconds', type=float, default=120)
    args = parser.parse_args(argv)
    try:
        receipt = record(args.binary, args.output, args.iterations, args.repetitions,
                         args.timeout_seconds)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(json.dumps({'status': receipt['status'], 'repetitions': receipt['repetitions'],
                      'receipt': str(args.output.resolve() / 'performance.json')}, indent=2))
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
