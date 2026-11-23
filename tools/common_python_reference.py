"""Fail-closed named comparison binding; no packet/configuration decoder or I/O owner."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = Path(__file__).with_name('common_python_references.json')
SUPPORTED = 'compact-arq-quic-overhead'
# Old manifests only bind their original source. Pin the separate live
# projection inventory without changing the historical manifest identifiers.
PROJECTION_REVIEW_SHA256 = 'c45e369dddb27f90c8a001eacc3b2593e7f88c28463185a9088a66c69b0c5642'
DIFFERENCES = frozenset(('codec_geometry', 'real_crypto_wire', 'kernel_tcp',
                         'finite_retry_history', 'acceptance_clock', 'measurement_window'))
PROJECTION = frozenset(('recovery', 'topology', 'owners_per_direction',
                       'source_window_per_owner', 'feedback_interval_us',
                       'feedback_packets', 'reverse_ack_path', 'nominal_rtt_us'))


def require(condition, message):
    if not condition:
        raise ValueError('Python comparison: ' + message)


def _pairs(values):
    result = {}
    for key, value in values:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def _nonfinite(_value):
    raise ValueError('Python comparison: nonfinite JSON value')


def _json(raw):
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_nonfinite)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def registry(path=REGISTRY):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'regular registry file required')
    with path.open('rb') as stream:
        raw = stream.read(256 * 1024 + 1)
    require(0 < len(raw) <= 256 * 1024, 'registry exceeds bound')
    value = _json(raw)
    require(isinstance(value, dict) and type(value.get('schema')) is int
            and value['schema'] == 1, 'unsupported registry schema')
    require(isinstance(value.get('references'), dict)
            and set(value['references']) == {SUPPORTED, 'packed-c46', 'packed-c47', 'packed-c48'},
            'named registry identity set differs')
    return value


def _reference(contract, values, source_root):
    ident = contract.get('id')
    require(type(ident) is str and ident in values['references'], 'unknown named reference')
    entry = values['references'][ident]
    require(isinstance(entry, dict) and entry.get('id') == ident, 'reference identity mismatch')
    expected = digest({key: value for key, value in entry.items() if key != 'sha256'})
    require(entry.get('sha256') == contract.get('reference_sha256') == expected,
            'full reference configuration/source digest differs')
    require(ident == SUPPORTED and entry.get('native_binding') == 'algorithm_configuration_only',
            'named shared Packed composition is not bound by this native profile')
    sources = entry.get('source_sha256')
    require(isinstance(sources, dict) and 0 < len(sources) <= 32, 'bounded source binding required')
    review = values.get('source_review', {})
    require(isinstance(review, dict), 'invalid projection source review')
    require(not review or digest(review) == PROJECTION_REVIEW_SHA256,
            'projection source review digest differs')
    reviewed = review.get('reviewed_projection_sha256', {})
    require(isinstance(reviewed, dict) and reviewed.keys() <= sources.keys(),
            'invalid reviewed source inventory')
    observed_changes = {}
    root = Path(source_root).resolve()
    for name, expected_hash in sources.items():
        require(type(name) is str and name.startswith('simulator/')
                and not Path(name).is_absolute() and '..' not in Path(name).parts,
                'invalid simulator source path')
        path = root / name
        require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root),
                'source binding file missing or redirected: ' + name)
        with path.open('rb') as stream:
            raw = stream.read(2 * 1024 * 1024 + 1)
        require(len(raw) <= 2 * 1024 * 1024, 'simulator source exceeds bound: ' + name)
        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_hash != expected_hash:
            require(review.get('id') == ident and review.get('reference_sha256') == expected
                    and reviewed.get(name) == actual_hash,
                    'simulator source changed; explicit reference review required: ' + name)
            observed_changes[name] = actual_hash
    return entry, {
        'historical_source_revision': review.get('historical_source_revision'),
        'checkout_matches_historical_sources': not observed_changes,
        'reviewed_checkout_differences_sha256': observed_changes,
    }


def _projection(actual, expected):
    require(isinstance(actual, dict) and set(actual) == PROJECTION, 'actual projection fields differ')
    require(isinstance(expected, dict) and set(expected) == PROJECTION, 'reference projection incomplete')
    for key in PROJECTION:
        require(type(actual[key]) is type(expected[key]) and actual[key] == expected[key],
                'actual algorithm configuration mismatch: ' + key)


def validate_row(row, *, require_comparable=False, source_root=ROOT, values=None):
    """Validate before namespace/socket creation; old rows remain unbound components."""
    contract = row.get('python_reference')
    if contract is None:
        require(not str(row.get('id', '')).startswith('python-'), 'named row is missing its binding')
        require(not require_comparable, 'unbound native component is not a Python comparison')
        return {'status': 'unbound_native_component', 'exact_native_equivalence': False}
    require(isinstance(contract, dict) and set(contract) == {
        'schema', 'id', 'reference_sha256', 'claim', 'actual', 'remaining_differences'},
        'contract fields differ')
    require(type(contract['schema']) is int and contract['schema'] == 1, 'unsupported contract schema')
    require(contract['claim'] == 'algorithm_configuration_only', 'unsupported equivalence claim')
    require(row.get('algorithm') == 'per_connection_compact', 'named row selects a different owner family')
    entry, source_verification = _reference(contract, registry() if values is None else values,
                                            source_root)
    _projection(contract['actual'], entry['required_actual'])
    differences = contract['remaining_differences']
    require(isinstance(differences, list) and all(type(item) is str for item in differences)
            and len(differences) == len(set(differences)) and set(differences) == DIFFERENCES,
            'known remaining differences must be complete and distinct')
    require(set(entry.get('remaining_differences', {})) == DIFFERENCES,
            'reference difference definitions are incomplete')
    require(not require_comparable, 'exact native comparison is unavailable: ' + ', '.join(sorted(DIFFERENCES)))
    return {'status': 'bound_algorithm_configuration_pending_offline_inspection',
            'reference_id': contract['id'], 'reference_sha256': entry['sha256'],
            'claim': contract['claim'], 'actual': contract['actual'],
            'reference_configuration': entry['configuration'],
            'reference_layout': entry['layout'], 'reference_behavior': entry['behavior'],
            'reference_scenario': entry['scenario'],
            'historical_observations': entry['observations'],
            'historical_provenance': entry['provenance'],
            'measurement_definition': 'Historical simulator results are reference metadata only. Actual native network, warmup, sample and flow settings are recorded in the current matrix plan; no repeat or equivalent measurement is implied.',
            'source_sha256': entry['source_sha256'],
            'source_verification': source_verification,
            'remaining_differences': entry['remaining_differences'],
            'exact_native_equivalence': False,
            'inspection': {},
            'scope': 'Selected recovery/topology fields only. Workload, kernel TCP, codec/wire, finite bounds and physical clock differences remain explicit.'}


def validate_inspection(row, side, text):
    """Require the actual decoder-derived selection from each offline daemon role."""
    require(side in ('a', 'b') and type(text) is str and len(text.encode()) <= 1024 * 1024,
            'inspection role or output bound invalid')
    lines = [line for line in text.splitlines() if line.strip()]
    require(0 < len(lines) <= 64 and all(len(line.encode()) <= 128 * 1024 for line in lines),
            'inspection event bound invalid')
    events = [_json(line) for line in lines]
    require(all(isinstance(event, dict) for event in events), 'inspection event is not an object')
    expected_event = ('secure_udp_common_requested_carrier_plan' if row.get('carrier') == 'raw'
                      else 'secure_udp_common_plan')
    plans = [event for event in events if event.get('event') in
             ('secure_udp_common_plan', 'secure_udp_common_requested_carrier_plan')]
    require(len(plans) == 1, 'exactly one actual plan inspection required')
    plan = plans[0]
    require(plan.get('event') == expected_event
            and type(plan.get('schema')) is int and plan['schema'] == 1
            and plan.get('validated') is True and plan.get('requested') is True
            and plan.get('authenticated') is False
            and plan.get('role') == ('initiator' if side == 'a' else 'responder'),
            'actual plan role or validation boundary differs')
    expected = row.get('expected_descriptor_hex')
    require(type(expected) is str and 0 < len(expected) <= 16384 and len(expected) % 2 == 0
            and re.fullmatch('[0-9a-f]+', expected) is not None,
            'bounded canonical descriptor required')
    require(plan.get('python_reference_descriptor_hex') == expected,
            'actual offline descriptor differs from requested manifest')
    _projection(plan.get('python_reference_actual'), row['python_reference']['actual'])
    return {'status': 'validated_decoder_derived_selection', 'role': plan['role'],
            'descriptor_sha256': hashlib.sha256(bytes.fromhex(expected)).hexdigest(),
            'actual': plan['python_reference_actual'],
            'scope': 'Offline requested plan validation; no authenticated session or native result implied.'}
