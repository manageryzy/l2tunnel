"""Inventory every saved run and plot payload-specific, condition-matched frontiers."""

import argparse
import ast
from collections import defaultdict
import csv
from hashlib import sha256
from html import escape
import json
from math import isfinite
from os.path import relpath
import re
from pathlib import Path

import numpy as np
from plotly.offline import get_plotlyjs

from l2tunnel_sim.stats import mean_ci


METRICS = ("goodput_mbps", "packet_extra_pct", "byte_extra_pct", "frame_p99_ms",
           "tcp_rtt_p99_ms", "tcp_ack_p99_ms", "tcp_all_segment_ack_p99_ms", "quic_rtt_p99_ms",
           "tcp_deadline_miss_pct", "tcp_syn_ping_p99_ms", "tcp_syn_ping_failure_pct",
           "tcp_syn_ping_background_goodput_mbps", "tcp_syn_probe_start_s")
AXES = ("packet_extra_pct", "byte_extra_pct", "tcp_syn_ping_p99_ms")
SYN_LATENCY = "tcp_syn_ping_p99_ms"
SYN_GOODPUT = "tcp_syn_ping_background_goodput_mbps"
STRATEGY_COLORS = {
    "Plain TCP": "#4c78a8",
    "QUIC": "#f58518",
    "KCP": "#e45756",
    "ARQ": "#79706e",
    "Compact ARQ": "#9467bd",
    "Block FEC": "#54a24b",
    "Sliding-window coding": "#159b9b",
    "Hybrid coding and ARQ": "#b79a20",
    "Shared compact coding": "#9d755d",
    "Aligned shared coding": "#d16ba5",
    "Compact wire coding": "#234c82",
    "Unclassified": "#777777",
}
CORE_FILES = ("model.py", "tcp.py", "compact.py")
CONDITIONS = ("payload_bytes", "forward_mbps", "reverse_mbps", "rtt_ms", "loss_rate", "loss_model",
              "mean_burst", "mtu", "duration_s", "warmup_s", "drain_s", "paths", "model", "version")
NUMERIC_CONDITIONS = ("payload_bytes", "forward_mbps", "reverse_mbps", "rtt_ms", "loss_rate", "mean_burst",
                      "mtu", "duration_s", "warmup_s", "drain_s")


def object_value(value):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return {}
    return value if isinstance(value, dict) else {}


def first(key, *sources, default=None):
    for source in sources:
        value = source.get(key)
        if value is not None and value != "":
            return value
    return default


def strategy_family(raw, profile, name):
    """Classify recorded protocol fields before consulting legacy strategy names."""
    mode = first("mode", profile, raw, default=first("kind", profile, raw, default=""))
    for value, family in (("quic", "QUIC"), ("kcp", "KCP"),
                          ("block", "Block FEC"), ("sliding", "Sliding-window coding"),
                          ("hybrid", "Hybrid coding and ARQ"), ("arq", "ARQ")):
        if mode == value:
            return family, f"recorded mode/kind={value}"
    wire = first("wire_format", profile, raw)
    wire_families = {"compact_wire": "Compact wire coding", "aligned_records": "Aligned shared coding",
                     "shared_records": "Shared compact coding"}
    if wire in wire_families:
        return wire_families[wire], f"recorded wire_format={wire}"
    recovery = first("recovery", profile, raw)
    transport = raw.get("transport", "")
    compact = object_value(profile.get("compact") or profile.get("config") or raw.get("compact"))
    if recovery == "shared_record_rlnc" or transport in ("shared_compact_inner_tcp", "shared_record_inner_tcp"):
        return "Shared compact coding", f"recorded recovery={recovery}, transport={transport}"
    if recovery == "block" or first("generation_sources", compact, profile, raw) is not None:
        return "Block FEC", "recorded block recovery or generation_sources"
    if compact or transport.startswith("compact_") or transport == "independent_full_l2_records":
        ratio = numeric(first("repair_ratio", compact, profile, raw))
        if ratio == 0 or (ratio is None and recovery == "arq"):
            return "Compact ARQ", "recorded compact recovery with zero repair ratio or ARQ"
        if (ratio is not None and ratio > 0) or recovery == "rlnc":
            return "Sliding-window coding", "recorded compact positive repair ratio or RLNC"
    if mode == "tcp":
        return "Plain TCP", "recorded mode/kind=tcp without a recorded tunnel format or recovery"
    if transport == "direct_tcp":
        return "Plain TCP", "recorded transport=direct_tcp"
    if transport in ("direct_quic", "quic_l2"):
        return "QUIC", f"recorded transport={transport}"
    legacy_names = ((r"(?:plain|direct) TCP\b", "Plain TCP"), (r"QUIC\b", "QUIC"),
                    (r"KCP\b", "KCP"), (r"ARQ\b", "ARQ"), (r"Block\b", "Block FEC"),
                    (r"Sliding\b", "Sliding-window coding"), (r"Hybrid\b", "Hybrid coding and ARQ"))
    for pattern, family in legacy_names:
        if re.match(pattern, name, re.I):
            return family, f"recorded legacy strategy name={name}"
    return "Unclassified", "recorded protocol fields do not identify a known family"


def numeric(value):
    try:
        result = float(value)
    except (ValueError, TypeError):
        return None
    return result if isfinite(result) else None


def boolean(value):
    return value is True or str(value).lower() == "true"


def source_hashes(manifest):
    result = {}
    for mapping in (manifest.get("sources"), manifest.get("source_sha256"),
                    object_value(manifest.get("provenance")).get("sources")):
        result.update({name: digest for name, digest in object_value(mapping).items()
                       if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)})
    return result


def comparison_version(manifest):
    """Match SYN comparisons by package, shared builder and recorded runtime."""
    sources = manifest["sources"]
    engine = {path: digest for path, digest in sources.items()
              if path.startswith("src/l2tunnel_sim/") or path == "studies/payload_sizes.py"}
    runtime = dict(manifest.get("dependencies", {}), **manifest.get("runtime", {}))
    runtime["python"] = manifest.get("python", runtime.get("python"))
    comparable_runtime = {name: runtime.get(name) for name in ("python", "numpy", "scipy", "aioquic")}
    identity = dict(sources=engine or sources, runtime=comparable_runtime)
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return "engine-" + sha256(encoded.encode()).hexdigest()[:12], runtime


def source_version(manifest, study):
    hashes = {Path(name).name: digest for name, digest in source_hashes(manifest).items()}
    if all(name in hashes for name in CORE_FILES):
        selected = {name: hashes[name] for name in CORE_FILES}
        return "core-" + sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest()[:12]
    # A missing member cannot be replaced by the version of today's checkout.
    if hashes:
        selected = {name: hashes[name] for name in CORE_FILES if name in hashes}
        return "partial-core-" + sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest()[:10] + "/" + study
    version = manifest.get("simulator_version")
    return "version-" + str(version) + "/" + study if version else "unhashed-" + study


def flatten(raw):
    result = dict(raw)
    for key in ("aggregate", "result", "measurement", "metrics"):
        nested = object_value(raw.get(key))
        if nested:
            result.pop(key, None)
            result.update(nested)
    return result


def literal(node):
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        return None


def verified_metadata(manifest, directory):
    """Read constants only from source bytes matching the recorded digest."""
    metadata, evidence, defaults, calls = {}, {}, {}, defaultdict(list)
    constructors = {"Scenario": ("rtt_ms", "loss_rate", "loss_model", "mtu", "mean_burst"),
                    "PathConfig": ("forward_mbps", "reverse_mbps", "rtt_factor", "jitter_ms")}
    simulator = Path(__file__).resolve().parents[1]
    for name, digest in source_hashes(manifest).items():
        path = Path(name)
        relative = str(path).split("simulator/", 1)[-1]
        candidates = [directory / "sources" / relative, path, simulator / relative]
        verified = next((p for p in candidates if p.is_file() and sha256(p.read_bytes()).hexdigest() == digest), None)
        if verified is None or (path.name != "config.py" and "studies" not in path.parts):
            continue
        tree = ast.parse(verified.read_text())
        label = f"verified source {name} sha256={digest}"
        if path.name == "config.py":
            for node in tree.body:
                if isinstance(node, ast.ClassDef) and node.name in constructors:
                    for field in node.body:
                        if isinstance(field, ast.AnnAssign) and isinstance(field.target, ast.Name):
                            value = literal(field.value)
                            if field.target.id in constructors[node.name] and value is not None:
                                defaults[(node.name, field.target.id)] = (value, label)
        else:
            for call in ast.walk(tree):
                if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
                    continue
                fields = constructors.get(call.func.id)
                if fields is None:
                    continue
                supplied = dict(zip(fields, call.args))
                supplied.update({item.arg: item.value for item in call.keywords if item.arg})
                unpacked = any(isinstance(arg, ast.Starred) for arg in call.args) or any(
                    item.arg is None for item in call.keywords)
                calls[call.func.id].append((supplied, unpacked, label))
    for constructor, instances in calls.items():
        for key in constructors[constructor]:
            values, labels = [], []
            for supplied, unpacked, label in instances:
                value = literal(supplied[key]) if key in supplied and not unpacked else None
                if key not in supplied and not unpacked and (constructor, key) in defaults:
                    value, default_label = defaults[(constructor, key)]
                    label += " omitted argument; " + default_label + " class default"
                if not isinstance(value, (int, float, str)):
                    break
                values.append(value)
                labels.append(label)
            if len(values) == len(instances) and len(set(values)) == 1:
                metadata[key] = values[0]
                evidence[key] = " | ".join(sorted(set(labels)))
    return metadata, evidence


def assumption_metadata(manifest):
    metadata, evidence = {}, {}
    patterns = (("payload_bytes", r"TCP payload (\d+(?:\.\d+)?) bytes", 1),
                ("mtu", r"MTU (\d+)", 1), ("rtt_ms", r"(\d+(?:\.\d+)?) ms RTT", 1),
                ("loss_rate", r"independent (\d+(?:\.\d+)?)% erasures", .01),
                ("forward_mbps", r"shared (\d+(?:\.\d+)?) Mbps forward", 1),
                ("reverse_mbps", r"and (\d+(?:\.\d+)?) Mbps reverse", 1))
    for index, text in enumerate(manifest.get("assumptions", [])):
        if not isinstance(text, str):
            continue
        for key, pattern, scale in patterns:
            match = re.search(pattern, text, re.I)
            if match:
                metadata[key] = float(match.group(1)) * scale
                evidence[key] = f"manifest.assumptions[{index}] {text}"
        if re.search(r"independent .*erasures", text, re.I):
            metadata["loss_model"] = "iid"
            evidence["loss_model"] = f"manifest.assumptions[{index}] {text}"
    return metadata, evidence


def task_for(raw, manifest):
    raw = flatten(raw)
    identifier = first("run_id", raw, default=raw.get("index"))
    found = {}
    for task in manifest.get("tasks", []):
        other = first("run_id", task, default=task.get("index"))
        if identifier is not None and str(other) == str(identifier):
            found = task
            break
    if not found and identifier is None:
        name = raw.get("strategy") or raw.get("name")
        matches = [task for task in manifest.get("tasks", [])
                   if name and first("name", object_value(task.get("strategy")),
                                     object_value(task.get("profile"))) == name]
        if len(matches) == 1:
            found = matches[0]
    return {**found, **object_value(raw.get("task"))}


def normalize(raw, task, manifest, study, source, row_number):
    raw = flatten(raw)
    config = object_value(manifest.get("config"))
    profile = object_value(raw.get("profile") or task.get("profile"))
    strategy = object_value(task.get("strategy_config") or task.get("strategy"))
    name = first("name", raw, profile, strategy)
    if not name:
        name = raw.get("strategy") or f"{study.split('/')[-1]} {Path(source).stem}"
    if not strategy and config.get("strategies"):
        strategy = next((s for s in config["strategies"] if s["name"] == name), {})
    if not profile:
        profile = strategy or {key: first(key, raw, task) for key in (
            "compact", "config", "recovery", "flow_count", "rto_min_ms", "reliable_acks", "controller",
            "payload_rate_mbps", "pacing_tcp_mbps", "window_bytes", "generation_sources", "repair_ratio", "repair_margin")
            if first(key, raw, task) is not None}
    profile = dict(profile)
    for key in ("flow_count", "window_policy", "payload_rate_mbps", "pacing_tcp_mbps"):
        item = first(key, profile, task, raw)
        if item is not None:
            profile[key] = item
    traffic = object_value(task.get("traffic_config") or task.get("traffic") or config.get("traffic"))
    traffic_design = {key: first(key, traffic, profile, raw) for key in (
        "frame_bytes", "window_bytes", "ack_every", "ack_delay_ms", "frame_interval_ms")
        if first(key, traffic, profile, raw) is not None}
    if traffic_design:
        profile["traffic"] = traffic_design
    for key in ("compact", "config"):
        if key in profile:
            profile[key] = object_value(profile[key])
    levels = [("raw", raw), ("task", task), ("profile", profile), ("config", config), ("manifest", manifest)]
    sources = []
    for label, level in levels:
        sources.append((label, level))
        for key in ("scenario", "traffic", "traffic_config", "path"):
            if object_value(level.get(key)):
                sources.append((label + "." + key, object_value(level[key])))
    singleton = {target: config[key][0] for key, target in (("loss_rates", "loss_rate"), ("rtt_ms", "rtt_ms"),
                 ("mtus", "mtu"), ("loss_models", "loss_model"))
                 if isinstance(config.get(key), list) and len(config[key]) == 1}
    sources.append(("manifest.config singleton", singleton))
    assumptions, assumption_evidence = assumption_metadata(manifest)
    sources.extend((("assumptions", assumptions), ("verified_source", manifest.get("_verified_metadata", {}))))
    provenance = {}

    def value(key, aliases=()):
        for label, mapping in sources:
            for candidate in (key, *aliases):
                item = mapping.get(candidate)
                if item is not None and item != "" and not isinstance(item, (dict, list)):
                    provenance[key] = (assumption_evidence.get(candidate) if label == "assumptions" else
                                       manifest.get("_verified_evidence", {}).get(candidate) if label == "verified_source" else
                                       label + "." + candidate)
                    return item
        return None

    row = {key: numeric(value(key, ("payload_bytes_per_frame",) if key == "payload_bytes" else ()))
           for key in NUMERIC_CONDITIONS}
    row["loss_model"] = value("loss_model")
    if row["loss_model"] != "burst":
        row["mean_burst"] = None
    paths = next((level["paths"] for _, level in levels if isinstance(level.get("paths"), list) and level["paths"]), [])
    if paths:
        selected = first("tcp_path", raw, strategy)
        selected_paths = [paths[int(selected)]] if selected not in (None, "") else paths
        for key in ("forward_mbps", "reverse_mbps"):
            if row[key] is None and all(numeric(path.get(key)) is not None for path in selected_paths):
                row[key] = sum(float(path[key]) for path in selected_paths)
                provenance[key] = "recorded paths, selected tcp_path" if selected is not None else "sum of recorded shared paths"
    row["paths"] = json.dumps(paths, sort_keys=True) if paths else "single path"
    delivered = numeric(first("tcp_delivered_frames", raw, default=raw.get("delivered_frames")))
    offered = numeric(raw.get("offered_frames"))
    acknowledged = numeric(raw.get("tcp_acked_frames"))
    if row["payload_bytes"] is None and delivered and numeric(raw.get("tcp_payload_bytes")) is not None:
        row["payload_bytes"] = numeric(raw["tcp_payload_bytes"]) / delivered
        provenance["payload_bytes"] = "raw.tcp_payload_bytes / raw.tcp_delivered_frames"
    goodput = numeric(first("application_goodput_mbps", raw, default=first("tcp_goodput_mbps", raw, default=raw.get("goodput_mbps"))))
    if row["duration_s"] is None and goodput and numeric(raw.get("tcp_payload_bytes_during_measurement")) is not None:
        row["duration_s"] = round(numeric(raw["tcp_payload_bytes_during_measurement"]) * 8 / goodput / 1e6, 9)
        provenance["duration_s"] = "raw measurement payload / raw goodput"
    # Whole-run metrics in the original generic runner have no excluded warmup.
    if row["warmup_s"] is None and (config.get("traffic") or task.get("traffic") or task.get("traffic_config")):
        row["warmup_s"] = 0
        provenance["warmup_s"] = "recorded full traffic interval; no warmup field in traffic configuration"
    complete_data = offered is not None and offered > 0 and delivered == offered
    ack_flag = raw.get("tcp_all_acknowledged")
    ack_known = ack_flag not in (None, "") or acknowledged is not None
    confirmed = boolean(ack_flag) if ack_flag not in (None, "") else complete_data and acknowledged == offered
    if acknowledged is not None and acknowledged != offered:
        confirmed = False
    compact = bool(profile.get("compact") or raw.get("compact") or "compact" in study.lower())
    outer = raw.get("outer_all_confirmed")
    outer_known = outer not in (None, "")
    outer_complete = boolean(outer) if outer_known else False
    if not outer_known and not compact:
        counters = [numeric(raw.get(key)) for key in ("forward_unconfirmed_symbols", "reverse_unconfirmed_symbols")]
        outer_known = all(item is not None for item in counters)
        outer_complete = outer_known and all(item == 0 for item in counters)
    completion_flags = {key: boolean(raw[key]) for key in ("fully_confirmed", "ack_all_flushed")
                        if raw.get(key) not in (None, "")}
    explicit_failure = any(not value for value in completion_flags.values())
    status = "complete" if complete_data and confirmed and outer_complete and not explicit_failure else "incomplete"
    known_failure = (ack_known and not confirmed) or (outer_known and not outer_complete) or explicit_failure
    if complete_data and not known_failure and (not ack_known or not outer_known):
        status = "confirmation unknown"
    execution_status = raw.get("execution_status")
    if execution_status == "unsupported":
        status = "unsupported"
    elif execution_status in ("error", "failed", "tool failure"):
        status = "tool failure"
    elif execution_status == "bound exhausted":
        status = "bound exhausted"
    quality = "recorded"
    diagnostic = ("before-tail-fix", "compact-tcp/pilot/", "compact-tcp/delta-pilot/",
                  "compact-tcp/paced-pilot/", "compact-block-pilot/", "l2-pareto/pilot.csv")
    if any(part in source for part in diagnostic):
        quality = "historical diagnostic"
    if raw.get("coding") == "ideal" or any(object_value(profile.get(k)).get("coding") == "ideal" for k in ("compact", "config")):
        quality = "idealized diagnostic"
    controller = str(first("tcp_controller", raw, default=first("controller", profile, task, default="")))
    transport = str(raw.get("transport", ""))
    model = ("fixed-window L2" if controller == "fixed_window" or raw.get("model") == "fixed_window_payload"
             or (not controller and transport in ("", "tunnel") and not compact)
             else "congestion-controlled transport")
    row.update(id=source + "#" + str(row_number), study=study, source=source, source_row=row_number,
               name=str(name), seed=first("seed", raw, task), replication=first("replication", raw, task),
               model=model, version=source_version(manifest, study), profile=json.dumps(profile, sort_keys=True),
               status=status, quality=quality, flow_count=first("flow_count", raw, profile, task),
               window_bytes=first("total_window_bytes", raw, default=first("window_bytes", raw, profile, task,
                                 object_value(task.get("traffic")), object_value(config.get("traffic")))),
               delivery_fraction=numeric(first("tcp_delivery_fraction", raw, default=raw.get("delivery_fraction"))),
               goodput_mbps=goodput, metadata_provenance=json.dumps(provenance, sort_keys=True),
               terminal_evidence=json.dumps(dict(data_complete=complete_data, ack_known=ack_known,
                                                 ack_complete=bool(confirmed), outer_known=outer_known,
                                                 outer_complete=bool(outer_complete),
                                                 completion_flags=completion_flags)))
    packets = numeric(first("forward_datagrams", raw, default=raw.get("forward_packets")))
    row["packet_extra_pct"] = 100 * (packets / delivered - 1) if packets is not None and delivered else None
    byte_count = numeric(raw.get("forward_wire_bytes"))
    payload_total = delivered * row["payload_bytes"] if delivered and row["payload_bytes"] else None
    row["byte_extra_pct"] = 100 * (byte_count / payload_total - 1) if byte_count is not None and payload_total else None
    row["frame_p99_ms"] = numeric(raw.get("with_drain_frame_p99_ms") if "with_drain_frame_p99_ms" in raw else raw.get("frame_p99_ms"))
    row["tcp_rtt_p99_ms"] = numeric(raw.get("tcp_timestamp_rtt_p99_ms"))
    row["tcp_ack_p99_ms"] = numeric(raw.get("with_drain_tcp_ack_rtt_p99_ms") if "with_drain_tcp_ack_rtt_p99_ms" in raw else raw.get("ack_rtt_p99_ms"))
    row["tcp_all_segment_ack_p99_ms"] = numeric(raw.get("with_drain_tcp_all_segment_ack_rtt_p99_ms"))
    deadline_miss = numeric(raw.get("with_drain_tcp_all_segment_ack_rtt_cohort_miss_fraction_upper"))
    row["tcp_deadline_miss_pct"] = 100 * deadline_miss if deadline_miss is not None else None
    row["quic_rtt_p99_ms"] = numeric(raw.get("quic_latest_rtt_p99_ms"))
    row["strategy_type"], row["strategy_type_evidence"] = strategy_family(raw, profile, str(name))
    row["execution_status"] = execution_status
    row["observation_status"] = raw.get("observation_status")
    row["execution_error"] = raw.get("error") or raw.get("error_message")
    for key in ("tcp_syn_ping_p99_ms", "tcp_syn_ping_failure_pct", "tcp_syn_ping_timeouts",
                "tcp_syn_ping_censored", "tcp_syn_ping_offered", "tcp_syn_ping_completed",
                "tcp_syn_ping_background_goodput_mbps", "tcp_syn_probe_start_s"):
        row[key] = numeric(raw.get(key))
    probe_config = first("tcp_syn_probe_config", raw, profile, default=profile.get("tcp_syn_probe"))
    probe_config = object_value(probe_config)
    row["tcp_syn_probe_config"] = json.dumps(probe_config, sort_keys=True)
    measurement_config = {key: value for key, value in probe_config.items()
                          if key not in ("reverse_copies", "copy_spacing_ms")}
    row["tcp_syn_probe_measurement_config"] = json.dumps(measurement_config, sort_keys=True)
    probe_flushed = raw.get("tcp_syn_probe_all_flushed")
    row["tcp_syn_probe_all_flushed"] = boolean(probe_flushed) if probe_flushed not in (None, "") else None
    steady_state = raw.get("tcp_syn_probe_steady_state_reached")
    row["tcp_syn_probe_steady_state_reached"] = boolean(steady_state) if steady_state not in (None, "") else None
    row["latency_periods"] = "frame, cumulative-ACK samples, and all-segment ACK completion through drain; TCP estimator and QUIC RTT during traffic"
    row["cohort"] = json.dumps([row[key] for key in CONDITIONS])
    payload = row["payload_bytes"]
    row["cohort_label"] = (f"{payload:g} B" if payload else "Unknown payload") + (
        f" | {row['forward_mbps']}/{row['reverse_mbps']} Mbps | RTT {row['rtt_ms']} ms"
        f" | loss {row['loss_rate']} {row['loss_model']} | MTU {row['mtu']}"
        f" | {row['duration_s']}s + drain {row['drain_s']}s | warmup {row['warmup_s']}s"
        f" | {model} | {row['version']}")
    required = [key for key in CONDITIONS if key != "mean_burst"]
    if row["loss_model"] == "burst":
        required.append("mean_burst")
    missing = [key for key in required if row[key] is None]
    row["eligible"] = status == "complete" and quality == "recorded" and not missing
    row["tcp_syn_ping_frontier_eligible"] = bool(
        row["eligible"] and row["tcp_syn_ping_offered"] is not None and row["tcp_syn_ping_offered"] > 0
        and row["tcp_syn_ping_completed"] == row["tcp_syn_ping_offered"]
        and row["tcp_syn_ping_failure_pct"] == 0 and row["tcp_syn_ping_timeouts"] == 0
        and row["tcp_syn_ping_censored"] == 0 and row["tcp_syn_ping_p99_ms"] is not None
        and row["tcp_syn_probe_all_flushed"] is not False
        and row["tcp_syn_probe_steady_state_reached"] is not False)
    row["exclusion_reason"] = "; ".join(([status] if status != "complete" else []) +
                                          ([quality] if quality != "recorded" else []) + ["unknown " + key for key in missing])
    return row


def is_observation(raw):
    return isinstance(raw, dict) and any(key in flatten(raw) for key in
           ("tcp_goodput_mbps", "application_goodput_mbps", "goodput_mbps", "offered_frames"))


def signature(raw):
    raw = flatten(raw)
    fields = (first("seed", raw), raw.get("offered_frames"),
              first("tcp_delivered_frames", raw, default=raw.get("delivered_frames")),
              raw.get("forward_wire_bytes"), first("forward_datagrams", raw, default=raw.get("forward_packets")),
              first("tcp_goodput_mbps", raw, default=first("application_goodput_mbps", raw, default=raw.get("goodput_mbps"))))
    if any(value in (None, "") for value in fields):
        status = first("execution_status", raw, default=raw.get("observation_status"))
        if status in ("unsupported", "error", "failed", "bound exhausted") and first("run_id", raw) is not None:
            return ("execution outcome", tuple(sorted((key, str(value)) for key, value in raw.items()
                                                     if value is not None and value != "")))
        return None
    return (str(fields[0]), *(numeric(value) for value in fields[1:]))


def export_origins(path, manifest, root):
    """Resolve only explicit export references, checking recorded hashes if present."""
    studies, sources = set(), set()
    references = [(name, None) for name in manifest.get("source_manifests", [])]
    references.extend(object_value(manifest.get("raw_inputs")).items())
    for name, details in object_value(manifest.get("studies")).items():
        references.append((str(path.parent.parent / name / "experiment.json"),
                           object_value(details).get("sha256")))
    sidecar = path.with_name("comparison-manifest.json")
    if path.name == "comparison-replications.csv" and sidecar.exists():
        details = json.loads(sidecar.read_text())
        references.extend((details[key], None) for key in ("baseline", "reliable") if key in details)
    for name, digest in references:
        candidates = (Path(name), path.parent / name, root / name, root.parent / name)
        resolved = next((candidate.resolve() for candidate in candidates if candidate.exists()), None)
        if resolved is None or not resolved.is_relative_to(root):
            continue
        if digest and (not resolved.is_file() or sha256(resolved.read_bytes()).hexdigest() != digest):
            continue
        if resolved.is_dir():
            studies.add(resolved.relative_to(root).as_posix())
        elif resolved.name in ("experiment.json", "manifest.json"):
            studies.add(resolved.parent.relative_to(root).as_posix())
        else:
            sources.add(resolved.relative_to(root).as_posix())
    return studies, sources


def generated_schema(records):
    """Report rows carry their original identity or a configuration-mean identity."""
    if not records:
        return None
    if all(str(row.get("id", "")).startswith("mean-") and "cohort" in row and "n" in row for row in records):
        return "derived configuration means"
    if all(row.get("source") and str(row.get("id", "")).startswith(row["source"] + "#")
           and "cohort" in row and "status" in row for row in records):
        return "derived normalized observations"
    return None


def analytical_references(path, records, rows, root):
    """Resolve reduced source tables using their analytical receipt and raw bytes."""
    sidecar = path.with_name("analysis.json")
    if path.name != "source-observations.csv" or not sidecar.is_file():
        return None
    try:
        analysis = json.loads(sidecar.read_text())
    except (ValueError, UnicodeError):
        return None
    if not isinstance(analysis, dict) or analysis.get("protocol_executions") != 0:
        return None
    known = {row["id"] for row in rows}
    candidates, issues = {}, []
    receipts = analysis.get("source_file_receipts", [])
    if not isinstance(receipts, list):
        issues.append("source_file_receipts is not a list")
        receipts = []
    for receipt in receipts:
        if not isinstance(receipt, dict) or not isinstance(receipt.get("path"), str):
            issues.append("invalid source receipt")
            continue
        name, digest = receipt["path"], receipt.get("sha256")
        locations = (Path(name), path.parent / name, root / name, root.parent / name)
        source = next((item.resolve() for item in locations if item.is_file()), None)
        if source is None or not source.is_relative_to(root):
            issues.append(f"unavailable or out-of-root source {name}")
            continue
        if sha256(source.read_bytes()).hexdigest() != digest:
            issues.append(f"source digest mismatch {name}")
            continue
        if source.suffix != ".json":
            continue
        try:
            original = json.loads(source.read_text())
        except (ValueError, UnicodeError):
            issues.append(f"unreadable source {name}")
            continue
        originals = original if isinstance(original, list) else [original]
        for index, raw in enumerate(originals, 1):
            identifier = source.relative_to(root).as_posix() + "#" + str(index)
            if identifier in known and is_observation(raw):
                candidates[identifier] = flatten(raw)
    aliases, unresolved = [], []
    for index, raw in enumerate(records, 1):
        matches = [identifier for identifier, original in candidates.items()
                   if all(key in original and str(original[key]) == str(value)
                          for key, value in raw.items())]
        if len(matches) == 1:
            aliases.append(matches[0])
        else:
            unresolved.append(dict(source_row=index, recorded_fields=raw,
                                   reason="no unique field-matched, digest-verified imported source",
                                   matching_source_ids=matches))
    return dict(alias_targets=aliases, unresolved_references=unresolved, receipt_issues=issues)


def source_file_references(path, records, rows, root):
    """Verify explicitly linked report rows without treating them as executions."""
    if not any("source_file" in row and "source_sha256" in row for row in records):
        return None
    known = {row["id"] for row in rows}
    aliases, unresolved, issues = [], [], []
    renamed = {"original_segments": "offered_frames", "acknowledged_segments": "tcp_acked_frames",
               "encapsulation": "forward_encapsulation", "throughput_latency_gate": "rtt_budget_met",
               "legacy_packet_gate": "packet_cost_target_met"}
    for index, reference in enumerate(records, 1):
        name = reference.get("source_file", "")
        locations = (path.parent / name, Path(name), root / name, root.parent / name)
        source = next((item.resolve() for item in locations if name and item.is_file()), None)
        originals, matches, reason = [], [], "no unique identity-matched imported source"
        if source is None or not source.is_relative_to(root):
            reason = "unavailable or out-of-root source"
        elif sha256(source.read_bytes()).hexdigest() != reference.get("source_sha256"):
            reason = "source digest mismatch"
        else:
            try:
                original = json.loads(source.read_text())
                originals = original if isinstance(original, list) else [original]
            except (ValueError, UnicodeError):
                reason = "unreadable JSON source"
        for source_index, raw in enumerate(originals, 1):
            identifier = source.relative_to(root).as_posix() + "#" + str(source_index)
            if identifier not in known or not is_observation(raw):
                continue
            original = flatten(raw)
            identities = [key for key in ("run_id", "index", "seed", "replication") if key in original]
            if not identities or any(key not in reference or str(reference[key]) != str(original[key])
                                     for key in identities):
                reason = "source identity mismatch or missing identity fields"
                continue
            expected = dict(original)
            expected.update({target: original.get(key) for target, key in renamed.items()})
            profile = object_value(original.get("profile"))
            compact = object_value(profile.get("compact"))
            expected.update(wire_format=first("wire_format", original, profile),
                            repair_ratio=first("repair_ratio", original, compact),
                            payload_pacing_mbps=first("payload_rate_mbps", original, profile))
            compared = {key: value for key, value in reference.items() if key in expected and key != "profile"}
            if any(str(value) != str(expected[key]) for key, value in compared.items()):
                reason = "source metric or configuration mismatch"
                continue
            if "profile" in reference:
                recorded_profile = reference["profile"]
                profile_matches = (str(recorded_profile) == str(original.get("profile"))
                                   or bool(profile) and object_value(recorded_profile) == profile
                                   or str(recorded_profile) in (str(original.get("strategy")), str(profile.get("name"))))
                if not profile_matches:
                    reason = "source profile mismatch"
                    continue
            matches.append(identifier)
        if len(matches) == 1:
            aliases.append(matches[0])
        else:
            unresolved.append(dict(source_row=index, recorded_fields=reference, reason=reason,
                                   matching_source_ids=matches))
            issues.append(f"row {index}: {reason}")
    return dict(alias_targets=aliases, unresolved_references=unresolved, receipt_issues=issues)


def load_all(root, output):
    csv.field_size_limit(max(csv.field_size_limit(), 16 * 1024 * 1024))
    root, output = root.resolve(), output.resolve()
    rows, inventory, manifests = [], [], {}
    signatures, observations = defaultdict(list), defaultdict(list)
    json_counts = defaultdict(int)
    raw_files, csv_files = [], []
    ignored = lambda p: output == p or output in p.parents or "sources" in p.relative_to(root).parts
    for path in sorted(root.rglob("*.json")):
        if ignored(path):
            continue
        try:
            data = json.loads(path.read_text())
        except (ValueError, UnicodeError):
            inventory.append(dict(study=path.relative_to(root).as_posix(), raw_runs=0, input_rows=0,
                                  alias_rows=0, state="unreadable JSON", detail="parse failure, file retained"))
            continue
        if path.name in ("experiment.json", "manifest.json"):
            data = {"tasks": data} if isinstance(data, list) else data
            if isinstance(data, dict):
                if path.parent not in manifests or path.name == "experiment.json":
                    manifests[path.parent] = data
        elif path.name == "execution-attempts.json" and isinstance(data, dict):
            inventory.append(dict(study=path.relative_to(root).as_posix(), raw_runs=0, input_rows=0,
                                  alias_rows=0, state="recorded execution attempts", detail=json.dumps(data, sort_keys=True)))
        elif is_observation(data):
            raw_files.append((path, data, 1))
        elif isinstance(data, list):
            raw_files.extend((path, item, index) for index, item in enumerate(data, 1) if is_observation(item))
    for directory, manifest in manifests.items():
        values, evidence = verified_metadata(manifest, directory)
        manifest["_verified_metadata"], manifest["_verified_evidence"] = values, evidence

    def context(path):
        directory = path.parent.parent if path.parent.name == "runs" else path.parent
        manifest = manifests.get(directory, {})
        if path.name == "pilot.csv" and path.with_name("pilot-config.json").exists():
            data = json.loads(path.with_name("pilot-config.json").read_text())
            manifest = {"tasks": data} if isinstance(data, list) else {"config": data}
        return directory, manifest

    def add(raw, path, index, directory, manifest):
        study, source = directory.relative_to(root).as_posix(), path.relative_to(root).as_posix()
        row = normalize(raw, task_for(raw, manifest), manifest, study, source, index)
        row["source_kind"] = path.suffix[1:].upper()
        key = signature(raw)
        row["same_outcome_as"] = json.dumps([previous["id"] for previous in signatures.get(key, [])]) if key else "[]"
        rows.append(row)
        observations[directory].append(flatten(raw))
        if key is not None:
            signatures[key].append(row)

    for path, raw, index in raw_files:
        directory, manifest = context(path)
        add(raw, path, index, directory, manifest)
        json_counts[directory] += 1
    for directory, count in sorted(json_counts.items()):
        inventory.append(dict(study=directory.relative_to(root).as_posix(), raw_runs=count, input_rows=count,
                              alias_rows=0, state="raw JSON observations", detail=f"{count} saved runs"))
    for path in sorted(root.rglob("*.csv")):
        if ignored(path):
            continue
        with path.open(newline="") as stream:
            records = list(csv.DictReader(stream))
        if not records or not any(is_observation(row) for row in records):
            continue
        directory, manifest = context(path)
        origins = export_origins(path, manifest, root)
        csv_files.append((path, records, directory, manifest, origins))
    # Raw CSV-only studies must be available before exports that reference them.
    csv_files.sort(key=lambda item: bool(item[4][0] or item[4][1] or generated_schema(item[1])))
    for path, records, directory, manifest, (origin_studies, origin_sources) in csv_files:
        reference_kind = "digest-verified source-file references"
        references = source_file_references(path, records, rows, root)
        if references is None:
            reference_kind = "analytical source references"
            references = analytical_references(path, records, rows, root)
        if references is not None:
            aliases, unresolved = references["alias_targets"], references["unresolved_references"]
            inventory.append(dict(study=path.relative_to(root).as_posix(), raw_runs=0,
                                  input_rows=len(records), alias_rows=len(aliases),
                                  unresolved_alias_rows=len(unresolved), state=reference_kind,
                                  alias_targets=json.dumps(aliases),
                                  unresolved_references=json.dumps(unresolved, sort_keys=True),
                                  receipt_issues=json.dumps(references["receipt_issues"]),
                                  detail=f"{len(records)} source references; {len(aliases)} verified original runs; "
                                         f"{len(unresolved)} unresolved references retained in inventory"))
            continue
        added, alias_ids = 0, []
        state = generated_schema(records)
        if state == "derived normalized observations":
            known = {row["id"] for row in rows}
            alias_ids = [raw["id"] for raw in records if raw["id"] in known]
        elif "flow_id" in records[0]:
            state = "component measurements"
        elif path.name in ("summary.csv", "configuration-means.csv", "frontiers.csv", "latency-validation-summary.csv",
                           "screen-summary.csv", "screen-frontiers.csv"):
            state = "derived summary"
        elif state is None:
            study = directory.relative_to(root).as_posix()
            for index, raw in enumerate(records, 1):
                matches = [previous for previous in signatures.get(signature(raw), [])
                           if (previous["study"] == study and previous["source_kind"] == "JSON")
                           or previous["study"] in origin_studies or previous["source"] in origin_sources]
                source_study = raw.get("source_study")
                if source_study and origin_studies:
                    matches = [previous for previous in matches
                               if previous["study"] in (source_study, str(Path(study).parent / source_study))]
                if matches:
                    alias_ids.append(matches[0]["id"])
                else:
                    add(raw, path, index, directory, manifest)
                    added += 1
            state = "raw CSV observations" if added else "verified duplicate export"
        unresolved = len(records) - len(alias_ids) if state == "derived normalized observations" else 0
        inventory.append(dict(study=path.relative_to(root).as_posix(), raw_runs=added, input_rows=len(records),
                              alias_rows=len(alias_ids), unresolved_alias_rows=unresolved, state=state,
                              alias_targets=json.dumps(alias_ids),
                              detail=f"{len(records)} rows; {len(alias_ids)} provenance-scoped aliases; "
                                     f"{added} additional observations; {unresolved} unresolved normalized references"))
    for directory, manifest in sorted(manifests.items()):
        tasks = manifest.get("tasks", [])
        if str(manifest.get("record_kind", "")).startswith(("analytic_", "coding_only_")):
            planned = manifest.get("analytic_tasks", tasks)
            if isinstance(planned, list) and planned:
                inventory.append(dict(study=directory.relative_to(root).as_posix(), raw_runs=0, input_rows=0,
                                      alias_rows=0, planned_tasks=len(planned), state="analytical task manifest",
                                      detail=f"{len(planned)} planned analytical tasks; executed-case coverage is "
                                             "recorded separately in the study report"))
            continue
        if not tasks:
            continue
        saved = observations[directory]
        saved_ids = {str(first("run_id", row, default=row.get("index"))) for row in saved
                     if first("run_id", row, default=row.get("index")) is not None}
        expected = {str(first("run_id", task, default=task.get("index"))) for task in tasks
                    if first("run_id", task, default=task.get("index")) is not None}
        missing = sorted(expected - saved_ids)
        inventory.append(dict(study=directory.relative_to(root).as_posix(), raw_runs=0, input_rows=0, alias_rows=0,
                              planned_tasks=len(tasks), saved_observations=len(saved), missing_task_ids=json.dumps(missing),
                              state="planned task coverage", detail=f"{len(tasks)} planned tasks; {len(saved)} saved observations; "
                              + (f"{len(missing)} missing task IDs {missing}" if expected else "task IDs unavailable")))
    if len({row["id"] for row in rows}) != len(rows):
        raise ValueError("A raw observation was imported more than once")
    return rows, inventory


def summarize(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[(row["cohort"], row["study"], row["name"], row["profile"], row["tcp_syn_probe_config"])].append(row)
    output = []
    for records in groups.values():
        first_row = records[0]
        summary = {key: first_row[key] for key in ("cohort", "cohort_label", "study", "name", "profile",
                   "payload_bytes", "version", "model", "strategy_type", "tcp_syn_probe_config",
                   "tcp_syn_probe_measurement_config")}
        summary.update(n=len(records), confirmed=sum(r["status"] == "complete" for r in records),
                       eligible=all(r["eligible"] for r in records), quality=first_row["quality"],
                       tcp_syn_ping_frontier_eligible=all(r["tcp_syn_ping_frontier_eligible"] for r in records),
                       id="mean-" + sha256("|".join(r["id"] for r in records).encode()).hexdigest()[:12])
        gate_values = [row["tcp_syn_probe_steady_state_reached"] for row in records]
        summary["tcp_syn_probe_steady_state_reached"] = all(gate_values) if all(value is not None for value in gate_values) else None
        seeds = [str(row["seed"]) for row in records if row["seed"] not in (None, "")]
        summary.update(independent_n=len(set(seeds)), repeated_seed_runs=len(seeds) - len(set(seeds)),
                       unknown_seed_runs=len(records) - len(seeds),
                       uncertainty_method="95% Student-t across seed means; unknown seeds suppress intervals")
        for key in ("tcp_syn_ping_timeouts", "tcp_syn_ping_censored", "tcp_syn_ping_offered", "tcp_syn_ping_completed"):
            values = [row[key] for row in records]
            summary[key] = sum(values) if all(value is not None for value in values) else None
        for metric in METRICS:
            units = defaultdict(list)
            observed = [row for row in records if row[metric] is not None]
            for row in observed:
                unit = str(row["seed"]) if row["seed"] not in (None, "") else "unknown-" + row["id"]
                units[unit].append(row[metric])
            stats = mean_ci([float(np.mean(values)) for values in units.values()])
            summary[metric] = stats["mean"]
            summary[metric + "_low"] = stats["ci_low"] if not summary["unknown_seed_runs"] else None
            summary[metric + "_high"] = stats["ci_high"] if not summary["unknown_seed_runs"] else None
            summary[metric + "_n"] = len(observed)
            summary[metric + "_independent_n"] = len({str(row["seed"]) for row in observed if row["seed"] not in (None, "")})
        output.append(summary)
    return output


def frontier(rows, metric):
    candidates = [row for row in rows if row["eligible"] and row[metric] is not None and row["goodput_mbps"] is not None
                  and row.get(metric + "_n", 1) == row.get("n", 1)
                  and row.get("goodput_mbps_n", 1) == row.get("n", 1)
                  and (metric != "tcp_syn_ping_p99_ms" or row.get("tcp_syn_ping_frontier_eligible", False))]
    selected, best, best_cost = [], float("-inf"), None
    for row in sorted(candidates, key=lambda row: (row[metric], -row["goodput_mbps"])):
        if row["goodput_mbps"] > best or (row["goodput_mbps"] == best and row[metric] == best_cost):
            selected.append(row)
            best = row["goodput_mbps"]
            best_cost = row[metric]
    return selected


def frontier_rows(means):
    output = []
    for metric in AXES:
        groups = defaultdict(list)
        for row in means:
            probe_config = row["tcp_syn_probe_measurement_config"] if metric == "tcp_syn_ping_p99_ms" else None
            groups[row["cohort"], probe_config].append(row)
        for group in groups.values():
            output.extend(dict(row, frontier_metric=metric) for row in frontier(group, metric))
    return output


def write_csv(path, rows):
    keys = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=keys or ["id"])
        writer.writeheader()
        writer.writerows(rows)


def plot_coverage(rows):
    """Account for each raw point, including observations with undefined coordinates."""
    groups = defaultdict(list)
    for row in rows:
        groups[row["payload_bytes"]].append(row)
    coverage = []
    for payload, records in sorted(groups.items(), key=lambda item: item[0] if item[0] is not None else float("inf")):
        for metric in AXES:
            counts = defaultdict(int)
            for row in records:
                missing = (row[metric] is None, row["goodput_mbps"] is None)
                counts[{(False, False): "measured_points", (True, False): "unmeasured_x_points",
                        (False, True): "unmeasured_y_points", (True, True): "unmeasured_both_points"}[missing]] += 1
            coverage.append(dict(payload_bytes=payload, metric=metric, recorded_runs=len(records),
                                 measured_points=counts["measured_points"],
                                 unmeasured_x_points=counts["unmeasured_x_points"],
                                 unmeasured_y_points=counts["unmeasured_y_points"],
                                 unmeasured_both_points=counts["unmeasured_both_points"],
                                 plotted_runs=sum(counts.values()),
                                 zero_goodput_points=sum(row["goodput_mbps"] == 0 for row in records),
                                 incomplete_or_diagnostic_points=sum(not row["eligible"] for row in records)))
    return coverage


def syn_presentation(rows, means, root):
    """Build measured-only views without changing any archived observation."""
    versions = {}
    for row in rows:
        if row["study"] in versions:
            continue
        directory = root / row["study"]
        manifest_path = next((directory / name for name in ("experiment.json", "manifest.json")
                              if (directory / name).is_file()), None)
        manifest = json.loads(manifest_path.read_text()) if manifest_path else {}
        if isinstance(manifest, list):
            manifest = {"tasks": manifest}
        hashes = source_hashes(manifest)
        versions[row["study"]] = (comparison_version(dict(manifest, sources=hashes))[0]
                                  if hashes else row["version"])

    def cohort(row):
        return json.dumps([row["cohort"], versions[row["study"]], row["tcp_syn_probe_measurement_config"]],
                          separators=(",", ":"))

    observed, coverage = [], []
    groups = defaultdict(list)
    for row in rows:
        reasons = []
        if row["tcp_syn_probe_steady_state_reached"] is not True:
            reasons.append("steady-state gate unmeasured or not reached")
        if row[SYN_LATENCY] is None:
            reasons.append("TCP SYN ping P99 unmeasured")
        if row[SYN_GOODPUT] is None:
            reasons.append("concurrent bulk goodput unmeasured")
        if row["status"] in ("unsupported", "tool failure", "bound exhausted"):
            reasons.append(row["status"])
        key = cohort(row)
        if not reasons:
            point = dict(row, syn_cohort=key)
            observed.append(point)
            groups[key].append(point)
        coverage.append(dict(id=row["id"], source=row["source"], payload_bytes=row["payload_bytes"],
            primary_display="measured point" if not reasons else "coverage table", reason=" | ".join(reasons),
            syn_cohort=key, tcp_syn_ping_p99_ms=row[SYN_LATENCY],
            concurrent_bulk_goodput_mbps=row[SYN_GOODPUT], status=row["status"]))

    selected_means = [dict(row, syn_cohort=cohort(row)) for row in means
        if cohort(row) in groups and row["tcp_syn_probe_steady_state_reached"] is True
        and row[SYN_LATENCY] is not None and row[SYN_GOODPUT] is not None
        and row[SYN_LATENCY + "_n"] == row["n"] and row[SYN_GOODPUT + "_n"] == row["n"]]
    definitions, boundaries = [], []
    for key, group in groups.items():
        first_row = group[0]
        averages = [row for row in selected_means if row["syn_cohort"] == key]
        coordinates = [dict(row, goodput_mbps=row[SYN_GOODPUT], goodput_mbps_n=row[SYN_GOODPUT + "_n"])
                       for row in averages]
        selected = {row["id"] for row in frontier(coordinates, SYN_LATENCY)}
        boundary = sorted((row for row in averages if row["id"] in selected), key=lambda row: row[SYN_LATENCY])
        boundaries.extend(boundary)
        identifier = sha256(key.encode()).hexdigest()[:12]
        payload = first_row["payload_bytes"]
        payload_label = f"{payload:g}" if payload is not None else "unknown"
        label = first_row["cohort_label"] + " | " + versions[first_row["study"]]
        definitions.append(dict(id=key, payload_bytes=payload, label=label,
            measurement_config=first_row["tcp_syn_probe_measurement_config"],
            duration_s=first_row["duration_s"], png=f"payload-{payload_label}-syn-{identifier}.png",
            raw_ids=[row["id"] for row in group], mean_ids=[row["id"] for row in averages],
            frontier_ids=[row["id"] for row in boundary],
            eligible_runs=sum(row["tcp_syn_ping_frontier_eligible"] for row in group)))
    definitions.sort(key=lambda row: (row["payload_bytes"] is None, row["payload_bytes"] or 0,
                                     -len(row["raw_ids"]), -(row["duration_s"] or 0), row["label"]))
    return dict(observations=observed, means=selected_means, frontiers=boundaries,
                cohorts=definitions, coverage=coverage)


def static_payloads(output, rows, means, *, root=None):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D
    from matplotlib.ticker import FuncFormatter, LogLocator, NullLocator
    import textwrap

    presentation = syn_presentation(rows, means, root or output.parent)
    for cohort in presentation["cohorts"]:
        observed = [row for row in presentation["observations"] if row["syn_cohort"] == cohort["id"]]
        averages = [row for row in presentation["means"] if row["syn_cohort"] == cohort["id"]]
        boundary = [row for row in presentation["frontiers"] if row["syn_cohort"] == cohort["id"]]
        families = [family for family in STRATEGY_COLORS if any(row["strategy_type"] == family for row in observed)]
        fig, axis = plt.subplots(figsize=(11, 7))
        for family in families:
            for eligible, marker in ((True, "o"), (False, "x")):
                points = [row for row in observed if row["strategy_type"] == family
                          and row["tcp_syn_ping_frontier_eligible"] == eligible]
                if points:
                    axis.scatter([row[SYN_LATENCY] for row in points], [row[SYN_GOODPUT] for row in points],
                                 s=42, alpha=.75, color=STRATEGY_COLORS[family], marker=marker)
            points = [row for row in averages if row["strategy_type"] == family]
            axis.plot([row[SYN_LATENCY] for row in points], [row[SYN_GOODPUT] for row in points],
                      linestyle="none", marker="D", markerfacecolor="none", color=STRATEGY_COLORS[family])
        axis.plot([row[SYN_LATENCY] for row in boundary], [row[SYN_GOODPUT] for row in boundary],
                  color="#475569", linewidth=1.5, linestyle="--")
        axis.axvline(1.5 * observed[0]["rtt_ms"], color="#b91c1c", linestyle=":")
        axis.axhline(.8 * observed[0]["forward_mbps"], color="#15803d", linestyle=":")
        axis.set(xlabel="TCP SYN ping P99 (ms)", ylabel="Concurrent stable-load bulk goodput (Mbps)",
                 xscale="log" if all(row[SYN_LATENCY] > 0 for row in observed) else "linear", yscale="linear")
        if axis.get_xscale() == "log":
            axis.xaxis.set_major_locator(LogLocator(base=10, subs=(1, 2, 5)))
            axis.xaxis.set_major_formatter(FuncFormatter(lambda value, position: f"{value:g}"))
            axis.xaxis.set_minor_locator(NullLocator())
        maximum_goodput = max(.8 * observed[0]["forward_mbps"],
                              *(row[SYN_GOODPUT] for row in observed))
        axis.set_ylim(0, maximum_goodput * 1.08)
        axis.grid(alpha=.2)
        handles = [Line2D([], [], linestyle="none", marker="o", color=STRATEGY_COLORS[family], label=family)
                   for family in families]
        if any(not row["tcp_syn_ping_frontier_eligible"] for row in observed):
            handles.append(Line2D([], [], linestyle="none", marker="x", color="#333333", label="Measured, frontier ineligible"))
        handles.extend((Line2D([], [], linestyle="--", marker="D", markerfacecolor="none", color="#475569", label="Configuration mean / frontier"),
                        Line2D([], [], linestyle=":", color="#b91c1c", label="1.5 × RTT target"),
                        Line2D([], [], linestyle=":", color="#15803d", label="80% capacity target")))
        fig.legend(handles=handles, loc="lower center", bbox_to_anchor=(.5, .01), ncol=3, fontsize=9)
        fig.suptitle("Coefficient/rank simulation · TCP SYN ping under stable bulk load\n" + "\n".join(textwrap.wrap(cohort["label"], 130))
                     + f"\n{len(observed)} measured runs · one matched comparison condition", fontsize=10)
        fig.subplots_adjust(left=.10, right=.97, bottom=.20, top=.77)
        fig.savefig(output / cohort["png"], dpi=160)
        plt.close(fig)

    write_csv(output / "syn-ping-coverage.csv", presentation["coverage"])
    (output / "syn-ping-static-index.json").write_text(json.dumps(presentation["cohorts"], indent=2) + "\n")
    table_rows = []
    for payload in sorted({row["payload_bytes"] for row in rows}, key=lambda value: (value is None, value or 0)):
        label = f"{payload:g} B" if payload is not None else "Unknown"
        cohorts = [row for row in presentation["cohorts"] if row["payload_bytes"] == payload]
        if not cohorts:
            table_rows.append(f"<tr><td>{label}</td><td>No measured stable-load TCP SYN ping cohort</td><td>0</td><td>—</td></tr>")
        for cohort in cohorts:
            table_rows.append(f'<tr><td>{label}</td><td>{escape(cohort["label"])}</td><td>{len(cohort["raw_ids"])}</td>'
                              f'<td><a href="{cohort["png"]}">PNG</a></td></tr>')
    page = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TCP SYN ping figures by comparison condition</title><style>body{font:15px/1.5 system-ui;margin:24px;color:#213547}main{max-width:1200px;margin:auto}.scroll{overflow:auto}table{border-collapse:collapse;width:100%}td,th{padding:10px;border-bottom:1px solid #ddd;text-align:left}a{color:#116e9d}</style></head><body><main>
<h1>TCP SYN ping figures by comparison condition</h1><p>Each image contains one payload and one matched physical, runtime and probe-measurement condition. The vertical axis is concurrent stable-load bulk goodput in Mbps. The horizontal axis is TCP SYN ping P99 in ms.</p>
<p>Coding recovery uses coefficient/rank calculations and original source bytes from the sender ledger. Historical cohorts use callback-dispatched TCP probe endpoints. Shared links arbitrate by FIFO arrival order. These figures measure the simulator model.</p>
<p><a href="report.html">Interactive measured results</a> · <a href="syn-ping-coverage.csv">Every saved case and display coverage</a> · <a href="historical-overview.html">Secondary historical archive</a></p>
<div class="scroll"><table><thead><tr><th>Payload</th><th>Matched condition</th><th>Measured runs</th><th>Figure</th></tr></thead><tbody>__ROWS__</tbody></table></div></main></body></html>'''
    (output / "syn-ping-index.html").write_text(page.replace("__ROWS__", "".join(table_rows)))


def historical_html_report(output, rows, means, frontiers, inventory):
    dataset = json.dumps(dict(runs=rows, means=means, frontiers=frontiers, strategy_colors=STRATEGY_COLORS), ensure_ascii=True, allow_nan=False).replace("</", "<\\/")
    inventory_html = "".join(f"<tr><td>{escape(r['study'])}</td><td>{r['raw_runs']}</td><td>{escape(r['state'])}</td><td>{escape(r['detail'])}</td></tr>" for r in inventory)
    figures = '<a href="syn-ping-index.html">Measured TCP SYN ping figures by payload and condition</a>'
    latency_root = output.parent / "tcp-latency"
    focused = (
        ("tcp-syn-ping-analysis", "Loaded new-connection TCP SYN ping"),
        ("compact-wire-screen", "Compact wire framing and full TCP deadlines"),
        ("compact-wire-ack-screen", "Compact wire ACK copies and full TCP deadlines"),
        ("compact-wire-ack-long", "Long-run compact wire ACK confirmation"),
        ("compact-ack-delta-analysis", "Batch-local ACK compression and repair padding"),
        ("compact-ack-four-analysis", "Matched three- and four-copy ACK screen"),
        ("aligned-record-analysis", "Aligned framing and payload-length compression"),
        ("aggregate-ack-analysis", "Cross-flow ACK aggregation"),
        ("aligned-latency-stages", "Passive latency-stage attribution"),
    )
    analytical = (
        ("rtt-budget-analysis", "Earlier coding-delay screen"),
        ("rtt-budget-analysis-v2", "Causal coding-delay screen"),
        ("rtt-budget-analysis-v2/confirmation", "Coding-delay confirmation"),
        ("sparse-coding-screen", "Sparse repair coefficients"),
        ("structured-coding-screen", "Diagonal Cauchy coding"),
        ("checkpoint-repair-screen", "Checkpoint repair scheduling"),
        ("age-support-screen", "Age-weighted repair support"),
        ("mixed-degree-screen", "Mixed sparse and dense repairs"),
        ("rolling-accumulator-screen", "Repeated-coefficient rolling repairs"),
        ("age-coefficient-screen", "Age-dependent coefficient taps"),
        ("recursive-parity-screen", "Source-regular recursive parity"),
        ("recursive-fallback-screen", "Recursive parity with fresh-prefix repairs"),
        ("selective-fallback-screen", "Delayed selective-feedback repairs"),
        ("spatial-coupling-screen", "Causal spatially coupled parity checks"),
        ("feedback-gate-screen", "Feedback-gated global repairs"),
        ("partial-repair-screen", "Coupled half-vector repair packets"),
        ("bitmap-coded-fallback-screen", "Coded repair of reported missing sources"),
        ("source-bridge-screen", "Delayed source bridging"),
        ("busy-period-diagnostic", "Phase-aware coding busy periods"),
        ("predictive-wire-budget", "Predictive record and compact wire budgets"),
        ("repair-extent-audit", "Repair support extents and padding bounds"),
        ("streaming-design-review", "Historical streaming-code reference budgets"),
        ("subpacket-convolutional-screen", "Subpacket convolutional coding"),
        ("lrsc-staircase-screen", "GF256 local-recovery staircase"),
        ("oracle-repair-diagnostic", "Ideal-information repair diagnostic"),
        ("wire-budget-audit", "Forward wire-budget audit"),
        ("latency-counterfactual", "Fixed-trajectory latency bounds"),
        ("deadline-converse", "Finite-deadline bounds"),
    )

    def related_links(studies):
        return " · ".join(
            f'<a href="{escape(relpath(latency_root / directory / "report.html", output))}">{label}</a>'
            for directory, label in studies if (latency_root / directory / "report.html").is_file())

    related = '<div class="panel"><h2>Focused studies and analytical screens</h2>'
    related += f'<p>{related_links(focused)}</p>'
    related += ('<p>Coding-only screens retain their individual analytical points in the linked reports. '
                'Their source-recovery delay and code rate have separate axes and model assumptions. '
                'The TCP and QUIC frontiers below use saved end-to-end protocol observations.</p>')
    related += f'<p>{related_links(analytical)}</p></div>'
    page = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secondary historical experiment archive</title><style>
body{font:15px/1.5 system-ui;color:#213547;background:#f5f7fa;margin:0}main{max-width:1550px;margin:auto;padding:24px}
h1{font-size:28px}h2{font-size:21px}a{color:#116e9d}.panel{background:white;padding:18px;margin:16px 0;border:1px solid #dce3ea;border-radius:8px}
.controls{display:flex;flex-wrap:wrap;gap:12px}label{display:flex;flex-direction:column;font-weight:600;min-width:0;max-width:100%}select{width:100%;min-width:0;max-width:100%;box-sizing:border-box;padding:7px;font:inherit}.wide{width:100%}
.plots{display:grid;grid-template-columns:1fr 1fr}.plot{min-width:0;height:540px}.scroll{overflow:auto;max-height:540px}table{border-collapse:collapse;width:100%;font-size:12px}td,th{padding:7px;border-bottom:1px solid #dce3ea;text-align:left;white-space:nowrap}th{position:sticky;top:0;background:#eaf0f6}
@media(max-width:1000px){.plots{grid-template-columns:1fr}}.muted{color:#596a7b}button{padding:6px 12px}
</style><script>__PLOTLY__</script></head><body><main><h1>Secondary historical experiment archive</h1>
<p><a href="report.html">Open the primary measured TCP SYN ping comparisons</a>. This secondary view inventories historical experiments across conditions. Undefined coordinates use labeled archive strips.</p>
<p>__COUNT__ individual saved runs across __STUDIES__ raw study directories. Historical pilots, dominated candidates, and incomplete observations are retained. Derived report exports are listed in the inventory and represented through their original raw runs.</p>
__RELATED__
<div class="panel controls"><label>Payload bytes<select id="payload"></select></label><label>Cost metric<select id="cost"><option value="packet_extra_pct">Extra forward packets / delivered record (%)</option><option value="byte_extra_pct">Extra forward IP bytes / delivered application bytes (%)</option></select></label>
<label>Latency metric<select id="latency"><option value="tcp_syn_ping_p99_ms">TCP SYN ping P99 (ms)</option></select></label>
<label>Y scale<select id="scale"><option value="linear">Linear</option><option value="log">Logarithmic</option></select></label>
<label class="wide">Matching condition and model version<select id="cohort"></select></label></div>
<p id="counts"></p><div class="panel plots"><div class="plot" id="costplot"></div><div class="plot" id="latencyplot"></div></div>
<p>Colors identify strategy families consistently across payloads and conditions. Circles and crosses retain individual raw observation IDs, and identical coordinates can overlap. Crosses indicate ineligible or unmeasured observations. Separate Unmeasured strips retain undefined coordinates, and logarithmic views retain zero goodput in a labeled bottom strip. Larger open diamonds are configuration means. Dashed frontiers stay within one payload, bandwidth pair, RTT, loss process, MTU, duration, warmup, drain, model category, and recorded core version. SYN-ping frontiers also match the recorded probe measurement configuration. Reverse-copy count and copy spacing remain competing transport choices, with their full configuration retained in exports.</p>
<p>Packet cost is 100 × (all forward IP datagrams through drain / unique delivered application records − 1). Small records can share a datagram, giving a negative value under this record-count definition. Byte cost compares all forward IP bytes with delivered application bytes. Throughput counts bulk application bytes arriving during the traffic interval. Probe traffic contributes to measured wire costs where probes are enabled.</p>
<p>TCP SYN ping measures the interval from first SYN submission to matching SYN-ACK reception, including retransmission waits. Each probe uses a fresh connection while bulk traffic runs, with admission beginning after the recorded bulk steady-state gate. Admission ends by traffic cutoff minus probe timeout so the complete timeout remains under load. P99 uses completed probes. The table and tooltips separately retain timeout and censored counts, and failure percentage includes both across all offered probes. A SYN frontier requires positive probe count, every probe completed, zero recorded failures, timeouts and censored probes, and confirmed bulk delivery. Cost frontiers keep their existing bulk-confirmation requirements. Historical runs without this instrumentation stay unmeasured on the SYN axis. Historical ACK and timestamp observations remain numerically intact in CSV exports.</p>
<p>Earlier fixed-window L2 models, established CUBIC/NewReno TCP, and aioquic payload-equivalent records retain their recorded model labels. Historical diagnostics and unverified confirmation remain visible, with separate model/version groups. IP service capacity excludes outer Ethernet framing and physical-line costs. Existing compact results use zero authentication-byte budgets unless their profile records another setting. TCP is a simulator congestion-control model. Timestamp RTT uses the simulation clock with sub-millisecond timestamp quantization omitted. GF256 rank computation is modeled, while payload coding and codec CPU time are excluded.</p><p>Core version hashes use the same model.py, tcp.py, and compact.py tuple when all three recorded digests exist. Full executed source hashes, including optional transport and measurement modules where recorded, remain available in each raw study manifest. Partial provenance stays study-specific. Metadata backfills identify their recorded fields, assumptions, or digest-verified constructor sources in the CSV. Same-seed reruns remain individual points. Intervals use one mean per seed within each study and configuration, and are suppressed for unknown seeds.</p>
<div class="panel"><h2>Selected observations</h2><button id="download">Download selected runs</button><div class="scroll"><table><thead><tr><th>Study / profile</th><th>Strategy type</th><th>Seed</th><th>Mbps</th><th>Extra packets %</th><th>TCP SYN ping P99 ms</th><th>Probe failure %</th><th>Probes completed / offered</th><th>Timeout / censored</th><th>Status</th><th>Raw observation</th></tr></thead><tbody id="records"></tbody></table></div></div>
<div class="panel"><h2>Coverage and exports</h2><p><a href="all-runs.csv">Every normalized raw run</a> · <a href="configuration-means.csv">Configuration means and intervals</a> · <a href="frontiers.csv">Payload- and condition-specific frontiers</a> · <a href="inventory.csv">Source inventory</a> · <a href="plot-coverage.csv">Per-payload plotted-point counts</a></p><p>__FIGURES__</p>
<div class="scroll"><table><thead><tr><th>Study</th><th>Imported raw runs</th><th>Classification</th><th>Coverage</th></tr></thead><tbody>__INVENTORY__</tbody></table></div></div>
<script id="data" type="application/json">__DATA__</script><script>
const data=JSON.parse(document.getElementById('data').textContent);
const get=id=>document.getElementById(id);
const familyColors=data.strategy_colors;
const payloads=[...new Set(data.runs.map(r=>r.payload_bytes))].sort((a,b)=>(a??Infinity)-(b??Infinity));
payloads.forEach(p=>get('payload').add(new Option(p===null?'Unknown':p+' B',String(p))));
get('payload').value=payloads.includes(1448)?'1448':String(payloads[0]);
function matchingPayload(r){return String(r.payload_bytes)===get('payload').value;}
function selectCohorts(){
 const cohorts=[...new Map(data.runs.filter(matchingPayload).map(r=>[r.cohort,r])).values()];
 cohorts.sort((a,b)=>Number(b.study.startsWith('tcp-latency'))-Number(a.study.startsWith('tcp-latency')) || b.duration_s-a.duration_s || a.cohort_label.localeCompare(b.cohort_label));
 get('cohort').replaceChildren(new Option('All conditions for this payload · separate frontiers','all'));
 cohorts.forEach(r=>get('cohort').add(new Option(r.cohort_label,r.cohort)));
 get('cohort').value='all'; render();
}
function selected(r){return matchingPayload(r)&&(get('cohort').value==='all'||r.cohort===get('cohort').value);}
function draw(target,metric,label){
 if(get(target).clientWidth<600){
  const lines=[''];
  for(const word of label.split(' ')){
   const last=lines.length-1;
   if(lines[last].length+word.length>28)lines.push(word);
   else lines[last]+=(lines[last]?' ':'')+word;
  }
  label=lines.join('<br>');
 }
 const rows=data.runs.filter(selected),means=data.means.filter(selected),traces=[];
 const missingY=r=>r.goodput_mbps===null||(get('scale').value==='log'&&r.goodput_mbps<=0);
 const unmeasured=rows.filter(r=>r[metric]===null&&!missingY(r));
 const missingGoodput=rows.filter(r=>r[metric]!==null&&missingY(r));
 const missingBoth=rows.filter(r=>r[metric]===null&&missingY(r));
 const hasMissingX=unmeasured.length+missingBoth.length>0;
 const hasMissingY=missingGoodput.length+missingBoth.length>0;
 const yStripLabel=get('scale').value==='log'?'Zero / unmeasured':'Unmeasured';
 const families=Object.keys(familyColors).filter(family=>rows.some(r=>r.strategy_type===family));
 const eligible=r=>metric==='tcp_syn_ping_p99_ms'?r.tcp_syn_ping_frontier_eligible:r.eligible;
 const probeText=r=>'Probes '+(r.tcp_syn_ping_completed??'unmeasured')+'/'+(r.tcp_syn_ping_offered??'unmeasured')+' completed/offered · failure '+(r.tcp_syn_ping_failure_pct??'unmeasured')+'%<br>Timeouts '+(r.tcp_syn_ping_timeouts??'unmeasured')+' · censored '+(r.tcp_syn_ping_censored??'unmeasured')+'<br>Steady-state gate '+(r.tcp_syn_probe_steady_state_reached??'unmeasured')+' · probe start '+(r.tcp_syn_probe_start_s??'unmeasured')+' s<br>Background goodput '+(r.tcp_syn_ping_background_goodput_mbps??'unmeasured')+' Mbps';
 families.forEach(family=>{
  const familyRows=rows.filter(r=>r.strategy_type===family);
  let legendShown=false;
  for(const [missingX,missingVertical] of [[false,false],[true,false],[false,true],[true,true]]){
   const points=familyRows.filter(r=>(r[metric]===null)===missingX&&missingY(r)===missingVertical);
   if(!points.length)continue;
   traces.push({type:'scattergl',mode:'markers',name:family,legendgroup:family,showlegend:!legendShown,ids:points.map(r=>r.id),meta:{kind:'raw-run',metric},xaxis:missingX?'x2':'x',yaxis:missingVertical?'y2':'y',x:points.map(r=>missingX?'Unmeasured':r[metric]),y:points.map(r=>missingVertical?yStripLabel:r.goodput_mbps),marker:{size:6,opacity:.55,color:familyColors[family],symbol:points.map(r=>!missingX&&!missingVertical&&eligible(r)?'circle':'x')},text:points.map(r=>r.name+'<br>'+r.study+'<br>'+r.id+'<br>Seed '+r.seed+' · '+r.status+'<br>'+r.quality+'<br>'+r.cohort_label+'<br>'+probeText(r)+'<br>Selected metric '+(r[metric]??'unmeasured')+' · goodput '+(r.goodput_mbps??'unmeasured')+' Mbps'),hovertemplate:'%{text}<extra>%{fullData.name}</extra>'});
   legendShown=true;
  }
  const points=means.filter(r=>r.strategy_type===family&&r[metric]!==null&&!missingY(r));
  traces.push({type:'scatter',mode:'markers',name:family+' configuration means',legendgroup:family,showlegend:false,x:points.map(r=>r[metric]),y:points.map(r=>r.goodput_mbps),marker:{symbol:'diamond-open',size:10,color:familyColors[family]},text:points.map(r=>r.name+'<br>'+r.study+'<br>n='+r.n+', bulk confirmed '+r.confirmed+'<br>'+probeText(r)),hovertemplate:'%{text}<br>X %{x:.4g}<br>Mean goodput %{y:.4g} Mbps<extra></extra>'});
 });
 const front=data.frontiers.filter(r=>selected(r)&&r.frontier_metric===metric);
 const frontierGroup=r=>JSON.stringify([r.cohort,metric==='tcp_syn_ping_p99_ms'?r.tcp_syn_probe_measurement_config:null]);
 const cohorts=[...new Set(front.map(frontierGroup))];
 cohorts.forEach((cohort,index)=>{const line=front.filter(r=>frontierGroup(r)===cohort).sort((a,b)=>a[metric]-b[metric]);traces.push({type:'scatter',mode:'lines',name:'Matched-condition frontier',showlegend:index===0,x:line.map(r=>r[metric]),y:line.map(r=>r.goodput_mbps),line:{dash:'dash',width:2,color:'#253c52'},text:line.map(r=>r.name),hovertemplate:'%{text}<br>%{x:.4g}, %{y:.4g} Mbps<extra></extra>'});});
 Plotly.react(target,traces,{template:'plotly_white',title:{text:label},xaxis:{title:{text:label},domain:hasMissingX?[0,.84]:[0,1]},xaxis2:{domain:[.91,1],type:'category',anchor:'y',visible:hasMissingX,tickfont:{size:9},showgrid:false},yaxis:{title:{text:'Application goodput (Mbps)'},type:get('scale').value,domain:hasMissingY?[.16,1]:[0,1]},yaxis2:{domain:[0,.07],type:'category',anchor:'x',visible:hasMissingY,tickfont:{size:9},showgrid:false},margin:{t:55,b:130,l:75,r:20},legend:{orientation:'h',y:-.3,maxheight:100,font:{size:9}},annotations:rows.some(r=>r[metric]!==null&&!missingY(r))?[]:[{text:'No recorded samples for this metric',xref:'paper',yref:'paper',x:.42,y:.5,showarrow:false}]},{responsive:true,displaylogo:false});
 const plotted=traces.filter(trace=>trace.meta?.kind==='raw-run').flatMap(trace=>trace.ids);
 if(plotted.length!==rows.length||new Set(plotted).size!==rows.length)throw new Error('Raw-run plot coverage mismatch');
 return {missing:rows.filter(r=>r[metric]===null).length,plotted:plotted.length};
}
function render(){
 const a=draw('costplot',get('cost').value,get('cost').selectedOptions[0].text);
 const b=draw('latencyplot',get('latency').value,get('latency').selectedOptions[0].text);
 const rows=data.runs.filter(selected);
 get('counts').textContent=rows.length+' individual runs selected. '+a.plotted+' cost points and '+b.plotted+' latency points plotted. Missing cost measurements '+a.missing+'. Missing latency measurements '+b.missing+'. Separate strips retain undefined coordinates and logarithmic zero values. Every run is retained in the table and CSV.';
 get('records').replaceChildren();
 rows.forEach(r=>{const tr=document.createElement('tr');[r.study+' / '+r.name,r.strategy_type,r.seed,r.goodput_mbps,r.packet_extra_pct,r.tcp_syn_ping_p99_ms,r.tcp_syn_ping_failure_pct,(r.tcp_syn_ping_completed??'—')+' / '+(r.tcp_syn_ping_offered??'—'),(r.tcp_syn_ping_timeouts??'—')+' / '+(r.tcp_syn_ping_censored??'—'),r.status+' · '+r.quality,r.id].forEach(value=>{const td=document.createElement('td');td.textContent=value===null?'—':typeof value==='number'?value.toFixed(3):value;tr.append(td);});get('records').append(tr);});
}
get('payload').addEventListener('change',selectCohorts);
['cohort','cost','latency','scale'].forEach(id=>get(id).addEventListener('change',render));
get('download').addEventListener('click',()=>{const blob=new Blob([JSON.stringify(data.runs.filter(selected),null,2)],{type:'application/json'});const link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download='selected-runs.json';link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);});
selectCohorts();
</script></main></body></html>"""
    page = (page.replace("__PLOTLY__", get_plotlyjs()).replace("__COUNT__", str(len(rows)))
            .replace("__STUDIES__", str(len({row["study"] for row in rows}))).replace("__DATA__", dataset)
            .replace("__INVENTORY__", inventory_html).replace("__FIGURES__", figures).replace("__RELATED__", related))
    (output / "historical-overview.html").write_text(page)


def html_report(output, rows, means, frontiers, inventory, *, root=None):
    historical_html_report(output, rows, means, frontiers, inventory)
    presentation = syn_presentation(rows, means, root or output.parent)
    dataset = json.dumps(dict(runs=rows, strategy_colors=STRATEGY_COLORS, **presentation),
                         ensure_ascii=True, allow_nan=False).replace("</", "<\\/")
    page = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Measured TCP SYN ping Pareto comparisons</title><style>
*{box-sizing:border-box}body{font:15px/1.5 system-ui;color:#213547;background:#f5f7fa;margin:0}main{max-width:1450px;margin:auto;padding:22px}
h1{font-size:28px;line-height:1.2}h2{font-size:21px}a{color:#116e9d}.panel{background:white;padding:18px;margin:16px 0;border:1px solid #dce3ea;border-radius:10px}
.controls{display:flex;flex-wrap:wrap;gap:12px}label{display:flex;flex-direction:column;font-weight:600;min-width:0;max-width:100%}select{width:100%;min-width:0;max-width:100%;box-sizing:border-box;padding:7px;font:inherit}.wide{width:100%}
#pingplot{min-width:0;width:100%;height:650px}.scroll{overflow:auto;max-height:460px}table{border-collapse:collapse;width:100%;font-size:12px}td,th{padding:7px;border-bottom:1px solid #dce3ea;text-align:left;white-space:nowrap}th{position:sticky;top:0;background:#eaf0f6}
p,li,summary{overflow-wrap:anywhere}summary{cursor:pointer;font-weight:600}button{padding:6px 12px}@media(max-width:600px){main{padding:8px}.panel{padding:12px}h1{font-size:24px}#pingplot{height:650px}}
</style><script>__PLOTLY__</script></head><body><main>
<header class="panel"><h1>Measured TCP SYN ping Pareto comparisons</h1>
<p>TCP SYN ping runs from the first SYN submission to its matching SYN-ACK reception, including retransmission waits. Probe admission starts after the recorded stable-load gate and ends by traffic cutoff minus probe timeout. The vertical axis measures concurrent bulk application throughput from that gate to traffic end.</p>
<p><a href="syn-ping-index.html">PNG figures by payload and comparison condition</a> · <a href="../tcp-latency/tcp-syn-ping-analysis/report.html">Focused probe records and diagnostics</a> · <a href="historical-overview.html">Secondary historical archive</a></p></header>
<section class="panel"><div class="controls"><label>Payload bytes<select id="payload"></select></label>
<label>TCP SYN ping axis<select id="xscale"><option value="log">Logarithmic milliseconds</option><option value="linear">Linear milliseconds</option></select></label>
<label class="wide">One matched comparison condition<select id="cohort"></select></label></div>
<p id="counts"></p><div id="pingplot"></div>
<p><strong>Model scope.</strong> Coding recovery uses coefficient/rank calculations and original source bytes from the sender ledger. Historical cohorts use callback-dispatched TCP probe endpoints. Shared links arbitrate by FIFO arrival order through <code>Link.free_at</code>. These figures measure the simulator model. Kernel TCP processing, independent payload decoding and fair-queue scheduling are outside its modeled scope.</p>
<p>Colors identify strategy families. Each marker retains an individual raw execution ID. Open diamonds are complete configuration means. Crosses identify measured outcomes that fail frontier eligibility. The dashed frontier maximizes concurrent bulk throughput and minimizes TCP SYN ping P99 within the selected condition. Throughput uses a linear Mbps scale. Red and green dotted lines show the 1.5 × RTT and 80% capacity targets.</p>
<p>Payload, link capacities, nominal RTT, loss process, MTU, duration, warmup, drain, simulator and shared-builder versions, recorded Python/NumPy/SciPy/aioquic versions, and probe measurement settings are matched. Reverse-copy count and spacing are competing transport settings. Every timeout and censored probe remains in the recorded failure counts. A measured point can be excluded from the frontier when confirmation or probe outcomes are incomplete.</p></section>
<section class="panel"><h2>Coverage for the selected payload</h2><p id="coverage-counts"></p>
<p>This table includes saved cases across historical conditions. Missing measurements, unsupported configurations and unsteady runs remain in coverage and exports. Full executed source hashes and exact raw records remain in their study manifests.</p>
<div class="scroll"><table><thead><tr><th>Study</th><th>Saved cases</th><th>Measured stable-load PING</th><th>Coverage only</th></tr></thead><tbody id="coverage-summary"></tbody></table></div>
<details><summary>Every saved case for this payload</summary><button id="download">Download selected-payload records</button>
<div class="scroll"><table><thead><tr><th>Study / method</th><th>Strategy family</th><th>Seed</th><th>Full Mbps</th><th>Concurrent Mbps</th><th>TCP SYN ping P99 ms</th><th>Extra packets %</th><th>Probe failure %</th><th>Status</th><th>Primary display</th><th>Raw observation</th></tr></thead><tbody id="records"></tbody></table></div></details></section>
<section class="panel"><h2>Complete archive and exports</h2><p>__COUNT__ raw observations and __MEANS__ configuration means remain in the archive. The primary comparison plot contains measured stable-load TCP SYN ping coordinates for one condition at a time.</p>
<p><a href="all-runs.csv">Every normalized raw run</a> · <a href="configuration-means.csv">Every configuration mean</a> · <a href="frontiers.csv">Archived full-interval and cost frontiers</a> · <a href="syn-ping-coverage.csv">Primary display coverage for every case</a> · <a href="syn-ping-static-index.json">Static figure point inventory</a> · <a href="inventory.csv">Source inventory</a> · <a href="plot-coverage.csv">Historical plot coverage</a></p>
<p><a href="historical-overview.html">Open the secondary historical archive</a> to inspect original cost and full-interval throughput plots, including labeled undefined-coordinate strips. IP service capacity excludes outer Ethernet and physical-line framing. Simulated handshake listeners respond immediately, while host scheduling and codec CPU time remain outside the model.</p></section>
<script id="data" type="application/json">__DATA__</script><script>
const data=JSON.parse(document.getElementById('data').textContent);
const get=id=>document.getElementById(id);
const latency='tcp_syn_ping_p99_ms',goodput='tcp_syn_ping_background_goodput_mbps';
const coverageById=new Map(data.coverage.map(row=>[row.id,row]));
const payloads=[...new Set(data.runs.map(row=>row.payload_bytes))].sort((a,b)=>(a??Infinity)-(b??Infinity));
payloads.forEach(payload=>get('payload').add(new Option(payload===null?'Unknown':payload+' B',String(payload))));
const measuredPayloads=new Set(data.observations.map(row=>row.payload_bytes));
get('payload').value=String(measuredPayloads.has(1448)?1448:payloads.find(payload=>measuredPayloads.has(payload))??payloads[0]);
function matchingPayload(row){return String(row.payload_bytes)===get('payload').value;}
function selected(row){return matchingPayload(row)&&row.syn_cohort===get('cohort').value;}
function selectCohorts(){
 const cohorts=data.cohorts.filter(matchingPayload);
 get('cohort').replaceChildren();
 cohorts.forEach(row=>get('cohort').add(new Option(row.label+' · '+row.raw_ids.length+' measured runs',row.id)));
 if(!cohorts.length)get('cohort').add(new Option('No measured stable-load TCP SYN ping cohort',''));
 get('cohort').disabled=!cohorts.length;
 get('cohort').value=cohorts.length?cohorts[0].id:'';
 render();
}
function escaped(value){return String(value).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');}
function render(){
 const rows=data.observations.filter(selected),means=data.means.filter(selected),traces=[];
 const families=Object.keys(data.strategy_colors).filter(family=>rows.some(row=>row.strategy_type===family));
 const hover=row=>escaped(row.name)+'<br>'+escaped(row.study)+'<br>'+escaped(row.id)+'<br>Seed '+row.seed+
  '<br>TCP SYN ping P99 '+row[latency]+' ms<br>Concurrent bulk '+row[goodput]+' Mbps<br>Full bulk '+row.goodput_mbps+
  ' Mbps<br>Completed/offered '+row.tcp_syn_ping_completed+'/'+row.tcp_syn_ping_offered+' · failure '+row.tcp_syn_ping_failure_pct+
  '%<br>Timeouts '+row.tcp_syn_ping_timeouts+' · censored '+row.tcp_syn_ping_censored+
  '<br>Steady-state gate '+row.tcp_syn_probe_steady_state_reached+' · probe start '+row.tcp_syn_probe_start_s+' s';
 families.forEach(family=>{
  const points=rows.filter(row=>row.strategy_type===family),averages=means.filter(row=>row.strategy_type===family);
  traces.push({type:'scatter',mode:'markers',name:family,legendgroup:family,showlegend:true,
   ids:points.map(row=>row.id),meta:{kind:'raw-run'},x:points.map(row=>row[latency]),y:points.map(row=>row[goodput]),
   marker:{size:9,color:data.strategy_colors[family],symbol:points.map(row=>row.tcp_syn_ping_frontier_eligible?'circle':'x')},
   text:points.map(hover),hovertemplate:'%{text}<extra>%{fullData.name}</extra>'});
  traces.push({type:'scatter',mode:'markers',name:family+' means',legendgroup:family,showlegend:false,
   ids:averages.map(row=>row.id),meta:{kind:'configuration-mean'},x:averages.map(row=>row[latency]),y:averages.map(row=>row[goodput]),
   marker:{size:13,symbol:'diamond-open',color:data.strategy_colors[family]},
   text:averages.map(row=>escaped(row.name)+'<br>'+escaped(row.study)+'<br>'+row.n+' runs · '+row.independent_n+' independent seeds'),
   hovertemplate:'%{text}<br>Mean P99 %{x:.4f} ms<br>Concurrent bulk %{y:.4f} Mbps<extra></extra>'});
 });
 const boundary=data.frontiers.filter(selected).sort((a,b)=>a[latency]-b[latency]);
 if(boundary.length)traces.push({type:'scatter',mode:'lines',name:'Matched-condition frontier',meta:{kind:'frontier'},
  ids:boundary.map(row=>row.id),x:boundary.map(row=>row[latency]),y:boundary.map(row=>row[goodput]),
  line:{dash:'dash',width:2,color:'#475569'},hovertemplate:'Mean P99 %{x:.4f} ms<br>Concurrent bulk %{y:.4f} Mbps<extra></extra>'});
 const logarithmic=get('xscale').value==='log'&&rows.every(row=>row[latency]>0);
 const xaxis={title:{text:'TCP SYN ping P99 (ms)'},type:logarithmic?'log':'linear',automargin:true};
 if(logarithmic&&rows.length){
  const values=rows.map(row=>row[latency]).concat(rows[0].rtt_ms*1.5);
  const low=Math.floor(Math.log10(Math.min(...values))),high=Math.ceil(Math.log10(Math.max(...values)));
  const ticks=[];for(let exponent=low;exponent<=high;exponent++)for(const multiplier of [1,2,5])ticks.push(multiplier*10**exponent);
  xaxis.tickmode='array';xaxis.tickvals=ticks;xaxis.ticktext=ticks.map(value=>String(Number(value.toPrecision(12))));
 }
 const shapes=rows.length?[
  {type:'line',x0:rows[0].rtt_ms*1.5,x1:rows[0].rtt_ms*1.5,y0:0,y1:1,yref:'paper',line:{color:'#b91c1c',dash:'dot'}},
  {type:'line',x0:0,x1:1,xref:'paper',y0:.8*rows[0].forward_mbps,y1:.8*rows[0].forward_mbps,line:{color:'#15803d',dash:'dot'}}]:[];
 const annotations=rows.length?[]:[{text:'No measured stable-load TCP SYN ping coordinates<br>for this payload. Saved cases appear in coverage below.',
  xref:'paper',yref:'paper',x:.5,y:.5,showarrow:false,align:'center'}];
 const maximumGoodput=rows.length?Math.max(.8*rows[0].forward_mbps,...rows.map(row=>row[goodput])):1;
 window.pingReady=Plotly.react('pingplot',traces,{template:'plotly_white',xaxis,
  yaxis:{title:{text:'Concurrent bulk goodput (Mbps)'},type:'linear',rangemode:'tozero',
   range:[0,maximumGoodput*1.08],automargin:true},
  margin:{t:25,b:135,l:75,r:20},legend:{orientation:'h',y:-.24,maxheight:125,font:{size:10}},shapes,annotations},
  {responsive:true,displaylogo:false});
 const plotted=traces.filter(trace=>trace.meta?.kind==='raw-run').flatMap(trace=>trace.ids);
 if(plotted.length!==rows.length||new Set(plotted).size!==rows.length)throw Error('Measured SYN plot coverage mismatch');
 get('counts').textContent=rows.length+' measured runs · '+means.length+' complete configuration means · one comparison condition. '+
  'TCP SYN ping in milliseconds, concurrent bulk throughput in Mbps.';
 const saved=data.runs.filter(matchingPayload),shown=data.observations.filter(matchingPayload),studyCounts=new Map();
 get('coverage-counts').textContent=saved.length+' saved cases across all historical conditions for this payload. '+shown.length+
  ' have measured stable-load PING coordinates in '+data.cohorts.filter(matchingPayload).length+' separate comparison conditions. '+
  (saved.length-shown.length)+' cases remain in coverage only.';
 get('records').replaceChildren();
 saved.forEach(row=>{
  const display=coverageById.get(row.id),count=studyCounts.get(row.study)||{saved:0,measured:0};
  count.saved++;count.measured+=Number(display.primary_display==='measured point');studyCounts.set(row.study,count);
  const tr=document.createElement('tr');
  [row.study+' / '+row.name,row.strategy_type,row.seed,row.goodput_mbps,row[goodput],row[latency],row.packet_extra_pct,
   row.tcp_syn_ping_failure_pct,row.status+' · '+row.quality,display.primary_display+(display.reason?' · '+display.reason:'')].forEach(value=>{
   const td=document.createElement('td');td.textContent=value===null?'—':typeof value==='number'?value.toFixed(4):value;tr.append(td);});
  const td=document.createElement('td'),link=document.createElement('a');link.href='../'+row.source;link.textContent=row.id;td.append(link);tr.append(td);get('records').append(tr);
 });
 get('coverage-summary').replaceChildren();
 [...studyCounts].forEach(([study,count])=>{const tr=document.createElement('tr');[study,count.saved,count.measured,count.saved-count.measured].forEach(value=>{
  const td=document.createElement('td');td.textContent=value;tr.append(td);});get('coverage-summary').append(tr);});
}
get('payload').addEventListener('change',selectCohorts);
get('cohort').addEventListener('change',render);get('xscale').addEventListener('change',render);
get('download').addEventListener('click',()=>{const blob=new Blob([JSON.stringify(data.runs.filter(matchingPayload),null,2)],{type:'application/json'});
 const link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download='selected-payload-runs.json';link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);});
selectCohorts();
</script></main></body></html>'''
    page = (page.replace("__PLOTLY__", get_plotlyjs()).replace("__DATA__", dataset)
            .replace("__COUNT__", str(len(rows))).replace("__MEANS__", str(len(means))))
    (output / "report.html").write_text(page)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    output = args.out or args.root / "all-experiments"
    output.mkdir(parents=True, exist_ok=True)
    rows, inventory = load_all(args.root, output)
    means = summarize(rows)
    frontiers = frontier_rows(means)
    write_csv(output / "all-runs.csv", rows)
    write_csv(output / "configuration-means.csv", means)
    write_csv(output / "frontiers.csv", frontiers)
    write_csv(output / "inventory.csv", inventory)
    write_csv(output / "plot-coverage.csv", plot_coverage(rows))
    static_payloads(output, rows, means, root=args.root)
    html_report(output, rows, means, frontiers, inventory, root=args.root)
    print(f"Plotted {len(rows)} individual runs and {len(means)} configuration means in {output}")


if __name__ == "__main__":
    main()
