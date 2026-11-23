"""Build two-member catalog switch plans from exact Rust-exported descriptors.

Input: the --packed-c48-pair and default common_benchmark_plan exports. Output:
a new manifest for common_native_matrix.py --switch-during-phase --flow-count N.

``--carrier`` selects the carriers (default ``udp`` and ``tls``, the original
output). ``--carrier raw`` adds raw packet rows; like TLS, their per-side
``carrier_policy`` files must be identical in both source rows and are copied
under the switch row's name. ``--pair`` selects the source pairs (default both);
the base export is only required when the ``base`` pair is selected.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path


# Carriers a switch row may use, in output order, and those with per-side policy files.
CARRIERS = ("udp", "tls", "raw")
POLICY_CARRIERS = ("tls", "raw")
DEFAULT_CARRIERS = ("udp", "tls")
# Source pair name -> (initial row prefix, target row prefix).
PAIRS = {
    "c48": ("packed-c48-queue-aware", "packed-c48-control"),
    "base": ("packed-compact", "aligned-compact"),
}


def read(path):
    return json.loads(path.read_bytes())


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def compose(source, initial, target, output):
    manifest_path = source / "manifest.json"
    manifest = read(manifest_path)
    rows = {row["id"]: row for row in manifest["rows"]}
    first, second = rows[initial], rows[target]
    require(first["status"] == second["status"] == "ready", "both exported rows must be ready")
    for key in ("carrier", "duplex", "layer", "required_cli", "policy_flag"):
        require(first[key] == second[key], f"incompatible row {key}")
    require(first["carrier"] in CARRIERS, "expected maintained TLS, original UDP or raw packet carrier")
    name = "switch-" + initial.rsplit("-", 1)[0] + "-to-" + target
    row = deepcopy(first)
    row.update(id=name, status="ready")
    documents = [read(source / row_i["common_plan"]) for row_i in (first, second)]
    ceiling = max(document["transaction"]["retained_bytes"] for document in documents)
    descriptors = []
    for row_i, document in zip((first, second), documents):
        require(document["catalog"] == [row_i["expected_descriptor_hex"]] and document["initial_index"] == 0,
                "expected original singleton descriptor")
        descriptors.extend(document.pop("catalog"))
        document["transaction"]["retained_bytes"] = ceiling
    require(documents[0] == documents[1] and descriptors[0] != descriptors[1],
            "incompatible runtime parameters or identical modes")
    catalog = hashlib.sha256(b"l2tunnel/record-transaction-catalog/v5\0")
    catalog.update(len(descriptors).to_bytes(2, "big"))
    for value in sorted(bytes.fromhex(item) for item in descriptors):
        catalog.update(value)
    combined = documents[0]
    combined["catalog"] = descriptors
    row["common_plan"] = name + ".common.json"
    row["catalog_digest_hex"] = catalog.hexdigest()
    row["parameters"]["runtime_retained_bytes"] = ceiling
    row["mode_switch"] = {
        "initial_row": initial,
        "target_row": target,
        "initial_descriptor_hex": descriptors[0],
        "target_descriptor_hex": descriptors[1],
        "source_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "source_plans_sha256": [hashlib.sha256((source / r["common_plan"]).read_bytes()).hexdigest()
                                for r in (first, second)],
    }
    save(output / row["common_plan"], combined)
    if first["carrier"] in POLICY_CARRIERS:
        for side in ("a", "b"):
            current = read(source / first["carrier_policy"][side])
            require(current == read(source / second["carrier_policy"][side]), "carrier policy differs")
            row["carrier_policy"][side] = f"{name}.{side}.carrier.json"
            save(output / row["carrier_policy"][side], current)
    return row


def default_kind(carriers):
    """Return the manifest kind used by the original UDP/TLS and raw-only generators."""
    return "closeout-live-raw-mode-switch" if tuple(carriers) == ("raw",) else "closeout-live-mode-switch"


def build(sources, carriers, pairs, output, kind=None):
    """Compose every selected carrier/pair row into ``output`` and write its manifest."""
    rows = []
    for carrier in carriers:
        for pair in pairs:
            initial, target = PAIRS[pair]
            rows.append(compose(sources[pair], f"{initial}-{carrier}", f"{target}-{carrier}", output))
    save(output / "manifest.json", {"version": 1, "kind": kind or default_kind(carriers),
                                    "rows": rows, "ready_rows": len(rows), "all_rows": len(rows)})
    return rows


def parse(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c48", type=Path, help="--packed-c48-pair export directory")
    parser.add_argument("--base", type=Path, help="default export directory")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--carrier", action="append", choices=CARRIERS,
                        help="carrier to compose (repeatable; default: udp and tls)")
    parser.add_argument("--pair", action="append", choices=tuple(PAIRS),
                        help="source pair to compose (repeatable; default: c48 and base)")
    parser.add_argument("--kind", help="manifest kind (default depends on the selected carriers)")
    args = parser.parse_args(argv)
    # Keep the original carrier-major, c48-then-base order regardless of option order.
    selected = set(args.carrier or DEFAULT_CARRIERS)
    args.carrier = [c for c in CARRIERS if c in selected]
    selected = set(args.pair or PAIRS)
    args.pair = [p for p in PAIRS if p in selected]
    for pair in args.pair:
        if getattr(args, pair) is None:
            parser.error(f"--{pair} is required when the {pair} pair is selected")
    return args


def main(argv=None):
    args = parse(argv)
    args.output.mkdir()
    rows = build({"c48": args.c48, "base": args.base}, args.carrier, args.pair, args.output, args.kind)
    print("\n".join(row["id"] for row in rows))


if __name__ == "__main__":
    main()
