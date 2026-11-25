#!/usr/bin/env python3
"""Merge exported Common plan rows into one multi-protocol plan.

A live protocol switch can only choose a member of the shared plan's
catalog, and every row the benchmark exporter writes holds exactly one
member. This merge step (owner request 2026-11-24, docs/modules/desktop-gui.md
DGUI-14) combines chosen rows of one export into a plan whose catalog holds
all of them, so the Connection page can switch between them live.

Rules (the same as the two-member ``common_native_switch_plans.compose``):

- every row is ``ready`` and agrees on carrier, duplex, layer, required CLI
  and policy flag;
- every source plan is an original singleton (its catalog is exactly the
  row's descriptor, initial index 0);
- apart from the catalog, the plans must be identical, except
  ``transaction.retained_bytes``, which becomes the largest of them so every
  member fits; anything else that differs (runtime, ingress, rolling work)
  refuses the merge;
- descriptors must be distinct; the first row is the initial member;
- TLS and raw carrier policy files must be identical and are copied.

Output: ``NAME.common.json`` and a ``manifest.json`` with one row, in the
exporter's format, so ``local_real_pair.py`` and the native matrix accept it.
Existing output files are never overwritten. The service still validates the
merged plan when a profile using it is saved or connected.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

CATALOG_DOMAIN = b"l2tunnel/record-transaction-catalog/v5\0"
# Plans hold at most this many catalog members (local API catalog paging
# and the GUI list handle it; the runtime bounds its own catalog).
MAX_MEMBERS = 64
POLICY_CARRIERS = ("tls", "raw")
AGREEING = ("carrier", "duplex", "layer", "required_cli", "policy_flag")
NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def read(path: Path):
    return json.loads(path.read_bytes())


def save(path: Path, value) -> None:
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def catalog_digest(descriptors: list[str]) -> str:
    """Order-independent catalog digest, as the switch-plan tool computes it."""
    digest = hashlib.sha256(CATALOG_DOMAIN)
    digest.update(len(descriptors).to_bytes(2, "big"))
    for value in sorted(bytes.fromhex(item) for item in descriptors):
        digest.update(value)
    return digest.hexdigest()


def differences(left, right, path: str = "") -> list[str]:
    """Paths where two plan documents differ."""
    if isinstance(left, dict) and isinstance(right, dict):
        found = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                found.append(f"{path}/{key} (only in one plan)")
            else:
                found.extend(differences(left[key], right[key], f"{path}/{key}"))
        return found
    return [] if left == right else [path or "/"]


def merge(source: Path, row_ids: list[str], name: str, output: Path) -> dict:
    """Merge ``row_ids`` of the export in ``source`` into ``output``."""
    require(bool(NAME.fullmatch(name)), "name must be lowercase letters, digits and dashes")
    require(2 <= len(row_ids) <= MAX_MEMBERS, f"choose 2 to {MAX_MEMBERS} rows")
    require(len(set(row_ids)) == len(row_ids), "a row is named twice")
    manifest_path = source / "manifest.json"
    manifest = read(manifest_path)
    rows = {row["id"]: row for row in manifest["rows"]}
    missing = [row_id for row_id in row_ids if row_id not in rows]
    require(not missing, f"unknown rows: {', '.join(missing)}")
    chosen = [rows[row_id] for row_id in row_ids]
    first = chosen[0]
    for row in chosen:
        require(row["status"] == "ready", f"{row['id']} is not ready")
        for key in AGREEING:
            require(row.get(key) == first.get(key),
                    f"{row['id']} differs from {first['id']} in {key}")
    documents = [read(source / row["common_plan"]) for row in chosen]
    descriptors = []
    for row, document in zip(chosen, documents):
        require(document.get("catalog") == [row["expected_descriptor_hex"]]
                and document.get("initial_index") == 0,
                f"{row['id']} is not an original singleton plan")
        descriptors.extend(document.pop("catalog"))
    require(len(set(descriptors)) == len(descriptors), "two rows have the same descriptor")
    ceiling = max(document["transaction"]["retained_bytes"] for document in documents)
    for document in documents:
        document["transaction"]["retained_bytes"] = ceiling
    for row, document in zip(chosen[1:], documents[1:]):
        found = differences(documents[0], document)
        require(not found, f"{row['id']} cannot share a plan with {first['id']}: "
                           f"{', '.join(found[:4])}{' …' if len(found) > 4 else ''}")
    combined = documents[0]
    combined["catalog"] = descriptors
    combined["initial_index"] = 0
    merged = deepcopy(first)
    merged.update(id=name, status="ready", common_plan=f"{name}.common.json",
                  catalog_digest_hex=catalog_digest(descriptors))
    merged.setdefault("parameters", {})["runtime_retained_bytes"] = ceiling
    merged["merged"] = {
        "rows": row_ids,
        "descriptors_hex": descriptors,
        "source_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "source_plans_sha256": [hashlib.sha256((source / row["common_plan"]).read_bytes()).hexdigest()
                                for row in chosen],
    }
    policies = {}
    if first["carrier"] in POLICY_CARRIERS:
        for side in ("a", "b"):
            current = read(source / first["carrier_policy"][side])
            for row in chosen[1:]:
                require(current == read(source / row["carrier_policy"][side]),
                        f"{row['id']} has a different side-{side} carrier policy")
            merged["carrier_policy"][side] = f"{name}.{side}.carrier.json"
            policies[merged["carrier_policy"][side]] = current
    output.mkdir(parents=True, exist_ok=True)
    targets = [output / merged["common_plan"], output / "manifest.json", *(output / p for p in policies)]
    existing = [str(path) for path in targets if path.exists()]
    require(not existing, f"refusing to overwrite: {', '.join(existing)}")
    save(output / merged["common_plan"], combined)
    for file_name, value in policies.items():
        save(output / file_name, value)
    save(output / "manifest.json", {"version": 1, "kind": "merged-catalog", "rows": [merged],
                                    "ready_rows": 1, "all_rows": 1})
    return merged


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path, required=True, help="export directory with manifest.json")
    parser.add_argument("--row", action="append", required=True, dest="rows",
                        help="row id to include; repeat, the first is the initial member")
    parser.add_argument("--name", required=True, help="name of the merged row and plan file")
    parser.add_argument("--output", type=Path, required=True, help="directory for the merged plan")
    args = parser.parse_args(argv)
    try:
        merged = merge(args.source, args.rows, args.name, args.output)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(2, f"merge_common_plans: {error}\n")
    print(f"{merged['common_plan']}: {len(args.rows)} members, catalog {merged['catalog_digest_hex']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
