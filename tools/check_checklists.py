#!/usr/bin/env python3
"""Validate the persistent implementation ledger without changing task status."""
from __future__ import annotations

from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = (
    "docs/implementation-checklist.md",
    "docs/flow-control.md",
    "docs/overlay-and-carriers.md",
    "docs/client-design.md",
    "docs/development-workflow.md",
) + tuple(str(path.relative_to(ROOT)) for path in sorted((ROOT / "docs/modules").glob("*.md")))
ITEM = re.compile(r"^- \[([ x])\] \[([A-Za-z0-9:-]+)\] (.+)$")


def validate(documents: dict[str, str], modes: list[dict]) -> dict[str, int]:
    tasks: dict[str, tuple[bool, str]] = {}
    for path, content in documents.items():
        for line in content.splitlines():
            if not line.startswith(("- [ ]", "- [x]")):
                continue
            match = ITEM.fullmatch(line)
            if match is None:
                raise ValueError(f"{path}: checkbox lacks a stable task ID")
            state, identity, description = match.groups()
            if identity in tasks:
                raise ValueError(f"duplicate checklist ID: {identity}")
            done = state == "x"
            if done and ("Evidence:" not in description or "](" not in description):
                raise ValueError(f"checked item lacks an evidence link: {identity}")
            tasks[identity] = (done, description)
    expected = {"P-" + mode["id"] for mode in modes}
    actual = {identity for identity in tasks if identity.startswith("P-")}
    if actual != expected:
        raise ValueError(f"parity checklist mismatch: missing={sorted(expected - actual)}, extra={sorted(actual - expected)}")
    for mode in modes:
        done = tasks["P-" + mode["id"]][0]
        if done != (mode["status"] in {"implemented", "integration-tested"}):
            raise ValueError(f"mode/checklist status mismatch: {mode['id']}")
    return {"tasks": len(tasks), "completed": sum(done for done, _ in tasks.values()), "parity_modes": len(expected)}


def main() -> None:
    documents = {path: (ROOT / path).read_text() for path in DOCUMENTS}
    modes = tomllib.loads((ROOT / "config/mode-catalog.toml").read_text())["mode"]
    result = validate(documents, modes)
    print(f"Checklist validated: {result['tasks']} unique tasks, {result['completed']} checked, {result['parity_modes']} parity gates.")


if __name__ == "__main__":
    main()
