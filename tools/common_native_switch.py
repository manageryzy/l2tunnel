"""Exercise an authenticated API4 record-profile switch during a live benchmark.

Used by common_native_matrix.py --switch-during-phase; switch rows come from
common_native_switch_plans.py.
"""
import hashlib
import json
import time


def require(condition, explanation):
    if not condition:
        raise ValueError(explanation)


def descriptor(configuration):
    raw = bytes.fromhex(configuration)
    require(len(raw) > 48, "incomplete canonical configuration")
    return (raw[:16] + raw[48:]).hex()


def rpc(case, binary, secrets, deadline, side, action, *flags):
    raw = case.command(
        "endpoint_" + side, binary, action, "--control-socket",
        secrets / f"control-{side}.sock", "--api-version", "4", *flags,
        deadline=deadline, allow_failure=True,
    )
    replies = [json.loads(line) for line in raw.splitlines() if line.startswith("{")]
    require(len(replies) == 1, f"{side} {action}: missing or ambiguous RPC response")
    reply = replies[0]
    require(reply.get("version") == 4 and reply.get("ok") is True and reply.get("code") == "ok",
            f"{side} {action}: {reply.get('code')} {reply.get('error', '')}")
    state = reply["state"]
    result = state["common"]
    require(state["phase"] == "forwarding" and result["running"] is True,
            f"{side} {action}: daemon stopped forwarding")
    return result


IDENTITIES = ("session", "transcript", "outer", "configuration", "catalog")


def summarize(states):
    return {side: {key: state[key] for key in
                   (*IDENTITIES, "current", "epoch", "generation", "phase", "operation")}
            for side, state in states.items()}


def switch_during_phase(case, binary, secrets, deadline):
    """Called once from the live phase, after its measurement clock starts."""
    switch = case.row["mode_switch"]
    report = {"status": "running", "started_ns": time.monotonic_ns(),
              "initial_row": switch["initial_row"], "target_row": switch["target_row"]}
    case.value["mode_switch"] = report
    case.save()
    try:
        def statuses():
            return {side: rpc(case, binary, secrets, deadline, side, "status")
                    for side in ("a", "b")}

        before = statuses()
        sender = before["a"]
        report["before"] = summarize(before)
        for side in ("a", "b"):
            state = before[side]
            require(all(state[k] == sender[k] for k in (*IDENTITIES, "epoch", "current")),
                    "initial peer binding mismatch")
            require(state["phase"] == "idle" and state["operation"] is None,
                    "operation already active")
            require(descriptor(state["current"]) == case.row["expected_descriptor_hex"],
                    "initial descriptor differs from the measurement manifest")
        root = bytes(sender["catalog"]).hex()
        require(root == case.row["catalog_digest_hex"], "live catalog differs from composed plan")
        page_state = rpc(case, binary, secrets, deadline, "a", "common-catalog",
                         "--generation", str(sender["generation"]), "--catalog", root,
                         "--offset", "0", "--limit", "2")
        page = page_state["catalog_page"]
        require(page_state["catalog"] == sender["catalog"] and page_state["generation"] == sender["generation"]
                and page["offset"] == 0 and page["total"] == 2 and page["next"] is None,
                "incomplete or stale live catalog")
        options = page["configurations"]
        targets = [item for item in options if descriptor(item) == switch["target_descriptor_hex"]]
        require(len(options) == 2 and sender["current"] in options and len(targets) == 1
                and targets[0] != sender["current"], "live target absent or ambiguous")
        target = targets[0]
        key = sender["next_request_key"]
        flags = ("--request-key", str(key), "--configuration", target)
        epoch = sender["epoch"] + 1
        report.update(request_key=key, requested_epoch=epoch,
                      target_sha256=hashlib.sha256(bytes.fromhex(target)).hexdigest(),
                      requested_ns=time.monotonic_ns())
        case.save()
        reply = rpc(case, binary, secrets, deadline, "a", "switch-common-configuration", *flags)
        report["rpc_return_ns"] = time.monotonic_ns()
        completed = reply["result"]
        require(completed["configuration"] == target and completed["request_key"] == key
                and completed["epoch"] == epoch and completed["outcome"] == "ok"
                and type(completed["operation"]) is int, "switch completion differs from keyed request")
        while True:
            case.check(deadline)
            after = statuses()
            for side, state in after.items():
                require(all(state[k] == before[side][k] for k in (*IDENTITIES, "generation")),
                        "switch replaced original session, carrier or catalog")
            if all(s["current"] == target and s["epoch"] == epoch and s["phase"] == "idle"
                   and s["operation"] is None for s in after.values()):
                break
            time.sleep(0.025)
        report["settled_ns"] = time.monotonic_ns()
        report["after"] = summarize(after)
        replay = rpc(case, binary, secrets, deadline, "a", "switch-common-configuration", *flags)
        require(replay["result"] == completed and replay["epoch"] == epoch and replay["current"] == target,
                "retry did not return the original keyed result")
        report.update(status="passed", result=completed, replay_verified=True,
                      finished_ns=time.monotonic_ns())
        # Original requested row remains in the receipt and exported immutable manifest.
        case.row = dict(case.row, expected_descriptor_hex=switch["target_descriptor_hex"])
    except Exception as error:
        report.update(status="failed", failure_type=type(error).__name__, error=str(error),
                      finished_ns=time.monotonic_ns())
        raise
    finally:
        case.save()
