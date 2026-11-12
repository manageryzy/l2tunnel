"""Comparable sixteen-flow direct TCP and QUIC controls with observed RTT."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from hashlib import sha256
import json
from pathlib import Path
import platform
from random import Random

from importlib.metadata import version

from payload_sizes import execute, summarize, write_csv


def report(out, summaries):
    table = ("<table><tr><th>Transport</th><th>Payload Mbps</th><th>95% CI</th><th>Post-warmup Mbps</th>"
             "<th>Protocol RTT P50/P95/P99 ms</th><th>ACK completion P99 ms</th>"
             "<th>Frame P99 ms</th><th>Minimum completion</th><th>Confirmed runs</th></tr>")
    for row in summaries:
        stem = "quic_latest_rtt" if row["rtt_protocol"] == "quic" else "tcp_timestamp_rtt"
        rtt = "/".join(f'{row[f"{stem}_p{p}_ms_mean"]:.2f}' for p in (50, 95, 99))
        ack = row["tcp_ack_rtt_p99_ms_mean"]
        table += (f'<tr><td>{row["strategy"]}</td><td>{row["application_goodput_mbps_mean"]:.3f}</td>'
                  f'<td>{row["application_goodput_mbps_ci_low"]:.3f}–{row["application_goodput_mbps_ci_high"]:.3f}</td>'
                  f'<td>{row["steady_application_goodput_mbps_mean"]:.3f}</td><td>{rtt}</td>'
                  f'<td>{ack:.2f}</td>' if ack is not None else
                  f'<tr><td>{row["strategy"]}</td><td>{row["application_goodput_mbps_mean"]:.3f}</td>'
                  f'<td>{row["application_goodput_mbps_ci_low"]:.3f}–{row["application_goodput_mbps_ci_high"]:.3f}</td>'
                  f'<td>{row["steady_application_goodput_mbps_mean"]:.3f}</td><td>{rtt}</td><td>—</td>')
        table += (f'<td>{row["frame_p99_ms_mean"]:.2f}</td>'
                  f'<td>{row["min_delivery_fraction"]:.3%}</td>'
                  f'<td>{row["confirmed_replications"]}/{row["replications"]}</td></tr>')
    table += "</table>"
    text = (
        "<h1>Comparable sixteen-flow transport controls</h1>"
        "<p>Every transport uses sixteen independent connections sharing one 100 Mbps forward "
        "link and 10 Mbps reverse link, with 70 ms configured propagation RTT and independent "
        "15% packet erasures in both directions. The total application window is fixed at "
        "4 MiB. Each native TCP segment or full L2 QUIC record represents 1448 application bytes.</p>"
        "<p>Each of five seeded replications offers traffic for 60 seconds and drains for "
        "20 seconds. The post-warmup interval spans seconds 5 through 60. Throughput excludes "
        "drain deliveries. Byte and packet overhead counts include drain transmissions. "
        "Protocol RTT percentiles use samples observed during seconds 0 through 60. "
        "Confidence intervals use replication statistics.</p>"
        "<p>Plain TCP uses the modeled CUBIC controller and NewReno recovery, with separate "
        "200 ms and 1000 ms minimum-RTO configurations. Observed TCP RTT is the timestamp "
        "sample supplied to the sender's RTT estimator. ACK completion RTT measures the "
        "elapsed time from original segment submission to a cumulative acknowledgement. "
        "The CSV also records smoothed RTT and post-warmup and drain-inclusive quantiles.</p>"
        "<p>QUIC uses actual aioquic CUBIC over its encrypted reliable stream, carrying complete "
        "1514-byte L2 records. Its reported payload rate is the 1448-byte application equivalent "
        "per complete record. This profile uses QUIC flow control and congestion control. "
        "An inner TCP state machine is absent. QUIC RTT comes from qlog recovery metrics "
        "after ACK processing, with ACK-delay adjustment. The QUIC handshake is completed "
        "before measurement. CPU processing time is excluded from simulated link time.</p>"
        '<p>Raw evidence includes <a href="replications.csv">replications</a>, '
        '<a href="summary.csv">summary and RTT metrics</a>, and '
        '<a href="experiment.json">configuration, runtime versions, and source hashes</a>.</p>'
    )
    (out / "report.html").write_text(
        "<!doctype html><html><head><meta charset='utf-8'><title>16-flow transport controls</title>"
        "<style>body{font:16px system-ui;margin:30px;max-width:1550px}p{max-width:1150px;line-height:1.5}"
        "table{border-collapse:collapse;font-size:14px}td,th{border:1px solid #ddd;padding:8px;text-align:right}"
        "td:first-child{text-align:left}</style></head><body>" + text + table + "</body></html>")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args()
    profiles = [
        dict(name="Plain TCP CUBIC 16 flows RTO200ms", kind="tcp", controller="cubic", rto_min_ms=200,
             flow_count=16, window_bytes=4 * 1048576),
        dict(name="Plain TCP CUBIC 16 flows RTO1s", kind="tcp", controller="cubic", rto_min_ms=1000,
             flow_count=16, window_bytes=4 * 1048576),
        dict(name="QUIC L2 CUBIC 16 flows", kind="quic", controller="cubic", flow_count=16,
             window_bytes=4 * 1048576),
    ]
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(5)]
    tasks = []
    for profile in profiles:
        for replication, seed in enumerate(seeds, 1):
            tasks.append(dict(run_id=len(tasks) + 1, profile=profile, forward_mbps=100, reverse_mbps=10,
                              rtt_ms=70, loss_rate=.15, loss_model="iid", payload_bytes=1448,
                              duration_s=60, warmup_s=5, drain_s=20, replication=replication, seed=seed))
    sources = [Path(__file__), Path(__file__).with_name("payload_sizes.py"),
               *sorted((Path(__file__).parents[1] / "src/l2tunnel_sim").glob("*.py"))]
    manifest = {"tasks": tasks, "sources": {str(path): sha256(path.read_bytes()).hexdigest() for path in sources},
                "runtime": {"python": platform.python_version(),
                            **{package: version(package) for package in ("aioquic", "cryptography", "numpy", "scipy")}},
                "assumptions": ["Native TCP and QUIC use sixteen independent congestion controllers",
                                "All sixteen flows share the physical queues, clocks, and erasure processes",
                                "Total 4 MiB application window is divided across flows",
                                "QUIC throughput is complete L2-record application equivalent without an inner TCP engine",
                                "RTT metrics are observed from protocol processing, not copied from configured propagation RTT"]}
    args.out.mkdir(parents=True, exist_ok=True)
    runs = args.out / "runs"
    runs.mkdir(exist_ok=True)
    manifest_path = args.out / "experiment.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise ValueError("existing experiment differs, select a fresh output directory")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    pending = [task for task in tasks if not (runs / f'{task["run_id"]:04}.json').exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(execute, task) for task in pending]
        for future in as_completed(futures):
            row = future.result()
            path = runs / f'{row["run_id"]:04}.json'
            temp = path.with_suffix(".tmp")
            temp.write_text(json.dumps(row, indent=2) + "\n")
            temp.replace(path)
            print(f'Completed {row["strategy"]} replication {row["replication"]}, '
                  f'{row["application_goodput_mbps"]:.4f} Mbps, '
                  f'{row["tcp_delivery_fraction"]:.3%} delivered', flush=True)
    rows = [json.loads(path.read_text()) for path in sorted(runs.glob("*.json"))]
    write_csv(args.out / "replications.csv", rows)
    summaries = summarize(rows)
    write_csv(args.out / "summary.csv", summaries)
    report(args.out, summaries)
    print(json.dumps({"completed_runs": len(rows), "out": str(args.out)}), flush=True)


if __name__ == "__main__":
    main()
