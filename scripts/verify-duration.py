#!/usr/bin/env python3
"""Run actual-duration loopback acceptance; short runs never count as long/soak.

Requires PowerShell 7 for process resource samples. Reports contain no credentials.
Examples:
  python scripts/verify-duration.py --binary /abs/relay-gate --mode long --seconds 2105 --report /abs/long.json
  python scripts/verify-duration.py --binary /abs/relay-gate --mode soak --seconds 172800 --report /abs/soak.json
"""

import argparse
import concurrent.futures
import hashlib
import http.server
import importlib.util
import json
import math
import pathlib
import shutil
import subprocess
import tempfile
import threading
import time


spec = importlib.util.spec_from_file_location("runtime_verify", pathlib.Path(__file__).with_name("verify-runtime.py"))
runtime_verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime_verify)


class LongUpstream(runtime_verify.MockUpstream):
    seconds = 0

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        heartbeat = b": ping\n\n"
        beats = max(1, math.ceil(self.seconds / 5))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(runtime_verify.SEMANTIC) + beats * len(heartbeat) + len(runtime_verify.END)))
        self.end_headers()
        self.wfile.write(runtime_verify.SEMANTIC)
        self.wfile.flush()
        start = time.monotonic()
        for index in range(beats):
            time.sleep(max(0, start + (index + 1) * self.seconds / beats - time.monotonic()))
            self.wfile.write(heartbeat)
            self.wfile.flush()
        self.wfile.write(runtime_verify.END)
        self.wfile.flush()


def sample_process(pwsh, pid, started):
    command = f"$taskProcess = Get-Process -Id {pid}; [pscustomobject]@{{rss_bytes=$taskProcess.WorkingSet64;private_bytes=$taskProcess.PrivateMemorySize64;handles=$taskProcess.HandleCount;threads=$taskProcess.Threads.Count;cpu_seconds=$taskProcess.CPU}} | ConvertTo-Json -Compress"
    raw = subprocess.check_output([pwsh, "-NoProfile", "-NonInteractive", "-Command", command], text=True, timeout=10)
    sample = json.loads(raw)
    sample.update(elapsed_seconds=round(time.monotonic() - started, 3), pid=pid)
    return sample


def resource_bounds(samples, minimum_window):
    warm = [sample for sample in samples if sample["elapsed_seconds"] >= min(1800, minimum_window / 3)]
    if len(warm) < 2:
        return {"rss_peak_bytes": max(sample["rss_bytes"] for sample in samples), "rss_slope_bytes_per_hour": None}
    times = [sample["elapsed_seconds"] for sample in warm]
    values = [sample["rss_bytes"] for sample in warm]
    mean_t, mean_v = sum(times) / len(times), sum(values) / len(values)
    denominator = sum((stamp - mean_t) ** 2 for stamp in times)
    slope = sum((stamp - mean_t) * (value - mean_v) for stamp, value in zip(times, values)) / denominator * 3600 if denominator else 0
    return {"rss_peak_bytes": max(sample["rss_bytes"] for sample in samples), "rss_slope_bytes_per_hour": round(slope, 3), "handle_growth": max(sample["handles"] for sample in warm) - min(sample["handles"] for sample in warm), "threads_peak": max(sample["threads"] for sample in samples)}


def run(args):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        raise RuntimeError("PowerShell 7 is required for resource sampling")
    report = {"format_version": 1, "mode": args.mode, "requested_seconds": args.seconds, "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(), "source_revision": args.source_revision, "status": "running", "samples": [], "requests": 0, "errors": 0, "upstream": "loopback fixture only", "duration_gate_passed": False}
    args.report.parent.mkdir(parents=True, exist_ok=True)

    def save():
        temporary = args.report.with_suffix(args.report.suffix + ".tmp")
        temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        temporary.replace(args.report)

    with tempfile.TemporaryDirectory(prefix="relay-duration-") as directory:
        runtime = runtime_verify.Runtime(args.binary, pathlib.Path(directory))
        handler = LongUpstream if args.mode == "long" else runtime_verify.MockUpstream
        LongUpstream.seconds = args.seconds
        remote = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        remote.daemon_threads = True
        threading.Thread(target=remote.serve_forever, daemon=True).start()
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        started = time.monotonic()
        try:
            runtime.start()
            version = json.loads(runtime.request("GET", "/healthz", auth=False)[1])["version"]
            assert version == args.source_revision, "binary version does not match the recorded source revision"
            _, body = runtime.seed(remote.server_port)
            settings = runtime.api("GET", "/settings")
            runtime.api("PUT", "/settings", {"real_total_sec": max(1800, math.ceil(args.seconds) + 120), "expected_revision": settings["revision"]})
            started = time.monotonic()
            next_sample, next_pause = started, started + 1800
            future = pool.submit(runtime.request, "POST", "/v1/messages", body, True, True) if args.mode == "long" else None
            while time.monotonic() - started < args.seconds or (future and not future.done()):
                now = time.monotonic()
                if now - started > args.seconds + 60:
                    raise AssertionError("response did not finish within the duration plus shutdown allowance")
                if args.mode == "soak":
                    status, raw, _ = runtime.request("POST", "/v1/messages", body, proxy=True)
                    report["requests"] += 1
                    if status != 200 or raw != runtime_verify.SEMANTIC + runtime_verify.END:
                        report["errors"] += 1
                        raise AssertionError("soak response failed its exact wire contract")
                    if now >= next_pause:
                        state = runtime.api("GET", "/state")
                        paused = runtime.api("POST", "/state", {"state": "paused", "expected_revision": state["revision"]})
                        assert runtime.request("POST", "/v1/messages", body, proxy=True)[0] == 503
                        runtime.api("POST", "/state", {"state": "running", "expected_revision": paused.get("revision", paused.get("new_revision"))})
                        next_pause = now + 1800
                if now >= next_sample:
                    report["samples"].append(sample_process(pwsh, runtime.process.pid, started))
                    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
                    save()
                    print(f"{args.mode}: {int(report['elapsed_seconds'])}s, requests={report['requests']}, errors={report['errors']}", flush=True)
                    next_sample = now + min(60, max(1, args.seconds / 10))
                if future and future.done():
                    break
                time.sleep(1 if args.mode == "long" else 0.5)
            if future:
                status, raw, _ = future.result(timeout=30)
                beats = max(1, math.ceil(args.seconds / 5))
                assert status == 200 and raw == runtime_verify.SEMANTIC + b": ping\n\n" * beats + runtime_verify.END, "long stream changed bytes or ended early"
                report["requests"] = 1
            runtime_verify.eventually(lambda: not runtime.api("GET", "/runtime")["in_flight"])
            report["samples"].append(sample_process(pwsh, runtime.process.pid, started))
            elapsed = time.monotonic() - started
            assert elapsed >= args.seconds, "wall-clock duration was shortened"
            report["elapsed_seconds"] = round(elapsed, 3)
            report["resources"] = resource_bounds(report["samples"], args.seconds)
            gaps = [later["elapsed_seconds"] - earlier["elapsed_seconds"] for earlier, later in zip(report["samples"], report["samples"][1:])]
            report["resources"]["max_sample_gap_seconds"] = round(max(gaps, default=0), 3)
            assert report["resources"]["max_sample_gap_seconds"] <= 120, "sampling gap prevents proving continuous runtime"
            assert report["resources"]["rss_peak_bytes"] <= 512 << 20, "RSS exceeded the acceptance ceiling"
            if args.mode == "soak" and args.seconds >= 172800:
                assert report["resources"]["rss_slope_bytes_per_hour"] <= 2 << 20, "sustained RSS growth exceeded the acceptance bound"
                assert report["resources"]["handle_growth"] <= 32 and report["resources"]["threads_peak"] <= 128, "process resources kept growing"
            report["duration_gate_passed"] = (args.mode == "long" and args.seconds > 2100) or (args.mode == "soak" and args.seconds >= 172800)
            report["status"] = "passed" if report["duration_gate_passed"] else "short_contract_only"
            save()
        except BaseException as error:
            report.update(status="failed", failure=type(error).__name__, elapsed_seconds=round(time.monotonic() - started, 3))
            save()
            raise
        finally:
            runtime.stop()
            pool.shutdown(wait=True, cancel_futures=True)
            remote.shutdown()
            remote.server_close()
    print(f"report: {args.report}; status={report['status']}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--mode", choices=("long", "soak"), required=True)
    parser.add_argument("--seconds", type=float, required=True)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    if args.seconds <= 0:
        parser.error("--seconds must be positive")
    args.binary, args.report = args.binary.resolve(strict=True), args.report.resolve()
    run(args)
