#!/usr/bin/env python3
"""Scan committed Git history with redacted output and verify the scanner gate."""

import argparse
import base64
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile


def scan(binary, repository, report):
    env = os.environ.copy()
    env.pop("GITLEAKS_CONFIG", None)
    env.pop("GITLEAKS_CONFIG_TOML", None)
    result = subprocess.run(
        [binary, "git", "--no-banner", "--no-color", "--redact=100", "--log-opts=--all",
         "--report-format=json", "--report-path=" + str(report), "."],
        cwd=repository, env=env, capture_output=True, text=True,
    )
    if result.returncode not in (0, 1) or not report.is_file():
        raise RuntimeError("secret scanner failed to produce a report")
    findings = json.loads(report.read_text(encoding="utf-8")) or []
    if bool(findings) != bool(result.returncode):
        raise RuntimeError("secret scanner exit status disagrees with its report")
    # Never emit Match/Secret fields, source excerpts, or credential material.
    for finding in findings:
        print(json.dumps({key: finding.get(key) for key in ("RuleID", "File", "StartLine", "Fingerprint")}))
    return findings


def self_test(binary, directory):
    root = directory / "canary"
    root.mkdir()
    canary = base64.urlsafe_b64encode(hashlib.sha256(b"relay-gate public scanner canary, never a real key").digest()).decode()
    (root / "canary.txt").write_text('api_key = "' + canary + '"\n', encoding="utf-8")
    for args in (("init", "-q"), ("add", "canary.txt"), ("-c", "user.name=Scanner fixture", "-c", "user.email=scanner@example.invalid", "commit", "-qm", "canary fixture")):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    if not scan(binary, root, directory / "canary-report.json"):
        raise RuntimeError("secret scanner failed to detect the deliberate canary")
    print("scanner self-test passed: a newly committed canary is rejected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", default="gitleaks")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="relay-secret-scan-") as temporary:
        directory = pathlib.Path(temporary)
        if args.self_test:
            self_test(args.gitleaks, directory)
        findings = scan(args.gitleaks, pathlib.Path(__file__).resolve().parents[1], directory / "history-report.json")
        if findings:
            raise SystemExit(f"committed history contains {len(findings)} unreviewed secret findings")
        print("committed history passed: no unreviewed findings")
