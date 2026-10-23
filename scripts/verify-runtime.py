#!/usr/bin/env python3
"""Exercise a real binary with disposable data and a loopback-only upstream.

No existing data, environment credentials, online provider or paid probe is used.
Run: python scripts/verify-runtime.py --binary /absolute/path/to/relay-gate
"""

import argparse
import concurrent.futures
from contextlib import closing
import gzip
import hashlib
import http.server
import json
import os
import pathlib
import re
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


SEMANTIC = b'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}\n\n'
END = b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
PRIVATE = "PRIVATE_RUNTIME_FIXTURE_72b04a"


def eventually(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except (OSError, sqlite3.Error, urllib.error.URLError):
            pass
        time.sleep(0.03)
    raise AssertionError("runtime condition did not become true before deadline")


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class MockUpstream(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    mode = "complete"
    started = threading.Event()
    release = threading.Event()

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.respond(b'{"object":"list","data":[{"id":"fixture"}]}', "application/json")

    def respond(self, wire, content_type, encoding=""):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(wire)))
        self.send_header("Connection", "close")
        if encoding:
            self.send_header("Content-Encoding", encoding)
        self.end_headers()
        self.wfile.write(wire)
        self.wfile.flush()

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path.endswith("count_tokens"):
            self.respond(b'{"input_tokens":13}', "application/json")
            return
        wire = SEMANTIC + (b"" if self.mode == "partial" else END)
        if self.mode == "gzip":
            self.respond(gzip.compress(wire, mtime=0), "text/event-stream", "gzip")
        elif self.mode == "blocked":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(wire)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(SEMANTIC)
            self.wfile.flush()
            self.started.set()
            if not self.release.wait(20):
                return
            self.wfile.write(END)
            self.wfile.flush()
        else:
            self.respond(wire, "text/event-stream")


class Runtime:
    def __init__(self, binary, root):
        # macOS /var and Windows short TEMP names may be filesystem aliases.
        # Exercise the canonical path, as the production instance lock requires.
        self.binary, self.root = binary, root.resolve()
        self.database = self.root / "runtime.db"
        self.port = free_port()
        self.origin = f"http://127.0.0.1:{self.port}"
        self.process = None
        self.log = None
        self.starts = 0
        self.admin = self.relay = ""
        self.cookie = ""
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def start(self):
        self.starts += 1
        path = self.root / f"process-{self.starts}.log"
        self.log = path.open("wb")
        env = os.environ.copy()
        for name in ("ADMIN_PASSWORD", "RELAY_KEYS", "ENCRYPTION_KEY", "RELAY_TRUSTED_PROXY_IPS", "RELAY_PUBLIC_ORIGIN", "RELAY_PUBLIC_HTTPS_STATUS_FILE"):
            env.pop(name, None)
        env.update(RELAY_DB=str(self.database), RELAY_ADDR=f"127.0.0.1:{self.port}")
        self.process = subprocess.Popen([str(self.binary)], env=env, stdout=self.log, stderr=subprocess.STDOUT, cwd=self.root)
        try:
            eventually(lambda: self.request("GET", "/healthz", auth=False)[0] == 200)
        except AssertionError as error:
            diagnostic = path.read_text(encoding="utf-8", errors="replace")
            diagnostic = re.sub(r"(?m)^(ADMIN_PASSWORD|RELAY_KEYS|ENCRYPTION_KEY)=.*$", r"\1=[REDACTED]", diagnostic)
            raise AssertionError(f"binary startup failed (exit={self.process.poll()}): " + diagnostic[-4000:]) from error
        text = path.read_text(encoding="utf-8")
        if self.starts == 1:
            self.admin = re.search(r"^ADMIN_PASSWORD=(\S+)$", text, re.M)[1]
            self.relay = re.search(r"^RELAY_KEYS=(\S+)$", text, re.M)[1]
        else:
            assert "ADMIN_PASSWORD=" not in text, "cold restart repeated bootstrap credentials"
        status, _, headers = self.request("POST", "/admin/api/login", {"password": self.admin}, auth=False)
        assert status == 200, "fixture administrator could not log in"
        self.cookie = headers["Set-Cookie"].split(";", 1)[0]

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            self.process.wait(timeout=15)
            self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def request(self, method, path, body=None, auth=True, proxy=False):
        data = None if body is None else json.dumps(body).encode()
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = "Bearer " + (self.relay if proxy else self.admin)
            if not proxy and self.cookie:
                headers.update(Cookie=self.cookie, Origin=self.origin)
        if proxy:
            headers.update({"User-Agent": "claude-cli/2.1.0 (external, cli)", "anthropic-version": "2023-06-01"})
        request = urllib.request.Request(self.origin + path, data=data, headers=headers, method=method)
        try:
            response = self.client.open(request, timeout=25)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.read(), response.headers

    def api(self, method, path, body=None, expected=200):
        status, raw, _ = self.request(method, "/admin/api" + path, body)
        assert status == expected, f"{method} {path} returned {status}, expected {expected}"
        return json.loads(raw) if raw else None

    def sql(self, query, args=()):
        with closing(sqlite3.connect(self.database.as_uri() + "?mode=ro", uri=True, timeout=2)) as database:
            return database.execute(query, args).fetchall()

    def seed(self, upstream_port):
        endpoints = [{"endpoint": kind, "auth_profile": {"mode": "header_bearer", "secret_ref": "upstream_api_key"}}
                     for kind in ("models", "messages", "responses", "chat_completions", "count_tokens")]
        upstream = self.api("POST", "/upstreams", {"name": "runtime-fixture", "base_url": f"http://127.0.0.1:{upstream_port}", "api_key": "fixture-upstream-credential", "probe_mode": "lazy", "initial_endpoints": endpoints}, 201)
        model = self.api("POST", "/model-names", {"name": "runtime-model", "protocol": "anthropic"}, 201)
        self.api("POST", "/routes", {"upstream_id": upstream["id"], "model_name_id": model["id"], "priority": 1, "weight": 100}, 201)
        body = {"model": "runtime-model", "messages": [{"role": "user", "content": PRIVATE}], "stream": True}
        return upstream, body


def verify(binary):
    with tempfile.TemporaryDirectory(prefix="relay-runtime-verify-") as directory:
        runtime = Runtime(binary, pathlib.Path(directory))
        remote = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockUpstream)
        remote.daemon_threads = True
        threading.Thread(target=remote.serve_forever, daemon=True).start()
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=3)
        try:
            runtime.start()
            assert runtime.sql("SELECT version FROM schema_version") == [(11,)]
            assert runtime.request("GET", "/admin/api/upstreams", auth=False)[0] == 401
            upstream, body = runtime.seed(remote.server_port)
            for mode, expected in (("complete", SEMANTIC + END), ("partial", SEMANTIC), ("gzip", gzip.compress(SEMANTIC + END, mtime=0))):
                MockUpstream.mode = mode
                status, wire, _ = runtime.request("POST", "/v1/messages", body, proxy=True)
                assert status == 200 and wire == expected, "proxy changed original response bytes"
            eventually(lambda: runtime.sql("SELECT COUNT(*) FROM probe_execution WHERE trigger='real_traffic'")[0][0] == 3)
            rows = runtime.sql("SELECT success,partial,normal_end_seen FROM probe_execution WHERE trigger='real_traffic' ORDER BY observation_order")
            assert rows == [(1, 0, 1), (0, 1, 0), (1, 0, 1)], "wire completeness was not persisted correctly"
            eventually(lambda: runtime.sql("SELECT seen_count FROM client_probe_profile") == [(2,)])
            profiles = runtime.sql("SELECT safe_headers_json,fixed_raw_query,body_template,body_shape_json,revision FROM client_probe_profile")
            assert PRIVATE not in repr(profiles) and profiles[0][-1] == 1, "private content or telemetry changed profile identity"
            eventually(lambda: runtime.sql("SELECT COUNT(*) FROM sample_request") == [(3,)])
            before_samples = 3
            settings = runtime.api("GET", "/settings")
            runtime.api("PUT", "/settings", {"sample_enabled": False, "expected_revision": settings["revision"]})
            MockUpstream.mode = "complete"
            assert runtime.request("POST", "/v1/messages", body, proxy=True)[0] == 200
            eventually(lambda: runtime.sql("SELECT seen_count FROM client_probe_profile") == [(3,)])
            assert runtime.sql("SELECT COUNT(*) FROM sample_request")[0][0] == before_samples, "sample switch did not remain independent"
            status = runtime.api("GET", "/credentials")
            assert status["rotation_allowed"], "production quiescer was not wired"
            encrypted_before = runtime.sql("SELECT in_body FROM sample_request ORDER BY id")
            assert encrypted_before and all(bytes(row[0]).startswith(b"v2:") for row in encrypted_before)
            keys_before = runtime.sql("SELECT key_id,wrapped_key FROM data_key ORDER BY purpose")
            MockUpstream.mode = "blocked"
            response = pool.submit(runtime.request, "POST", "/v1/messages", body, True, True)
            assert MockUpstream.started.wait(5), "blocked stream never reached upstream"
            rotation = pool.submit(runtime.api, "POST", "/credentials/rotate-master", {"password": runtime.admin, "new_master": "fixture-new-master-after-runtime-rotation"})
            eventually(lambda: runtime.api("GET", "/state").get("maintenance") is True)
            assert not rotation.done(), "rotation skipped the real in-flight stream"
            assert runtime.request("POST", "/v1/messages", body, proxy=True)[0] == 503, "maintenance admitted a new model request"
            runtime.api("POST", "/probe-secrets", {"name": "blocked-write", "value": "fixture"}, 409)
            assert runtime.sql("SELECT key_id,wrapped_key FROM data_key ORDER BY purpose") == keys_before, "master rewrap started before drain"
            MockUpstream.release.set()
            assert response.result(timeout=10)[1] == SEMANTIC + END
            result = rotation.result(timeout=15)
            assert result["phase"] == "cleaned", "rotation did not finish safely"
            assert runtime.sql("SELECT in_body FROM sample_request ORDER BY id") == encrypted_before, "Master rotation rewrote sample bodies"
            keys_after = runtime.sql("SELECT key_id,wrapped_key FROM data_key ORDER BY purpose")
            assert [row[0] for row in keys_after] == [row[0] for row in keys_before] and keys_after != keys_before
            assert not runtime.api("GET", "/state").get("maintenance"), "successful rotation left maintenance active"
            backups = list(runtime.root.glob("backups/*/manifest.json"))
            assert backups and all(path.with_name("secrets.json").is_file() for path in backups), "backup did not pair DB and secrets"
            digest = hashlib.sha256()
            with binary.open("rb") as executable:
                for block in iter(lambda: executable.read(1024 * 1024), b""):
                    digest.update(block)
            version = json.loads(runtime.request("GET", "/healthz", auth=False)[1])["version"]
            for path in backups:
                paired = json.loads(path.read_text(encoding="utf-8"))["paired_build_id"]
                assert paired.startswith("sha256:" + digest.hexdigest() + " "), "backup did not identify the actual reader artifact"
                assert " version=" + urllib.parse.quote_plus(version) + " " in paired, "backup lost the actual build version label"
            state = runtime.api("GET", "/state")
            runtime.api("POST", "/state", {"state": "paused", "expected_revision": state["revision"]})
            runtime.stop()
            runtime.start()
            assert runtime.api("GET", "/state")["state"] == "paused", "cold restart lost paused state"
            assert runtime.sql("SELECT in_body FROM sample_request ORDER BY id") == encrypted_before
            assert runtime.api("GET", "/upstreams/" + str(upstream["id"]))["api_key_is_set"], "cold restart lost encrypted credentials"
            assert runtime.request("POST", "/v1/messages", body, proxy=True)[0] == 503
            assert runtime.sql("SELECT COUNT(*) FROM probe_execution WHERE trigger!='real_traffic'") == [(0,)], "Lazy mode emitted synthetic probes"
            print("runtime verification passed: original SSE/gzip bytes, partial semantics, private shape learning, independent sample toggle, real drain, write fence, stable data keys, paired backup, cold restart, paused/Lazy state")
        finally:
            MockUpstream.release.set()
            runtime.stop()
            pool.shutdown(wait=True, cancel_futures=True)
            remote.shutdown()
            remote.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    args = parser.parse_args()
    verify(args.binary.resolve(strict=True))
