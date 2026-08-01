#!/usr/bin/env python3
"""M0 探测脚本的自测靶机。模拟一个中转站的各种行为，用于验证 probe-upstream.sh。

用法：
    python3 scripts/mock-upstream.py [port] [scenario]

scenario:
    normal      正常站：全端点可用，SSE 真实吐字
    fake_empty  假活：200 但 SSE 无有效 delta
    fake_error  假活：200 但 SSE 内含 error 事件
    no_resp     不支持 /v1/responses（返回 404）
    xk_only     只认 x-api-key，Bearer 返回 401
    dead        全挂：一律 503
    slow        首 Token 延迟 8 秒（测延迟测量是否准）
    bad_gateway 一律 502（M6：可重试的失败，用来验证换站）
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18999
SCENARIO = sys.argv[2] if len(sys.argv) > 2 else "normal"

KNOWN_MODELS = {"claude-opus-5", "claude-opus-4.8", "gpt-5.6-sol",
                "gpt-5.6-terra", "gpt-5.6-luna"}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        # 把收到的鉴权头也记下来。
        #
        # M6 的冒烟要验证一条不变量：**A 站的 key 绝不出现在发往 B 站的
        # 请求里**（换站重试时复用上一次的出站头就会这样）。而这件事只能
        # 从**站这一侧**观察 —— 网关自己的样本存的是脱敏后的值，看不出
        # 收到的到底是谁的 key。
        #
        # 只影响 stderr 输出，HTTP 行为一个字节都没变，所以 m2/m3 的
        # 冒烟不受影响。
        xk = self.headers.get("x-api-key") or "-"
        sys.stderr.write("  [mock] %s %s key=%s\n" % (self.command, self.path, xk))

    # ---- helpers ----
    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _sse_open(self):
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()

    def _chunk(self, s):
        b = s.encode()
        self.wfile.write(b"%x\r\n%s\r\n" % (len(b), b))
        self.wfile.flush()

    def _sse_end(self):
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _auth_ok(self):
        xk = self.headers.get("x-api-key")
        br = self.headers.get("authorization")
        if SCENARIO == "xk_only":
            return bool(xk)
        return bool(xk or br)

    def _body(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            return json.loads(raw)
        except Exception:
            return {}

    # ---- routes ----
    def do_GET(self):
        if SCENARIO == "dead":
            return self._json(503, {"error": "upstream down"})
        # bad_gateway 只让 POST（真实转发）失败，GET /v1/models 照常成功 ——
        # 那是 L1 探活的端点。两者都挂的话这个站会被判 dead 而被选路排除，
        # 于是重试根本不会撞上它，而验证换站恰恰需要它被选中一次。
        if SCENARIO == "bad_gateway" and not self.path.startswith("/v1/models"):
            return self._json(502, {"error": "bad gateway"})
        if self.path.startswith("/v1/models"):
            return self._json(200, {"object": "list", "data": [
                {"id": m, "object": "model"} for m in sorted(KNOWN_MODELS)]})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        # **必须先读走请求体**，哪怕这个场景要立刻返回错误。
        #
        # HTTP/1.1 默认 keep-alive：不读走 body 的话，它会留在连接里，
        # 被下一次请求当成请求行解析 —— Python 于是回 501 Unsupported
        # method。表现为「偶尔一个请求的状态码莫名其妙」，而真正的原因
        # 在**上一个**请求里。M6 的冒烟就是这样先记到一个假的 501 的。
        body = self._body()

        if SCENARIO == "dead":
            return self._json(503, {"error": "upstream down"})
        if SCENARIO == "bad_gateway":
            # 502 是 §3.5 明确列为可重试的一类。响应体里回显收到的 key，
            # 让冒烟能验证「日志与样本里的 key 都被脱敏了」——
            # 真实中转站的鉴权错误经常这么回显。
            return self._json(502, {"error": {
                "type": "bad_gateway",
                "message": "upstream unavailable, got key %s" % (
                    self.headers.get("x-api-key") or "-")}})
        if not self._auth_ok():
            return self._json(401, {"type": "error",
                                    "error": {"type": "authentication_error",
                                              "message": "invalid api key"}})
        model = body.get("model", "")
        p = self.path.split("?")[0]

        if p == "/v1/messages/count_tokens":
            return self._json(200, {"input_tokens": 12})

        if p == "/v1/responses":
            if SCENARIO == "no_resp":
                return self._json(404, {"error": {
                    "message": "Unknown request URL: POST /v1/responses"}})
            return self._json(200, {"id": "resp_1", "object": "response",
                                    "model": model, "output": [
                    {"type": "message", "role": "assistant", "content": [
                        {"type": "output_text", "text": "2"}]}]})

        if p == "/v1/chat/completions":
            return self._json(200, {"id": "cc_1", "object": "chat.completion",
                                    "model": model, "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": "2"},
                     "finish_reason": "stop"}]})

        if p == "/v1/messages":
            if model not in KNOWN_MODELS:
                return self._json(400, {"type": "error", "error": {
                    "type": "invalid_request_error",
                    "message": f"model: {model} not found"}})
            if not body.get("stream"):
                return self._json(200, {"id": "msg_1", "type": "message",
                                        "role": "assistant", "model": model,
                                        "content": [{"type": "text", "text": "2"}],
                                        "stop_reason": "end_turn"})
            return self._stream_messages(model)

        self._json(404, {"error": "not found"})

    def _stream_messages(self, model):
        self._sse_open()
        self._chunk('event: message_start\ndata: {"type":"message_start",'
                    '"message":{"id":"msg_1","model":"%s","content":[]}}\n\n' % model)
        self._chunk('event: ping\ndata: {"type":"ping"}\n\n')

        if SCENARIO == "fake_empty":
            self._chunk('event: message_stop\ndata: {"type":"message_stop"}\n\n')
            return self._sse_end()

        if SCENARIO == "fake_error":
            self._chunk('event: error\ndata: {"type":"error","error":'
                        '{"type":"overloaded_error","message":"upstream busy"}}\n\n')
            return self._sse_end()

        if SCENARIO == "slow":
            time.sleep(8)

        self._chunk('event: content_block_start\ndata: {"type":"content_block_start",'
                    '"index":0,"content_block":{"type":"text","text":""}}\n\n')
        self._chunk('event: content_block_delta\ndata: {"type":"content_block_delta",'
                    '"index":0,"delta":{"type":"text_delta","text":"2"}}\n\n')
        self._chunk('event: message_stop\ndata: {"type":"message_stop"}\n\n')
        self._sse_end()


if __name__ == "__main__":
    print(f"mock upstream: http://127.0.0.1:{PORT}  scenario={SCENARIO}",
          file=sys.stderr)
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
