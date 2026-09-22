package transform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RequestInput is the outbound request after Endpoint URL/auth/model mapping.
type RequestInput struct {
	Header http.Header
	Body   []byte
}

// RequestResult is the post-transform request (or original on fail_open).
type RequestResult struct {
	Header     http.Header
	Body       []byte
	HitRules   []string
	Changed    bool
	Synthetic  bool
	Err        error
	PolicyUsed string
	Taint      *TaintBag // rendered secrets; redact diagnostics with Taint.Redact
}

// ResponseInput is a non-streaming upstream response before Commit.
type ResponseInput struct {
	Status int
	Header http.Header
	Body   []byte
}

// ResponseResult is the post-transform response.
type ResponseResult struct {
	Status     int
	Header     http.Header
	Body       []byte
	HitRules   []string
	Changed    bool
	Synthetic  bool
	Err        error
	PolicyUsed string
	Taint      *TaintBag
}

// SSEEvent is one complete SSE event (name + data lines joined).
type SSEEvent struct {
	Event string
	Data  string
	Raw   []byte // original framing bytes if available
}

// ApplyRequest runs compiled request rules. Protected headers present before
// apply are restored afterward (auth/model protection layer §15.3).
func (c *Compiled) ApplyRequest(in RequestInput) RequestResult {
	return c.ApplyRequestSecrets(in, nil)
}

// ApplyRequestSecrets is ApplyRequest with optional secret resolution for
// secret_ref / {{SECRET:name}} rules. Rendered secrets are tainted.
func (c *Compiled) ApplyRequestSecrets(in RequestInput, secrets SecretMap) RequestResult {
	policy := c.Version.ReqFailPolicy
	if policy == "" {
		policy = FailClosed
	}
	sec := &applySecrets{lookup: secrets}
	out := RequestResult{
		Header:     cloneHeader(in.Header),
		Body:       append([]byte(nil), in.Body...),
		PolicyUsed: policy,
		Taint:      &sec.taint,
	}
	savedAuth := snapshotProtected(out.Header)
	budget := c.reqBudget
	if budget == 0 {
		budget = time.Duration(DefaultRequestBudgetMs) * time.Millisecond
	}
	deadline := time.Now().Add(budget)

	for i, rule := range c.Version.Rules {
		if err := checkBudget(deadline); err != nil {
			out.Err = err
			out.Header = cloneHeader(in.Header)
			out.Body = append([]byte(nil), in.Body...)
			out.Changed = false
			out.HitRules = nil
			restoreProtected(out.Header, savedAuth)
			return out
		}
		switch rule.Kind {
		case KindSetHeader, KindDeleteHeader, KindRenameHeader, KindReplaceBytes, KindSetJSONPointer,
			KindJSONPatchAdd, KindJSONPatchRemove, KindJSONPatchCopy, KindBodyTemplate:
			if err := c.applyOneRequest(i, rule, &out, sec); err != nil {
				out.Err = sec.taint.RedactErr(err)
				out.Header = cloneHeader(in.Header)
				out.Body = append([]byte(nil), in.Body...)
				out.Changed = false
				out.HitRules = nil
				restoreProtected(out.Header, savedAuth)
				return out
			}
		default:
			// response / SSE rules skipped on request path
		}
	}
	restoreProtected(out.Header, savedAuth)
	out.Changed = HeaderFingerprint(out.Header) != HeaderFingerprint(in.Header) ||
		!bytes.Equal(out.Body, in.Body)
	return out
}

func (c *Compiled) applyOneRequest(i int, rule Rule, out *RequestResult, sec *applySecrets) error {
	name := "r" + strconv.Itoa(i) + ":" + rule.Kind
	switch rule.Kind {
	case KindSetHeader:
		val, err := sec.resolveRuleValue(rule)
		if err != nil {
			return err
		}
		if err := rejectCRLFinHeaderValue(val); err != nil {
			return err
		}
		out.Header.Set(rule.Name, val)
		out.HitRules = append(out.HitRules, name)
	case KindDeleteHeader:
		out.Header.Del(rule.Name)
		out.HitRules = append(out.HitRules, name)
	case KindRenameHeader:
		vals := out.Header.Values(rule.From)
		if len(vals) == 0 {
			return nil
		}
		out.Header.Del(rule.From)
		for _, v := range vals {
			out.Header.Add(rule.To, v)
		}
		out.HitRules = append(out.HitRules, name)
	case KindReplaceBytes:
		if !bytes.Contains(out.Body, []byte(rule.From)) {
			return nil
		}
		n := bytes.Count(out.Body, []byte(rule.From))
		repl := []byte(rule.To)
		added := n * (len(repl) - len(rule.From))
		if added > MaxAddedBytes {
			return fmt.Errorf("replace_bytes would add %d bytes", added)
		}
		out.Body = bytes.ReplaceAll(out.Body, []byte(rule.From), repl)
		out.HitRules = append(out.HitRules, name)
	case KindSetJSONPointer:
		val, err := sec.resolveRuleValue(rule)
		if err != nil {
			return err
		}
		next, err := setJSONPointerOffset(out.Body, rule.Name, val)
		if err != nil {
			return err
		}
		if int64(len(next))-int64(len(out.Body)) > MaxAddedBytes {
			return fmt.Errorf("json pointer rewrite exceeds added-byte budget")
		}
		out.Body = next
		out.HitRules = append(out.HitRules, name)
	case KindJSONPatchAdd, KindJSONPatchRemove, KindJSONPatchCopy:
		patched := rule
		if rule.Kind == KindJSONPatchAdd {
			val, err := sec.resolveRuleValue(rule)
			if err != nil {
				return err
			}
			patched.Value = val
			patched.SecretRef = ""
		}
		next, err := applyJSONPatch(out.Body, patched)
		if err != nil {
			return err
		}
		out.Body = next
		out.HitRules = append(out.HitRules, name)
	case KindBodyTemplate:
		val, err := sec.resolveRuleValue(rule)
		if err != nil {
			return err
		}
		next, err := applyBodyTemplate(out.Body, []byte(val))
		if err != nil {
			return err
		}
		out.Body = next
		out.HitRules = append(out.HitRules, name)
	}
	return nil
}

// ApplyResponse runs non-streaming response rules before Commit.
func (c *Compiled) ApplyResponse(in ResponseInput) ResponseResult {
	return c.ApplyResponseSecrets(in, nil)
}

// ApplyResponseSecrets is ApplyResponse with optional secret resolution.
func (c *Compiled) ApplyResponseSecrets(in ResponseInput, secrets SecretMap) ResponseResult {
	policy := c.Version.ResFailPolicy
	if policy == "" {
		policy = FailOpen
	}
	sec := &applySecrets{lookup: secrets}
	out := ResponseResult{
		Status:     in.Status,
		Header:     cloneHeader(in.Header),
		Body:       append([]byte(nil), in.Body...),
		PolicyUsed: policy,
		Taint:      &sec.taint,
	}
	if len(out.Body) > MaxBodyBuffer {
		out.Err = fmt.Errorf("response body exceeds %d byte buffer", MaxBodyBuffer)
		if policy == FailOpen {
			out.Status, out.Header, out.Body = in.Status, cloneHeader(in.Header), append([]byte(nil), in.Body...)
			out.Changed = false
		}
		return out
	}
	saved := snapshotProtected(out.Header)
	budget := c.reqBudget
	if budget == 0 {
		budget = time.Duration(DefaultRequestBudgetMs) * time.Millisecond
	}
	deadline := time.Now().Add(budget)
	for i, rule := range c.Version.Rules {
		if err := checkBudget(deadline); err != nil {
			out.Err = err
			out.Status, out.Header, out.Body = in.Status, cloneHeader(in.Header), append([]byte(nil), in.Body...)
			out.Changed = false
			out.HitRules = nil
			restoreProtected(out.Header, saved)
			return out
		}
		switch rule.Kind {
		case KindSetHeader, KindDeleteHeader, KindRenameHeader, KindReplaceBytes, KindSetJSONPointer,
			KindJSONPatchAdd, KindJSONPatchRemove, KindJSONPatchCopy, KindBodyTemplate, KindSetStatus:
			if err := c.applyOneResponse(i, rule, &out, sec); err != nil {
				out.Err = sec.taint.RedactErr(err)
				out.Status, out.Header, out.Body = in.Status, cloneHeader(in.Header), append([]byte(nil), in.Body...)
				out.Changed = false
				out.HitRules = nil
				restoreProtected(out.Header, saved)
				return out
			}
		}
	}
	restoreProtected(out.Header, saved)
	out.Changed = out.Status != in.Status ||
		HeaderFingerprint(out.Header) != HeaderFingerprint(in.Header) ||
		!bytes.Equal(out.Body, in.Body)
	return out
}

func (c *Compiled) applyOneResponse(i int, rule Rule, out *ResponseResult, sec *applySecrets) error {
	name := "r" + strconv.Itoa(i) + ":" + rule.Kind
	switch rule.Kind {
	case KindSetHeader:
		val, err := sec.resolveRuleValue(rule)
		if err != nil {
			return err
		}
		if err := rejectCRLFinHeaderValue(val); err != nil {
			return err
		}
		out.Header.Set(rule.Name, val)
		out.HitRules = append(out.HitRules, name)
	case KindDeleteHeader:
		out.Header.Del(rule.Name)
		out.HitRules = append(out.HitRules, name)
	case KindRenameHeader:
		vals := out.Header.Values(rule.From)
		if len(vals) == 0 {
			return nil
		}
		out.Header.Del(rule.From)
		for _, v := range vals {
			out.Header.Add(rule.To, v)
		}
		out.HitRules = append(out.HitRules, name)
	case KindReplaceBytes:
		if !bytes.Contains(out.Body, []byte(rule.From)) {
			return nil
		}
		out.Body = bytes.ReplaceAll(out.Body, []byte(rule.From), []byte(rule.To))
		out.HitRules = append(out.HitRules, name)
	case KindSetJSONPointer:
		val, err := sec.resolveRuleValue(rule)
		if err != nil {
			return err
		}
		next, err := setJSONPointerOffset(out.Body, rule.Name, val)
		if err != nil {
			return err
		}
		out.Body = next
		out.HitRules = append(out.HitRules, name)
	case KindJSONPatchAdd, KindJSONPatchRemove, KindJSONPatchCopy:
		patched := rule
		if rule.Kind == KindJSONPatchAdd {
			val, err := sec.resolveRuleValue(rule)
			if err != nil {
				return err
			}
			patched.Value = val
			patched.SecretRef = ""
		}
		next, err := applyJSONPatch(out.Body, patched)
		if err != nil {
			return err
		}
		out.Body = next
		out.HitRules = append(out.HitRules, name)
	case KindBodyTemplate:
		val, err := sec.resolveRuleValue(rule)
		if err != nil {
			return err
		}
		next, err := applyBodyTemplate(out.Body, []byte(val))
		if err != nil {
			return err
		}
		out.Body = next
		out.HitRules = append(out.HitRules, name)
	case KindSetStatus:
		code, err := strconv.Atoi(strings.TrimSpace(rule.Value))
		if err != nil || code < 100 || code > 599 {
			return fmt.Errorf("invalid status %q", rule.Value)
		}
		out.Status = code
		out.HitRules = append(out.HitRules, name)
	}
	return nil
}

// ApplySSEEvent transforms one complete SSE event atomically.
func (c *Compiled) ApplySSEEvent(ev SSEEvent) (SSEEvent, []string, bool, error) {
	out := ev
	var hits []string
	synthetic := false
	budget := c.sseBudget
	if budget == 0 {
		budget = time.Duration(DefaultSSEBudgetMs) * time.Millisecond
	}
	deadline := time.Now().Add(budget)
	for i, rule := range c.Version.Rules {
		if err := checkBudget(deadline); err != nil {
			return ev, hits, false, err
		}
		switch rule.Kind {
		case KindSSEMatch:
			if rule.Match != "" && ev.Event != rule.Match && rule.Match != "*" {
				continue
			}
			if rule.From != "" && !strings.Contains(out.Data, rule.From) {
				continue
			}
			if rule.To != "" || rule.From != "" {
				out.Data = strings.ReplaceAll(out.Data, rule.From, rule.To)
			}
			if rule.Value != "" {
				out.Data = rule.Value
			}
			hits = append(hits, "r"+strconv.Itoa(i)+":sse_match")
			if rule.Synthetic {
				synthetic = true
			}
		case KindSSEAppendEnd:
			// handled by AppendSyntheticEnd, not per-event
		}
	}
	if len(out.Data) > MaxSSEEventBytes {
		return ev, hits, false, fmt.Errorf("sse event exceeds %d bytes", MaxSSEEventBytes)
	}
	out.Raw = encodeSSE(out.Event, out.Data)
	return out, hits, synthetic, nil
}

// AppendSyntheticEnd returns an optional terminal event when configured.
func (c *Compiled) AppendSyntheticEnd() (SSEEvent, bool) {
	for i, rule := range c.Version.Rules {
		if rule.Kind != KindSSEAppendEnd {
			continue
		}
		data := rule.Value
		if data == "" {
			data = `{"type":"message_stop"}`
		}
		ev := SSEEvent{Event: rule.Match, Data: data}
		if rule.Match == "" {
			ev.Event = "message_stop"
		}
		ev.Raw = encodeSSE(ev.Event, ev.Data)
		_ = i
		return ev, true
	}
	return SSEEvent{}, false
}

// ShadowDiff applies on a copy and returns a redacted summary without mutating live.
func (c *Compiled) ShadowDiff(phase string, req RequestInput, res ResponseInput) string {
	return c.ShadowDiffSecrets(phase, req, res, nil)
}

// ShadowDiffSecrets is ShadowDiff with secret resolution; summaries never include plaintext.
func (c *Compiled) ShadowDiffSecrets(phase string, req RequestInput, res ResponseInput, secrets SecretMap) string {
	switch phase {
	case "request":
		r := c.ApplyRequestSecrets(req, secrets)
		errMsg := ""
		if r.Err != nil {
			errMsg = r.Err.Error()
		}
		if r.Taint != nil {
			errMsg = r.Taint.Redact(errMsg)
		}
		return fmt.Sprintf("request changed=%v hits=%v in=%s out=%s err=%v",
			r.Changed, r.HitRules, HashBytes(req.Body), HashBytes(r.Body), errMsg)
	case "response":
		r := c.ApplyResponseSecrets(res, secrets)
		errMsg := ""
		if r.Err != nil {
			errMsg = r.Err.Error()
		}
		if r.Taint != nil {
			errMsg = r.Taint.Redact(errMsg)
		}
		return fmt.Sprintf("response changed=%v hits=%v status %d→%d in=%s out=%s err=%v",
			r.Changed, r.HitRules, res.Status, r.Status, HashBytes(res.Body), HashBytes(r.Body), errMsg)
	default:
		return "unknown phase"
	}
}

func encodeSSE(event, data string) []byte {
	var b strings.Builder
	if event != "" {
		b.WriteString("event: ")
		b.WriteString(event)
		b.WriteByte('\n')
	}
	for _, line := range strings.Split(data, "\n") {
		b.WriteString("data: ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	return []byte(b.String())
}

func cloneHeader(h http.Header) http.Header {
	if h == nil {
		return make(http.Header)
	}
	out := make(http.Header, len(h))
	for k, vs := range h {
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}

func snapshotProtected(h http.Header) map[string][]string {
	out := make(map[string][]string)
	for name := range protectedHeaders {
		if vs := h.Values(name); len(vs) > 0 {
			cp := make([]string, len(vs))
			copy(cp, vs)
			out[name] = cp
		}
	}
	return out
}

func restoreProtected(h http.Header, saved map[string][]string) {
	for name := range protectedHeaders {
		h.Del(name)
	}
	for name, vs := range saved {
		for _, v := range vs {
			h.Add(name, v)
		}
	}
}

// setJSONPointerOffset replaces an existing string/number/bool/null value at a
// simple top-level or nested pointer using offset splice when the value is a
// JSON string; otherwise falls back to unmarshal/remarshal for that object.
func setJSONPointerOffset(body []byte, pointer, newVal string) ([]byte, error) {
	if !json.Valid(body) {
		return nil, fmt.Errorf("body is not JSON")
	}
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return nil, fmt.Errorf("empty json pointer")
	}
	// Prefer offset replace for top-level string fields (same spirit as ReplaceModel).
	if len(parts) == 1 {
		key := unescapePointer(parts[0])
		start, end, typ, err := locateTopLevelValue(body, key)
		if err != nil {
			return nil, err
		}
		var quoted []byte
		switch typ {
		case jsonString:
			var err error
			quoted, err = json.Marshal(newVal)
			if err != nil {
				return nil, err
			}
		case jsonOther:
			if !json.Valid([]byte(newVal)) {
				// treat as JSON string
				var err error
				quoted, err = json.Marshal(newVal)
				if err != nil {
					return nil, err
				}
			} else {
				quoted = []byte(newVal)
			}
		}
		out := make([]byte, 0, len(body)-(end-start)+len(quoted))
		out = append(out, body[:start]...)
		out = append(out, quoted...)
		out = append(out, body[end:]...)
		return out, nil
	}
	// Nested: limited remarshal path with explicit warning semantics for callers.
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, err
	}
	if err := setNested(root, parts, newVal); err != nil {
		return nil, err
	}
	return json.Marshal(root)
}

type valueType int

const (
	jsonString valueType = iota
	jsonOther
)

func locateTopLevelValue(body []byte, key string) (start, end int, typ valueType, err error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return 0, 0, 0, err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return 0, 0, 0, fmt.Errorf("top-level JSON must be object")
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return 0, 0, 0, err
		}
		k, ok := kt.(string)
		if !ok {
			return 0, 0, 0, fmt.Errorf("JSON object key not string")
		}
		if k != key {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return 0, 0, 0, err
			}
			continue
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return 0, 0, 0, err
		}
		end = int(dec.InputOffset())
		start = end - len(raw)
		if start < 0 || end > len(body) {
			return 0, 0, 0, fmt.Errorf("invalid value span")
		}
		raw = bytes.TrimSpace(raw)
		if len(raw) > 0 && raw[0] == '"' {
			return start, end, jsonString, nil
		}
		return start, end, jsonOther, nil
	}
	return 0, 0, 0, fmt.Errorf("json pointer key %q not found", key)
}

func setNested(root any, parts []string, newVal string) error {
	cur := root
	for i, p := range parts {
		key := unescapePointer(p)
		m, ok := cur.(map[string]any)
		if !ok {
			return fmt.Errorf("path not an object at %q", key)
		}
		if i == len(parts)-1 {
			var v any
			if json.Valid([]byte(newVal)) {
				_ = json.Unmarshal([]byte(newVal), &v)
			} else {
				v = newVal
			}
			m[key] = v
			return nil
		}
		next, ok := m[key]
		if !ok {
			return fmt.Errorf("missing %q", key)
		}
		cur = next
	}
	return fmt.Errorf("empty path")
}

func unescapePointer(s string) string {
	s = strings.ReplaceAll(s, "~1", "/")
	s = strings.ReplaceAll(s, "~0", "~")
	return s
}
