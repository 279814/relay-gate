package transform

import (
	"bytes"
	"strings"
)

// SSEScanner accumulates upstream bytes and emits complete SSE events
// (terminated by a blank line). Trailing bytes without a blank line are
// available via Flush at EOF (§15: no half-event output).
type SSEScanner struct {
	buf []byte
}

// Feed appends p and returns every complete event found.
func (s *SSEScanner) Feed(p []byte) ([]SSEEvent, error) {
	if len(p) > 0 {
		s.buf = append(s.buf, p...)
	}
	var out []SSEEvent
	for {
		sep, n := findSSEBoundary(s.buf)
		if sep < 0 {
			if len(s.buf) > MaxSSEEventBytes {
				return out, errSSETooLarge()
			}
			break
		}
		raw := append([]byte(nil), s.buf[:sep+n]...)
		s.buf = s.buf[sep+n:]
		out = append(out, ParseSSEEvent(raw))
	}
	return out, nil
}

// Flush returns a final unterminated event, if any.
func (s *SSEScanner) Flush() (SSEEvent, bool) {
	if len(bytes.TrimSpace(s.buf)) == 0 {
		s.buf = nil
		return SSEEvent{}, false
	}
	raw := append([]byte(nil), s.buf...)
	s.buf = nil
	return ParseSSEEvent(raw), true
}

func findSSEBoundary(b []byte) (idx, sepLen int) {
	// Prefer CRLF blank line, then LF.
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		return i, 4
	}
	if i := bytes.Index(b, []byte("\n\n")); i >= 0 {
		return i, 2
	}
	return -1, 0
}

func errSSETooLarge() error {
	return &sseLimitError{}
}

type sseLimitError struct{}

func (e *sseLimitError) Error() string {
	return "sse event exceeds buffer while framing"
}

// ParseSSEEvent decodes one framed SSE block into event/data fields.
func ParseSSEEvent(raw []byte) SSEEvent {
	ev := SSEEvent{Raw: append([]byte(nil), raw...)}
	var dataLines []string
	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 || line[0] == ':' {
			continue
		}
		if bytes.HasPrefix(line, []byte("event:")) {
			ev.Event = strings.TrimSpace(string(line[len("event:"):]))
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			dataLines = append(dataLines, string(line[len("data:"):]))
			// SSE allows optional single leading space after "data:".
			if len(dataLines[len(dataLines)-1]) > 0 && dataLines[len(dataLines)-1][0] == ' ' {
				dataLines[len(dataLines)-1] = dataLines[len(dataLines)-1][1:]
			}
			continue
		}
	}
	ev.Data = strings.Join(dataLines, "\n")
	return ev
}

// IsSSEContentType reports text/event-stream responses.
func IsSSEContentType(ct string) bool {
	return strings.Contains(strings.ToLower(ct), "text/event-stream")
}
