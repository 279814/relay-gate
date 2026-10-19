package security

import (
	"net/http"
	"strings"
	"sync"
)

// Capture owns one admitted original-upstream copy. It never parses payloads,
// decompresses, writes evidence or waits for a worker on the forwarding path.
type Capture struct {
	mu        sync.Mutex
	observer  *Observer
	job       ObserveJob
	body      []byte
	total     int64
	tailPos   int
	completed bool
}

// Wrap reserves bounded capture admission before retaining any response bytes.
// The proxy owns the separate optional AttemptObserver interface adapter.
func (o *Observer) Wrap(job ObserveJob) *Capture {
	c := &Capture{}
	if !o.reserve() {
		return c
	}
	c.observer = o
	job.Body = nil
	job.input = ScanInput{Spec: job.Spec, Source: "traffic"}
	for i, key := range job.Keys {
		if i >= 64 || len(key) > 4096 {
			job.input.IncompleteReason = "credential_context_limit"
			break
		}
		job.input.Keys = append(job.input.Keys, key)
	}
	job.Keys = nil
	c.job = job
	return c
}

func (c *Capture) TryHeaders(header http.Header) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.observer == nil || c.completed {
		return
	}
	for _, field := range []struct {
		name   string
		target *string
	}{
		{"Content-Type", &c.job.input.ContentType},
		{"Content-Encoding", &c.job.input.Encoding},
	} {
		value := header.Get(field.name)
		if len(value) > 1024 {
			value = value[:1024]
			c.job.input.IncompleteReason = "header_context_limit"
		}
		*field.target = value
	}
}

func (c *Capture) TryRequest(body []byte, truncated bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.observer == nil || c.completed {
		return
	}
	if len(body) > MaxEventBytes {
		body = body[:MaxEventBytes]
		truncated = true
	}
	c.job.request = append(c.job.request[:0], body...)
	c.job.requestTruncated = truncated
}

// TryChunk copies a prefix plus a rolling tail without inventing gap markers.
func (c *Capture) TryChunk(body []byte) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.observer == nil || c.completed {
		return
	}
	c.total += int64(len(body))
	if len(c.body) < MaxScanBytes {
		n := min(MaxScanBytes-len(c.body), len(body))
		c.body = append(c.body, body[:n]...)
		body = body[n:]
	}
	if len(body) == 0 {
		return
	}
	tail := c.body[MaxScanBytes/2:]
	if len(body) > len(tail) {
		body = body[len(body)-len(tail):]
	}
	n := copy(tail[c.tailPos:], body)
	copy(tail, body[n:])
	c.tailPos = (c.tailPos + len(body)) % len(tail)
}

// Interrupted records only a fixed reason, never transport error text. A
// partially delivered response cannot support a complete scan conclusion.
func (c *Capture) Interrupted() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.observer != nil && !c.completed {
		c.job.input.IncompleteReason = appendIncomplete(c.job.input.IncompleteReason, "capture_interrupted")
	}
}

// Complete is idempotent. Only bytes actually committed to the client qualify;
// retry/discard/fallback paths pass false and immediately release admission.
func (c *Capture) Complete(committed bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.completed || c.observer == nil {
		c.mu.Unlock()
		return
	}
	c.completed = true
	o, job := c.observer, c.job
	c.observer, c.job = nil, ObserveJob{}
	if committed {
		job.input.TotalBytes = c.total
		if c.total <= MaxScanBytes {
			job.input.Segments = []Segment{{Body: c.body}}
		} else {
			tail := c.body[MaxScanBytes/2:]
			ordered := append(make([]byte, 0, len(tail)), tail[c.tailPos:]...)
			ordered = append(ordered, tail[:c.tailPos]...)
			job.input.Segments = []Segment{{Body: c.body[:MaxScanBytes/2]}, {Offset: c.total - int64(len(ordered)), Body: ordered}}
		}
	}
	c.body = nil
	c.mu.Unlock()
	if committed {
		o.enqueueOwned(job)
	} else {
		o.release()
	}
}

func appendIncomplete(existing, reason string) string {
	if existing == "" {
		return reason
	}
	if strings.Contains(","+existing+",", ","+reason+",") {
		return existing
	}
	return existing + "," + reason
}
