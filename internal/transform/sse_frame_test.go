package transform_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/transform"
)

func TestSSEScanner_FramesEvents(t *testing.T) {
	var s transform.SSEScanner
	evs, err := s.Feed([]byte("event: a\ndata: 1\n\nevent: b\ndata: 2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Event != "a" || evs[0].Data != "1" {
		t.Fatalf("first=%+v", evs)
	}
	evs, err = s.Feed([]byte("\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Event != "b" || evs[0].Data != "2" {
		t.Fatalf("second=%+v", evs)
	}
	if ev, ok := s.Flush(); ok {
		t.Fatalf("unexpected flush %+v", ev)
	}
}

// A stream with no event boundary must not grow the scanner past the
// documented event limit, even if the caller keeps feeding after the error.
func TestSSEScanner_UnboundedEventDoesNotGrowBuffer(t *testing.T) {
	const chunk = 32 * 1024
	const total = 6 << 20
	body := bytes.Repeat([]byte("data: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"), total/64)

	var s transform.SSEScanner
	var got []byte
	sawLimit := false
	for off := 0; off < len(body); off += chunk {
		end := off + chunk
		if end > len(body) {
			end = len(body)
		}
		evs, err := s.Feed(body[off:end])
		for _, ev := range evs {
			got = append(got, ev.Raw...)
		}
		var limitErr *transform.SSELimitError
		if errors.As(err, &limitErr) {
			sawLimit = true
			got = append(got, limitErr.Pending...)
		} else if err != nil {
			t.Fatal(err)
		}
		if n := s.Buffered(); n > transform.MaxSSEEventBytes+4 {
			t.Fatalf("scanner holds %d bytes after %d fed, cap %d", n, end, transform.MaxSSEEventBytes+4)
		}
	}
	if !sawLimit {
		t.Fatal("expected SSELimitError for event over MaxSSEEventBytes")
	}
	if s.Buffered() != 0 {
		t.Fatalf("scanner still holds %d bytes after overflow", s.Buffered())
	}
	if _, ok := s.Flush(); ok {
		t.Fatal("flush after overflow must be empty")
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("events+pending lost bytes: got %d want %d", len(got), len(body))
	}
}

// Events under the limit still frame when a single Feed carries more than the
// scanner hold size.
func TestSSEScanner_LargeFeedUnderLimitFrames(t *testing.T) {
	payload := bytes.Repeat([]byte("y"), transform.MaxSSEEventBytes-16)
	one := append(append([]byte("data: "), payload...), '\n', '\n')
	body := bytes.Repeat(one, 3)

	var s transform.SSEScanner
	evs, err := s.Feed(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 3 {
		t.Fatalf("events=%d want 3", len(evs))
	}
	for i, ev := range evs {
		if ev.Data != string(payload) {
			t.Fatalf("event %d data len=%d", i, len(ev.Data))
		}
	}
	if s.Buffered() != 0 {
		t.Fatalf("buffered=%d", s.Buffered())
	}
}
