package transform_test

import (
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
