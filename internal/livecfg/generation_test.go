package livecfg

import "testing"

func TestPublishedRoutingAndProbeShareGeneration(t *testing.T) {
	st := testStore(t)
	seed(t, st)
	s, _ := newSource(t, st)
	pub, err := s.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	if pub.Routing.Generation != pub.Probe.Generation {
		t.Fatal("routing configuration cannot prove its shared observation generation")
	}
}
