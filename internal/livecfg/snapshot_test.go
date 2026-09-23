package livecfg

import (
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestProbeSnapshot_NoSecretPlaintextAndExpectations(t *testing.T) {
	st := testStore(t)
	_, upID, _ := seed(t, st)
	s, _ := newSource(t, st)
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	snap, err := s.ProbeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	up := snap.Upstreams[upID]
	if up == nil {
		t.Fatal("missing upstream in probe snapshot")
	}
	// ProbeUpstreamConfig 没有 APIKey 字段；路由快照才有。
	routing, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if routing.Upstreams[upID].APIKey == "" {
		t.Fatal("routing snapshot still needs decrypted key")
	}
	if strings.Contains(routing.Upstreams[upID].APIKey, "enc:") {
		t.Fatal("routing key should be plaintext for outbound, not ciphertext marker")
	}

	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	reach, err := snap.ReachabilityExpectation(upID, selector)
	if err != nil {
		t.Fatal(err)
	}
	if reach.ObservationToken == "" || reach.Revision.NetworkRevision != up.NetworkRevision ||
		reach.Revision.CreatedAt != up.CreatedAt {
		t.Fatalf("reachability expectation=%+v upstream created_at=%d", reach, up.CreatedAt)
	}

	s.Invalidate()
	if _, err := s.ProbeSnapshot(); err == nil {
		t.Fatal("invalidate must make probe snapshot unavailable")
	}
	if _, err := s.Snapshot(); err != nil {
		t.Fatalf("routing must remain readable after invalidate: %v", err)
	}
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProbeSnapshot(); err != nil {
		t.Fatalf("refresh must restore probe snapshot: %v", err)
	}
}
