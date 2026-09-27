package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

type priorCapturingReducer struct {
	fakeStateReducer
	prior []*model.UpstreamReachability
}

func (reducer *priorCapturingReducer) ReduceReachability(current *model.UpstreamReachability, execution model.ProbeExecution, policy model.ReachabilityReductionPolicy) (*model.UpstreamReachability, error) {
	reducer.prior = append(reducer.prior, current)
	return reducer.fakeStateReducer.ReduceReachability(current, execution, policy)
}

// 网络来源改动递增 network_revision 后，旧 revision 下的 Reachability 行
// 不得作为 reducer 的起点：旧 unreachable 的连续失败或旧 reachable 状态
// 会被新 revision 的第一次观察直接继承。
func TestCommitReachabilityStartsFreshAfterNetworkRevisionBump(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "reach-netrev")
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(model.DefaultSettings(), selector)
	if err != nil {
		t.Fatal(err)
	}
	reducer := &priorCapturingReducer{}
	var order int64
	commit := func() *model.UpstreamReachability {
		t.Helper()
		order++
		revision := model.ReachabilityRevision{
			NetworkRevision:     upstream.NetworkRevision,
			CreatedAt:           upstream.CreatedAt,
			SettingsFingerprint: revisioncodec.ReachabilitySettingsFingerprint(policy),
		}
		expectation := &model.ReachabilityExpectation{
			UpstreamID: upstream.ID, PolicySelector: selector, Revision: revision,
			ObservationToken: revisioncodec.NewReachabilityToken(revision),
		}
		id := fmt.Sprintf("netrev-%d", order)
		execution := minimalReachabilityExecution(t, store, upstream, expectation, id, id+"-evidence", order)
		result, err := store.CommitProbeObservation(context.Background(), &model.ProbeObservation{
			Execution: execution, ReachabilityExpectation: expectation, ReachabilityPolicy: &policy.State,
		}, reducer)
		if err != nil {
			t.Fatal(err)
		}
		if result.Reachability != model.ApplyCurrent {
			t.Fatalf("commit %d result = %+v", order, result)
		}
		return reducer.prior[len(reducer.prior)-1]
	}
	update := func(edit func(*model.Upstream)) {
		t.Helper()
		edit(upstream)
		upstream.APIKey = ""
		if err := store.UpdateUpstreamWithRevision(context.Background(), upstream, upstream.Revision); err != nil {
			t.Fatal(err)
		}
	}

	if prior := commit(); prior != nil {
		t.Fatalf("first commit prior = %+v", prior)
	}

	network := []struct {
		name string
		edit func(*model.Upstream)
	}{
		{"base_url", func(u *model.Upstream) { u.BaseURL = "https://reach-netrev-moved.example.com" }},
		{"proxy_url", func(u *model.Upstream) { u.ProxyURL = "http://proxy.example.com:8080" }},
		{"host_override", func(u *model.Upstream) { u.HostOverride = "api.reach-netrev.example.com" }},
		{"tls_server_name", func(u *model.Upstream) { u.TLSServerName = "tls.reach-netrev.example.com" }},
	}
	for _, change := range network {
		before := upstream.NetworkRevision
		update(change.edit)
		if upstream.NetworkRevision != before+1 {
			t.Fatalf("%s edit network_revision %d -> %d", change.name, before, upstream.NetworkRevision)
		}
		if prior := commit(); prior != nil {
			t.Fatalf("%s edit: reducer inherited row from network_revision %d (now %d): %+v",
				change.name, prior.ObservedNetworkRevision, upstream.NetworkRevision, prior)
		}
		prior := commit()
		if prior == nil || prior.ObservedNetworkRevision != upstream.NetworkRevision {
			t.Fatalf("%s edit: same-revision commit prior = %+v", change.name, prior)
		}
	}

	before := upstream.NetworkRevision
	update(func(u *model.Upstream) { u.Name = "reach-netrev-display" })
	if upstream.NetworkRevision != before {
		t.Fatalf("display-name edit bumped network_revision %d -> %d", before, upstream.NetworkRevision)
	}
	if prior := commit(); prior == nil || prior.ObservedNetworkRevision != upstream.NetworkRevision {
		t.Fatalf("display-name edit dropped current row: prior = %+v", prior)
	}
}
