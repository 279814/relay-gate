package probe

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/revisioncodec"
	"github.com/279814/relay-gate/internal/store"
)

// §8.6 / §8.9：出网前的 config_error（写错的 base URL、空 key）没有网络证据，
// 带着 Reachability 期望也不得推进站级失败计数；真实建连失败仍要计入阈值。
func TestExecutor_PreSendConfigErrorLeavesReachabilityUnchanged(t *testing.T) {
	cipher, err := store.NewCipher("test-encryption-key-32-bytes-long")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "reach.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	settings := model.DefaultSettings()
	settings.OKThreshold = 1
	settings.FailThreshold = 1
	if err := st.SaveSettings(settings); err != nil {
		t.Fatal(err)
	}
	up := &model.Upstream{
		Name: "reach", BaseURL: "https://reach.example", APIKey: "sk-reach-key-123456",
		AuthStyle: model.AuthXAPIKey, L1Path: "/v1/models", Enabled: true,
	}
	if err := st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}

	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	revision := model.ReachabilityRevision{
		NetworkRevision: up.NetworkRevision, CreatedAt: up.CreatedAt,
		SettingsFingerprint: revisioncodec.ReachabilitySettingsFingerprint(policy),
	}
	expectation := &model.ReachabilityExpectation{
		UpstreamID: up.ID, PolicySelector: selector, Revision: revision,
		ObservationToken: revisioncodec.NewReachabilityToken(revision),
	}

	reach := health.NewReachabilityTracker(capSettings{settings})
	recorder := NewResultRecorder(st, health.NewObservationReducer(nil), reach, NewCapabilityRegistry(capSettings{settings}))

	var order int64
	runWith := func(exec *Executor, target *model.Upstream) ExecutionResult {
		t.Helper()
		order++
		res, err := exec.Execute(context.Background(), ExecutionRequest{
			ExecutionID: fmt.Sprintf("reach-%d", order), Trigger: model.TriggerScheduled,
			Upstream: target, Endpoint: model.EndpointModels, Mode: ObserveProbe,
			Budget: outbound.L1Budget(fastSettings()), ObservationOrder: order,
			ReachabilityExpectation: expectation, ReachabilityPolicy: &policy.State,
		})
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if !res.Apply.ExecutionStored {
			t.Fatalf("execution 必须落库: %+v", res.Apply)
		}
		return res
	}
	run := func(target *model.Upstream, rt http.RoundTripper) ExecutionResult {
		t.Helper()
		return runWith(newTestExecutorFor(target, rt, recorder, AlwaysOpenAdmission(), WallClock()), target)
	}
	storedRow := func() *model.UpstreamReachability {
		t.Helper()
		page, err := st.ListReachability(context.Background(), model.ReachabilityFilter{
			PageRequest: model.PageRequest{Limit: 20},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range page.Items {
			if row.UpstreamID == up.ID {
				return row
			}
		}
		return nil
	}

	ok := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		return respFrom(404, "", ""), nil
	}}
	if res := run(up, ok); res.Apply.Reachability != model.ApplyCurrent {
		t.Fatalf("HTTP 响应应提交 reachability: %+v", res.Apply)
	}
	before := storedRow()
	if before == nil || before.State != model.ReachabilityReachable {
		t.Fatalf("404 仍是 reachable: %+v", before)
	}

	badURL := *up
	badURL.BaseURL = "://not-a-url"
	emptyKey := *up
	emptyKey.APIKey = ""
	neverSend := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		t.Error("config_error 不该出网")
		return nil, errors.New("unreachable")
	}}
	// 存量脏行的 proxy_url 在装池时被拒：走真实 Manager，而不是注入的 RoundTripper。
	badProxy := *up
	badProxy.ProxyURL = "http://proxyuser:proxysecret@"
	manager := outbound.NewManager()
	t.Cleanup(manager.CloseIdleConnections)
	badProxyExec := NewExecutor(
		outbound.NewProvider(testEndpoints{upstream: &badProxy}, nil, outbound.NewResolver(testHasher{})),
		nil, nil, ManagerTransports{Manager: manager}, recorder, AlwaysOpenAdmission(), WallClock(), nil)
	for name, target := range map[string]*model.Upstream{
		"bad_base_url": &badURL, "empty_key": &emptyKey, "bad_proxy_url": &badProxy,
	} {
		var res ExecutionResult
		if target == &badProxy {
			res = runWith(badProxyExec, target)
		} else {
			res = run(target, neverSend)
		}
		if res.Decision.ErrorClass != model.ErrorConfig || res.Sent {
			t.Fatalf("%s: 应为未发送的 config_error，实际 class=%q sent=%v", name, res.Decision.ErrorClass, res.Sent)
		}
		if res.Execution.ErrorClass != model.ErrorConfig {
			t.Fatalf("%s: execution 行应记 config_error，实际 %q", name, res.Execution.ErrorClass)
		}
		if res.Apply.Reachability != model.ApplyNotApplicable {
			t.Fatalf("%s: reachability disposition 应为 not_applicable，实际 %q", name, res.Apply.Reachability)
		}
		if got := storedRow(); got == nil || *got != *before {
			t.Fatalf("%s: config_error 不得改动 reachability 行\nbefore=%+v\nafter=%+v", name, before, got)
		}
		if !reach.OK(up.ID, up.NetworkRevision) {
			t.Fatalf("%s: config_error 不得让站 effective unreachable", name)
		}
	}

	refused := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
	}}
	if res := run(up, refused); res.Apply.Reachability != model.ApplyCurrent {
		t.Fatalf("真实建连失败应提交 reachability: %+v", res.Apply)
	}
	if got := storedRow(); got == nil || got.State != model.ReachabilityUnreachable || got.ConsecutiveFail != 1 {
		t.Fatalf("阈值为 1 时一次建连失败应提交 unreachable: %+v", got)
	}
}
