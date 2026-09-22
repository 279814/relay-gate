package health

import (
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func TestReduceReachability_HTTPResponseIsReachable(t *testing.T) {
	reducer := NewObservationReducer(func() time.Time {
		return time.UnixMilli(1_700_000_000_000)
	})
	policy := model.ReachabilityReductionPolicy{ReachableThreshold: 1, UnreachableThreshold: 2}

	for _, status := range []int{200, 401, 404, 429, 503} {
		row, err := reducer.ReduceReachability(nil, model.ProbeExecution{
			Reachable: true, StatusCode: status, SentAtMS: 1000, GotConnAtMS: 1100,
			ResponseHeaderAtMS: 1200, DoneAtMS: 1300,
		}, policy)
		if err != nil {
			t.Fatalf("status %d: %v", status, err)
		}
		if row.State != model.ReachabilityReachable {
			t.Fatalf("status %d: state=%s, want reachable", status, row.State)
		}
		if row.LastConnectMS != 100 || row.LastHeaderMS != 100 {
			t.Fatalf("status %d: latencies connect=%d header=%d", status, row.LastConnectMS, row.LastHeaderMS)
		}
	}
}

func TestReduceReachability_TransportFailureUpdatesUnreachable(t *testing.T) {
	reducer := NewObservationReducer(fixedNow)
	policy := model.ReachabilityReductionPolicy{ReachableThreshold: 1, UnreachableThreshold: 2}

	first, err := reducer.ReduceReachability(nil, model.ProbeExecution{
		Reachable: false, ErrorClass: model.ErrorUnreachable,
		SentAtMS: 1000, DoneAtMS: 1500, RedactedDetail: "transport_failure",
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if first.State != model.ReachabilityUnknown || first.ConsecutiveFail != 1 {
		t.Fatalf("first fail = %+v", first)
	}
	second, err := reducer.ReduceReachability(first, model.ProbeExecution{
		Reachable: false, ErrorClass: model.ErrorUnreachable,
		SentAtMS: 2000, DoneAtMS: 2600,
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if second.State != model.ReachabilityUnreachable || second.ConsecutiveFail != 2 {
		t.Fatalf("second fail = %+v", second)
	}
	if second.LastConnectMS != 600 {
		t.Fatalf("connect latency = %d", second.LastConnectMS)
	}
}

func TestReduceReachability_StageTimingVariants(t *testing.T) {
	reducer := NewObservationReducer(fixedNow)
	policy := model.ReachabilityReductionPolicy{ReachableThreshold: 1, UnreachableThreshold: 2}

	t.Run("tls success", func(t *testing.T) {
		row, err := reducer.ReduceReachability(nil, model.ProbeExecution{
			Reachable: true, SentAtMS: 1000, TLSHandshakeStartAtMS: 1050,
			TLSHandshakeDoneAtMS: 1150, GotConnAtMS: 1200, ResponseHeaderAtMS: 1300,
		}, policy)
		if err != nil {
			t.Fatal(err)
		}
		if row.LastConnectMS != 200 || row.LastTLSMS != 100 || row.LastHeaderMS != 100 {
			t.Fatalf("latencies=%+v", row)
		}
	})
	t.Run("reused connection tls=0", func(t *testing.T) {
		row, err := reducer.ReduceReachability(nil, model.ProbeExecution{
			Reachable: true, SentAtMS: 1000, GotConnAtMS: 1005, ResponseHeaderAtMS: 1100,
		}, policy)
		if err != nil {
			t.Fatal(err)
		}
		if row.LastTLSMS != 0 || row.LastConnectMS != 5 || row.LastHeaderMS != 95 {
			t.Fatalf("reused=%+v", row)
		}
	})
	t.Run("invalid stage order zeroes", func(t *testing.T) {
		row, err := reducer.ReduceReachability(nil, model.ProbeExecution{
			Reachable: false, SentAtMS: 2000, GotConnAtMS: 1000, DoneAtMS: 3000,
			RedactedDetail: "transport_failure",
		}, policy)
		if err != nil {
			t.Fatal(err)
		}
		if row.LastConnectMS != 0 || row.LastTLSMS != 0 || row.LastHeaderMS != 0 {
			t.Fatalf("invalid stages must zero: %+v", row)
		}
		if row.LastError != "stage_order_invalid" {
			t.Fatalf("diag = %q", row.LastError)
		}
	})
	t.Run("clock skew zeroes", func(t *testing.T) {
		row, err := reducer.ReduceReachability(nil, model.ProbeExecution{
			Reachable: true, SentAtMS: 1000, TLSHandshakeStartAtMS: 1200,
			TLSHandshakeDoneAtMS: 1100, GotConnAtMS: 1300, ResponseHeaderAtMS: 1400,
		}, policy)
		if err != nil {
			t.Fatal(err)
		}
		if row.LastConnectMS != 0 || row.LastError != "" {
			// reachable path clears LastError; stage diag only on unreachable path.
			if row.LastConnectMS != 0 || row.LastTLSMS != 0 || row.LastHeaderMS != 0 {
				t.Fatalf("clock skew must zero latencies: %+v", row)
			}
		}
	})
}

func TestReduceCapability_ScopeIsolationAndTTL(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	reducer := NewObservationReducer(func() time.Time { return now })
	policy := model.CapabilityReductionPolicy{
		SupportedTTL:   7 * 24 * time.Hour,
		UnsupportedTTL: 24 * time.Hour,
		TransientTTL:   time.Minute,
	}

	models404, err := reducer.ReduceCapability(nil, model.ProbeExecution{
		Endpoint: model.EndpointModels, Capability: model.CapabilityUnsupported,
		ErrorClass: model.ErrorUnsupported, StatusCode: 404,
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if models404.State != model.CapabilityUnsupported {
		t.Fatalf("models 404 state=%s", models404.State)
	}
	wantUnsupportedExp := now.UnixMilli() + policy.UnsupportedTTL.Milliseconds()
	if models404.ExpiresAt != wantUnsupportedExp {
		t.Fatalf("unsupported expires=%d want=%d", models404.ExpiresAt, wantUnsupportedExp)
	}

	countTokens, err := reducer.ReduceCapability(nil, model.ProbeExecution{
		Endpoint: model.EndpointCountTokens, Capability: model.CapabilityUnsupported,
		ErrorClass: model.ErrorUnsupported, StatusCode: 404,
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	// 独立行：不共享 models 结论。调用方按 (scope,endpoint) 分 key。
	if countTokens.State != model.CapabilityUnsupported {
		t.Fatalf("count_tokens unsupported=%s", countTokens.State)
	}

	messages := &model.EndpointCapability{
		State: model.CapabilitySupported, Endpoint: model.EndpointMessages,
	}
	unchanged, err := reducer.ReduceCapability(messages, model.ProbeExecution{
		Endpoint: model.EndpointCountTokens, Capability: model.CapabilityUnsupported,
		ErrorClass: model.ErrorUnsupported, StatusCode: 404,
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	// reducer 本身按单行工作；本测确认它不会因为别的 endpoint 输入而崩溃。
	if unchanged.State != model.CapabilityUnsupported {
		t.Fatalf("reducer writes the execution endpoint state, got %s", unchanged.State)
	}

	modelNotFound, err := reducer.ReduceCapability(nil, model.ProbeExecution{
		Endpoint: model.EndpointMessages, Capability: model.CapabilityConfigError,
		ErrorClass: model.ErrorModelNotFound, StatusCode: 404, RouteID: 9,
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if modelNotFound.State != model.CapabilityConfigError || modelNotFound.ExpiresAt != 0 {
		t.Fatalf("model_not_found = %+v", modelNotFound)
	}

	supported, err := reducer.ReduceCapability(nil, model.ProbeExecution{
		Capability: model.CapabilitySupported, ErrorClass: model.ErrorNone, StatusCode: 200,
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	wantSupportedExp := now.UnixMilli() + policy.SupportedTTL.Milliseconds()
	if supported.ExpiresAt != wantSupportedExp {
		t.Fatalf("supported expires=%d want=%d", supported.ExpiresAt, wantSupportedExp)
	}

	// 过期派生：ExpiresAt <= now 时 effective unknown 由 Registry 负责，库内仍是五态。
	if supported.State != model.CapabilitySupported {
		t.Fatalf("persisted state must stay supported, got %s", supported.State)
	}

	auth, err := reducer.ReduceCapability(nil, model.ProbeExecution{
		Capability: model.CapabilityUnknown, ErrorClass: model.ErrorAuthRejected, StatusCode: 401,
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if auth.State != model.CapabilityUnknown || auth.ErrorClass != model.ErrorAuthRejected {
		t.Fatalf("401 must stay auth_rejected/unknown until calibration: %+v", auth)
	}

	ignoredCurrent := &model.EndpointCapability{State: model.CapabilitySupported, StatusCode: 200}
	ignored, err := reducer.ReduceCapability(ignoredCurrent, model.ProbeExecution{
		Capability: model.CapabilityTransientError, ErrorClass: model.ErrorIgnored,
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if ignored.State != model.CapabilitySupported || ignored.StatusCode != 200 {
		t.Fatalf("ignored must not change capability: %+v", ignored)
	}
}

func fixedNow() time.Time {
	return time.UnixMilli(1_700_000_000_000)
}
