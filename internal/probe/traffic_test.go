package probe

import (
	"context"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
)

type stubProbeSnap struct {
	gen uint64
}

func (s stubProbeSnap) ProbeSnapshot() (*livecfg.ProbeSnapshot, error) {
	return &livecfg.ProbeSnapshot{Generation: s.gen}, nil
}

func TestTrafficObserver_CapacityFallsBackWithoutBlocking(t *testing.T) {
	m := NewTrafficObserverManager(stubProbeSnap{}, nil, nil, discardLogger())
	for i := 0; i < fullObserverLeases; i++ {
		<-m.leases
	}
	instr := m.PrepareAttempt(context.Background(), health.AttemptTarget{
		RouteID: 1, UpstreamID: 2, Endpoint: model.EndpointMessages,
	}, health.AttemptRequestView{})
	if instr.Observer == nil || instr.Retry == nil {
		t.Fatal("容量不足时仍应返回 instrumentation")
	}
	if instr.Trace == nil {
		t.Fatal("即使无 full lease 也要有 Trace")
	}
	if m.Stats().DroppedByCapacity < 1 {
		t.Fatal("应增加 capacity drop 计数")
	}
	instr.Observer.TryHeaders(200, nil, time.Now())
	instr.Observer.Finish(health.AttemptFinish{})
}

func TestRetryDecider_KeepOnUndecidedPrefix(t *testing.T) {
	d := NewRetryDecider(model.ProtoOpenAIChat)
	advice := d.DecidePeek(context.Background(), 200, nil, []byte("data: {\"id\":"), false)
	if advice.Disposition != health.RetryKeepAttempt {
		t.Fatalf("未决前缀应 KeepAttempt，得到 %s", advice.Disposition)
	}
}

func TestRetryDecider_TryNextOn5xx(t *testing.T) {
	d := NewRetryDecider(model.ProtoOpenAIChat)
	advice := d.DecidePeek(context.Background(), 503, nil, nil, true)
	if advice.Disposition != health.RetryTryNextRoute {
		t.Fatalf("503 应 TryNextRoute，得到 %s", advice.Disposition)
	}
}

func TestLearner_ShapeHashStable(t *testing.T) {
	shape := model.ClientRequestShape{FixedRawQuery: "a=1", BodyShapeJSON: []byte(`{"k":"string"}`)}
	a, b := ShapeHash(shape), ShapeHash(shape)
	if a == "" || a != b {
		t.Fatalf("ShapeHash 应稳定非空：%q %q", a, b)
	}
}

func TestOutboundAttemptTrace_ReconnectMS(t *testing.T) {
	// covered in outbound package; compile link check only
	_ = time.Now()
}
