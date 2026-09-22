package probe

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// fakeExecutionStore 是 ExecutionStore 的假实现：记录最后一次写入，
// 并可注入一个失败，用来验证 recorder 把写库错误如实上抛。
type fakeExecutionStore struct {
	calls   int
	last    *model.ProbeExecution
	failErr error
}

func (f *fakeExecutionStore) InsertProbeExecution(_ context.Context, execution *model.ProbeExecution) error {
	f.calls++
	// 拷一份存下来：调用方复用同一个 execution 结构体时，
	// 留指针会让断言看到后续被改动的值。
	clone := *execution
	f.last = &clone
	return f.failErr
}

// 落一行 execution 并把两个 disposition 钉成 not_applicable。
func TestExecutionOnlyRecorderStoresExecutionWithNotApplicable(t *testing.T) {
	store := &fakeExecutionStore{}
	recorder := NewExecutionOnlyRecorder(store)

	obs := &model.ProbeObservation{
		Execution: model.ProbeExecution{
			ID:                      "exec-1",
			Trigger:                 model.TriggerScheduled,
			UpstreamID:              7,
			Endpoint:                model.EndpointModels,
			Success:                 true,
			Reachable:               true,
			ReachabilityDisposition: model.ApplyCurrent, // 故意填个别的值，验证被覆盖
			CapabilityDisposition:   model.ApplyCurrent,
		},
	}

	result, err := recorder.Record(context.Background(), obs)
	if err != nil {
		t.Fatalf("Record 不该失败: %v", err)
	}
	if store.calls != 1 {
		t.Fatalf("应恰好写库一次，实际 %d 次", store.calls)
	}
	if store.last == nil {
		t.Fatal("store 没有收到 execution")
	}
	if store.last.ReachabilityDisposition != model.ApplyNotApplicable {
		t.Errorf("Reachability disposition 应为 not_applicable，实际 %q", store.last.ReachabilityDisposition)
	}
	if store.last.CapabilityDisposition != model.ApplyNotApplicable {
		t.Errorf("Capability disposition 应为 not_applicable，实际 %q", store.last.CapabilityDisposition)
	}
	if store.last.ID != "exec-1" {
		t.Errorf("execution 其余字段应原样落库，ID=%q", store.last.ID)
	}
	if !result.ExecutionStored {
		t.Error("apply 结果应标记 ExecutionStored=true")
	}
	if result.Reachability != model.ApplyNotApplicable || result.Capability != model.ApplyNotApplicable {
		t.Errorf("apply 结果的两个 disposition 应为 not_applicable，实际 reach=%q cap=%q",
			result.Reachability, result.Capability)
	}
}

// 写库失败作为 Go error 上抛，且 apply 结果为零值（§P0-09 第 10 条）。
func TestExecutionOnlyRecorderPropagatesStoreError(t *testing.T) {
	sentinel := errors.New("boom")
	store := &fakeExecutionStore{failErr: sentinel}
	recorder := NewExecutionOnlyRecorder(store)

	result, err := recorder.Record(context.Background(),
		&model.ProbeObservation{Execution: model.ProbeExecution{ID: "exec-2"}})
	if !errors.Is(err, sentinel) {
		t.Fatalf("应上抛 store 的错误，实际 %v", err)
	}
	if result.ExecutionStored {
		t.Error("写库失败时不应标记 ExecutionStored")
	}
}

// 未装配 store 或 observation 为空都返回校验错误，不 panic。
func TestExecutionOnlyRecorderGuards(t *testing.T) {
	if _, err := (*ExecutionOnlyRecorder)(nil).Record(context.Background(), nil); err == nil {
		t.Error("nil recorder 应返回错误")
	}
	recorder := NewExecutionOnlyRecorder(&fakeExecutionStore{})
	if _, err := recorder.Record(context.Background(), nil); err == nil {
		t.Error("nil observation 应返回错误")
	}
}
