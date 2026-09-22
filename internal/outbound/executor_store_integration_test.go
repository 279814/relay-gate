// Executor → ExecutionOnlyRecorder → 真实 store.InsertProbeExecution 的端到端
// 验收（§P0-09 第 1、6 条）。
//
// 为什么必须对着真库而不是只用假 recorder：假 recorder 只证明「Executor 把
// 一行 execution 交出去了」，证明不了那一行**能落库**。而真正会在生产里炸的
// 恰恰是落库那一步 —— buildExecution 少填 RecipeOrigin 时，
// store.InsertProbeExecution → recordExecutionCostTx → CostEvidenceFromExecution
// 因 RecipeOrigin.Valid() 失败，整行写不下去，Scheduler 把它当 Ignore，
// 探活从此不再更新健康。这条测试盯的就是那条成本证据路径能走通。
//
// 放在外部测试包是为了同时 import probe 与 store 而不成环。
package outbound_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/store"
)

// stubTransports 是一个只回一份固定响应的 TransportManager。
//
// 不出网：这条测试验的是「发送主链 → 落库」，靶站的具体行为无关，
// 用一份带语义证据的 SSE 就够 —— 关键在写库那一步，而不是网络。
type stubTransports struct{ body string }

func (s stubTransports) RoundTripper(outbound.NetworkConfig) (http.RoundTripper, error) {
	return stubRoundTripper{body: s.body}, nil
}

type stubRoundTripper struct{ body string }

func (rt stubRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	header := http.Header{}
	header.Set("Content-Type", "text/event-stream")
	return &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(rt.body)),
	}, nil
}

// 一次成功的 L2：拿到 content_block_delta（语义证据）即判活。
const l2SemanticSSE = "event: message_start\ndata: {\"type\":\"message_start\"}\n\n" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\"," +
	"\"delta\":{\"type\":\"text_delta\",\"text\":\"2\"}}\n\n"

// 成功的 L2 经 ExecutionOnlyRecorder 落进真库，证明 recipe origin / evidence /
// 成本证据这条链在真实约束下成立（§P0-09 第 1、6 条）。
func TestExecutorRecordsSuccessfulL2IntoRealStore(t *testing.T) {
	cipher, err := store.NewCipher("executor-store-integration-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir()+"/executor.db", cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	upstream := &model.Upstream{
		Name: "exec-store-site", BaseURL: "https://example.invalid",
		APIKey: "sk-upstream-value", AuthStyle: model.AuthXAPIKey, Enabled: true,
	}
	if err := st.CreateUpstream(upstream); err != nil {
		t.Fatal(err)
	}
	modelName := &model.ModelName{
		Name: "claude-opus-5", Protocol: model.ProtoAnthropic,
		MatchMode: model.MatchExact, Enabled: true,
	}
	modelName.Defaults()
	if err := st.CreateModelName(modelName); err != nil {
		t.Fatal(err)
	}
	route := &model.Route{
		ModelNameID: modelName.ID, UpstreamID: upstream.ID,
		Priority: 1, Weight: 100, Enabled: true,
	}
	if err := st.CreateRoute(route); err != nil {
		t.Fatal(err)
	}

	// 与 main 同一套装配：targets/secrets 用真 store，recipes 空库落到内置模板。
	targets := outbound.NewProvider(st, st, outbound.NewResolver(cipher))
	recipes := probe.NewRecipeResolver(st).WithNotFound(func(err error) bool {
		return errors.Is(err, store.ErrNotFound)
	})
	recorder := probe.NewExecutionOnlyRecorder(st)
	executor := probe.NewExecutor(targets, st, recipes,
		stubTransports{body: l2SemanticSSE}, recorder,
		probe.AlwaysOpenAdmission(), probe.WallClock(),
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx := context.Background()
	order, _, err := st.ReserveObservationOrders(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	kind, ok := modelName.Protocol.Endpoint()
	if !ok {
		t.Fatalf("协议 %q 没有对应 endpoint", modelName.Protocol)
	}

	result, err := executor.Execute(ctx, probe.ExecutionRequest{
		ExecutionID:      "exec-store-l2",
		Trigger:          model.TriggerScheduled,
		Upstream:         upstream,
		ModelName:        modelName,
		Route:            route,
		Endpoint:         kind,
		Mode:             probe.ObserveProbe,
		Budget:           outbound.L2Budget(model.DefaultSettings()),
		ObservationOrder: order,
	})
	if err != nil {
		t.Fatalf("Execute 不该返回基础设施错误（写库失败会走这里）: %v", err)
	}
	if !result.Decision.Success {
		t.Errorf("拿到语义证据应判成功，得到 decision=%+v", result.Decision)
	}
	if !result.Sent {
		t.Error("已进入 RoundTrip，Sent 应为 true")
	}
	if !result.Apply.ExecutionStored {
		t.Error("execution 应已落进真库（ExecutionStored=true）")
	}
	// 证明关键字段确实被填上了：这几项缺一，成本证据/写库就会失败。
	if !result.Execution.RecipeOrigin.Valid() {
		t.Errorf("RecipeOrigin 必须合法，否则成本证据建不起来，得到 %q", result.Execution.RecipeOrigin)
	}
	if result.Execution.EvidenceHash == "" {
		t.Error("EvidenceHash 应由 Executor 在写库前算好")
	}
	if result.Execution.SentAtMS <= 0 {
		t.Error("已发送的执行 SentAt 应非零")
	}

	// 幂等：同一份 evidence 再写一次不该报错（store 按 evidence_hash 比对）。
	if _, err := recorder.Record(ctx, &model.ProbeObservation{Execution: result.Execution}); err != nil {
		t.Errorf("同 evidence 重复落库应幂等成功，得到 %v", err)
	}
}
