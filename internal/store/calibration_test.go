package store

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestPrepareCalibrationCandidate_RollsBackOnFailure(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "cal-prep")
	mn := mkModelName(t, st, "cal-model", model.ProtoAnthropic)
	rt := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Priority: 1, Weight: 1, Enabled: true}
	if err := st.CreateRoute(rt); err != nil {
		t.Fatal(err)
	}
	run := &model.CalibrationRun{
		RouteID:  rt.ID,
		Endpoint: model.EndpointMessages,
		Candidates: []model.CalibrationCandidate{
			{AuthMode: model.AuthModeBearer, SourceRecipe: model.RecipeIdentity{
				Storage: model.RecipeStorageEmbedded, Origin: model.RecipeCompact,
				TemplateID: "builtin:messages:compact:1", Revision: 1,
			}, EstimatedInputTokens: 12},
		},
	}
	if err := st.CreateCalibrationRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if err := st.StartCalibrationRun(context.Background(), run.ID, 1); err != nil {
		t.Fatal(err)
	}
	fresh, err := st.GetCalibrationRun(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	// 非法 method 让 version 校验失败 → 整事务回滚，candidate 仍 planned
	_, err = st.PrepareCalibrationCandidate(context.Background(), fresh.ID, 0, fresh.Revision,
		PrepareCalibrationMaterial{
			Origin: model.RecipeCompact, Method: "GET", // messages 不允许 GET
			Body: []byte(`{}`), BodyIsText: true, TimeoutProfile: model.TimeoutL2Standard,
		})
	if err == nil {
		t.Fatal("非法 material 应失败")
	}
	after, err := st.GetCalibrationRun(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Candidates[0].State != model.CalibrationCandidatePlanned {
		t.Fatalf("失败后应仍 planned，got %s", after.Candidates[0].State)
	}
	if after.Candidates[0].MaterializedRecipe.DBVersionID != 0 {
		t.Fatal("回滚后不应留下 materialized version")
	}
}

func TestCommitCalibrationSuccess_MissingRunFails(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "cal-commit")
	ep, err := st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.CommitCalibrationSuccess(context.Background(), model.CalibrationCommit{
		RunID: "missing", ExpectedRunRevision: 1, CandidateOrdinal: 0,
		ExecutionID: "x", Endpoint: *ep, ExpectedEndpointRevision: ep.Revision,
		RecipeID: 1, ExpectedRecipeRevision: 1, SelectedVersionID: 1,
	})
	if err == nil {
		t.Fatal("缺失 run 应失败")
	}
}

func TestCommitCalibrationSuccess_CredentialChangeRequiresRetest(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	up := mkUpstream(t, st, "cal-cred")
	mn := mkModelName(t, st, "cal-cred-model", model.ProtoAnthropic)
	rt := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Priority: 1, Weight: 1, Enabled: true}
	if err := st.CreateRoute(rt); err != nil {
		t.Fatal(err)
	}
	ep, err := st.Endpoint(ctx, up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	run := &model.CalibrationRun{
		RouteID:  rt.ID,
		Endpoint: model.EndpointMessages,
		Candidates: []model.CalibrationCandidate{
			{AuthMode: model.AuthModeBearer, SourceRecipe: model.RecipeIdentity{
				Storage: model.RecipeStorageEmbedded, Origin: model.RecipeCompact,
				TemplateID: "builtin:messages:compact:1", Revision: 1,
			}, EstimatedInputTokens: 12},
		},
	}
	if err := st.CreateCalibrationRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	if err := st.StartCalibrationRun(ctx, run.ID, 1); err != nil {
		t.Fatal(err)
	}
	fresh, err := st.GetCalibrationRun(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	version, err := st.PrepareCalibrationCandidate(ctx, fresh.ID, 0, fresh.Revision, PrepareCalibrationMaterial{
		Origin: model.RecipeCompact, Method: "POST",
		Headers:    []model.HeaderTemplate{{Name: "content-type", Values: []string{"application/json"}}},
		Body:       []byte(`{"model":"x","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`),
		BodyIsText: true, StreamExpected: true, TimeoutProfile: model.TimeoutL2Standard,
		EstimatedInputTokens: 12, SourceTemplateID: "builtin:messages:compact:1", SourceRevision: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	fresh, err = st.GetCalibrationRun(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	candidate := fresh.Candidates[0]
	execID := candidate.ExecutionID
	if err := st.MarkCalibrationSendStarted(ctx, fresh.ID, 0, execID, fresh.Revision); err != nil {
		t.Fatal(err)
	}
	recipeID, err := st.MaterializedRecipeID(ctx, fresh.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	recipe, err := st.GetRecipe(ctx, recipeID)
	if err != nil {
		t.Fatal(err)
	}
	order := nextTestObservationOrder(t, st)
	execution := model.ProbeExecution{
		ID: execID, Trigger: model.TriggerCalibration, UpstreamID: up.ID,
		UpstreamNetworkRevision: up.NetworkRevision, UpstreamCredentialRevision: up.CredentialRevision,
		EndpointID: ep.ID, EndpointRevision: ep.Revision, AuthProfileRevision: ep.AuthProfile.Revision,
		RouteID: rt.ID, RouteCapabilityRevision: rt.CapabilityRevision,
		ModelCapabilityRevision: mn.CapabilityRevision,
		Endpoint:                model.EndpointMessages, RecipeBindingUse: model.BindingExplicitTest,
		RecipeStorage: model.RecipeStorageDB, RecipeOrigin: model.RecipeCompact,
		RecipeID: recipeID, RecipeVersionID: version.ID,
		CalibrationRunID: fresh.ID, CandidateOrdinal: 0,
		EvidenceHash: "evidence-cal-cred",
		ErrorClass:   model.ErrorNone, Capability: model.CapabilityUnknown,
		Scope: model.ScopeRouteEndpoint, Reachable: true, Final: true, Success: true,
		ObservationOrder: order, SentAtMS: order, DoneAtMS: order + 1,
	}
	if err := st.InsertProbeExecution(ctx, &execution); err != nil {
		t.Fatal(err)
	}

	// 测试后改凭据：commit 必须 409，不能把旧 key 的成功固化成 Auth Profile。
	up.APIKey = "sk-cal-cred-rotated-key"
	if err := st.UpdateUpstream(up); err != nil {
		t.Fatal(err)
	}
	fresh, err = st.GetCalibrationRun(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.CommitCalibrationSuccess(ctx, model.CalibrationCommit{
		RunID: fresh.ID, ExpectedRunRevision: fresh.Revision, CandidateOrdinal: 0,
		ExecutionID: execID, Endpoint: *ep, ExpectedEndpointRevision: ep.Revision,
		RecipeID: recipeID, ExpectedRecipeRevision: recipe.Revision, SelectedVersionID: version.ID,
	})
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("凭据变更后 commit error=%v, want ErrRevisionConflict", err)
	}
}
