package store

import (
	"context"
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
