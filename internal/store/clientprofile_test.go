package store

// ClientProbeProfile 与 Recipe publish 的仓储测试。守的是三条：
// 唯一 tested fallback 不会被候选顶掉、telemetry 写不动 Revision、
// 发布必须凭一次仍然新鲜且身份对得上的显式测试。

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func mkCandidate(t *testing.T, store *Store, upstreamID int64, family, shape string) *model.ClientProbeProfile {
	t.Helper()
	profile := &model.ClientProbeProfile{
		UpstreamID: upstreamID, Endpoint: model.EndpointMessages,
		ClientFamily: family, ShapeHash: shape, SeenCount: 1,
		BodyTemplate: []byte(`{"model":"{{UPSTREAM_MODEL}}","max_tokens":1}`),
	}
	if err := store.CreateClientProfileCandidate(context.Background(), profile); err != nil {
		t.Fatalf("建候选 %s/%s: %v", family, shape, err)
	}
	return profile
}

func TestClientProfileCandidatesCoexistAndCannotOverwriteTestedFallback(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	upstream := mkUpstream(t, store, "profile-site")

	// 同 upstream+endpoint 下的多个 family/shape 候选必须能并存。
	first := mkCandidate(t, store, upstream.ID, "claude-cli", "shape-a")
	second := mkCandidate(t, store, upstream.ID, "claude-cli", "shape-b")
	third := mkCandidate(t, store, upstream.ID, "other-cli", "shape-a")
	page, err := store.ListClientProfilesPage(ctx,
		model.ClientProfileFilter{UpstreamID: upstream.ID, Endpoint: model.EndpointMessages})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 3 {
		t.Fatalf("候选并存 = %d 项, want 3", len(page.Items))
	}
	for _, item := range page.Items {
		if item.Status != model.ProfileCandidate {
			t.Errorf("profile %d 建成 %s, want candidate", item.ID, item.Status)
		}
	}
	// 身份唯一键重复要被 DB 拦住，而不是覆盖已有行。
	duplicate := &model.ClientProbeProfile{
		UpstreamID: upstream.ID, Endpoint: model.EndpointMessages,
		ClientFamily: "claude-cli", ShapeHash: "shape-a", SeenCount: 1,
	}
	if err := store.CreateClientProfileCandidate(ctx, duplicate); err == nil {
		t.Error("同 family+shape 重复建应被唯一键拒绝")
	}

	// 没有 tested 时 TestedClientProfile 必须回 ErrNotFound —— 调用方据此走内置模板。
	if _, err := store.TestedClientProfile(ctx, upstream.ID, model.EndpointMessages); !errors.Is(err, ErrNotFound) {
		t.Errorf("无 tested 时 error = %v, want ErrNotFound", err)
	}

	// 提升第一个为 tested，需要一次针对它的显式 profile 测试。
	markTested(t, store, first, upstream)
	tested, err := store.TestedClientProfile(ctx, upstream.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	if tested.ID != first.ID {
		t.Fatalf("tested = %d, want %d", tested.ID, first.ID)
	}

	// 再提升第二个：旧的必须被降级，且任一时刻只能有一个 tested。
	markTested(t, store, second, upstream)
	tested, err = store.TestedClientProfile(ctx, upstream.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	if tested.ID != second.ID {
		t.Errorf("换绑后 tested = %d, want %d", tested.ID, second.ID)
	}
	var testedCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM client_probe_profile
		WHERE upstream_id=? AND endpoint='messages' AND status='tested'`, upstream.ID).Scan(&testedCount); err != nil {
		t.Fatal(err)
	}
	if testedCount != 1 {
		t.Errorf("tested 行数 = %d, want 1", testedCount)
	}
	demoted, err := store.ListClientProfilesPage(ctx,
		model.ClientProfileFilter{UpstreamID: upstream.ID, Status: model.ProfileDisabled})
	if err != nil {
		t.Fatal(err)
	}
	if len(demoted.Items) != 1 || demoted.Items[0].ID != first.ID {
		t.Errorf("被降级的应是 %d，实际 %+v", first.ID, demoted.Items)
	}

	// 候选不能被 UPSERT 顶掉 tested：改候选只允许改 candidate。
	third.ShapeHash = "shape-a-v2"
	if err := store.UpdateClientProfileCandidate(ctx, third, third.Revision); err != nil {
		t.Fatalf("改 candidate 应成功: %v", err)
	}
	current, err := store.TestedClientProfile(ctx, upstream.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateClientProfileCandidate(ctx, current, current.Revision); err == nil {
		t.Error("改 tested profile 应被拒绝 —— 它正在服务")
	}
}

// TestClientProfileTelemetryDoesNotBumpRevision 是验收项 12 最容易写错的一条：
// 繁忙站每来一个同形状请求都会 touch 一次，若它动了 Revision，
// 在途的 explicit profile test 会被自己的真实流量判成 stale。
func TestClientProfileTelemetryDoesNotBumpRevision(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	upstream := mkUpstream(t, store, "telemetry-site")
	profile := mkCandidate(t, store, upstream.ID, "claude-cli", "shape-a")

	before, err := loadProfile(t, store, profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.TouchClientProfile(ctx, profile.ID, before.LastSeenAt+5000); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchClientProfile(ctx, profile.ID, before.LastSeenAt+9000); err != nil {
		t.Fatal(err)
	}
	after, err := loadProfile(t, store, profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != before.Revision {
		t.Errorf("telemetry 后 Revision = %d, want 不变的 %d", after.Revision, before.Revision)
	}
	if after.SeenCount != before.SeenCount+2 {
		t.Errorf("SeenCount = %d, want %d", after.SeenCount, before.SeenCount+2)
	}
	if after.LastSeenAt != before.LastSeenAt+9000 {
		t.Errorf("LastSeenAt = %d, want %d", after.LastSeenAt, before.LastSeenAt+9000)
	}
	// 时间戳倒流（乱序回调）不能把 LastSeenAt 往回改。
	if err := store.TouchClientProfile(ctx, profile.ID, before.LastSeenAt); err != nil {
		t.Fatal(err)
	}
	regressed, err := loadProfile(t, store, profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if regressed.LastSeenAt != before.LastSeenAt+9000 {
		t.Errorf("倒流后 LastSeenAt = %d, 不应回退", regressed.LastSeenAt)
	}
	if err := store.TouchClientProfile(ctx, 99999, 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("touch 不存在的 profile error = %v, want ErrNotFound", err)
	}
}

// TestClientProfileActiveSecretRefsFollowTestedBinding 守「active Secret refs
// 只跟随 tested binding」：候选持有 active ref 会让从未发布的形状挡住 Secret 删除。
func TestClientProfileActiveSecretRefsFollowTestedBinding(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	upstream := mkUpstream(t, store, "secret-ref-site")
	if _, err := store.CreateProbeSecret("probe-beta", []byte("context-1m-2025-08-07")); err != nil {
		t.Fatal(err)
	}
	profile := &model.ClientProbeProfile{
		UpstreamID: upstream.ID, Endpoint: model.EndpointMessages,
		ClientFamily: "claude-cli", ShapeHash: "with-secret", SeenCount: 1,
		SafeHeaders:  []model.HeaderTemplate{{Name: "anthropic-beta", Values: []string{"{{SECRET:probe-beta}}"}}},
		BodyTemplate: []byte(`{"model":"{{UPSTREAM_MODEL}}","max_tokens":1}`),
	}
	if err := store.CreateClientProfileCandidate(ctx, profile); err != nil {
		t.Fatal(err)
	}
	// 候选阶段：required 快照要有，active ref 不该有。
	if got := countRefs(t, store, "client_profile_required_secret", profile.ID); got != 1 {
		t.Errorf("候选的 required_secret = %d, want 1", got)
	}
	if got := countRefs(t, store, "client_profile_active_secret_ref", profile.ID); got != 0 {
		t.Errorf("候选的 active_secret_ref = %d, want 0", got)
	}
	markTested(t, store, profile, upstream)
	if got := countRefs(t, store, "client_profile_active_secret_ref", profile.ID); got != 1 {
		t.Errorf("tested 的 active_secret_ref = %d, want 1", got)
	}
	current, err := loadProfile(t, store, profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DisableClientProfile(ctx, profile.ID, current.Revision); err != nil {
		t.Fatal(err)
	}
	if got := countRefs(t, store, "client_profile_active_secret_ref", profile.ID); got != 0 {
		t.Errorf("停用后 active_secret_ref = %d, want 0", got)
	}
	// 引用不存在的 Secret 必须当场失败，不能写出一条永远解析不了的 profile。
	broken := &model.ClientProbeProfile{
		UpstreamID: upstream.ID, Endpoint: model.EndpointMessages,
		ClientFamily: "claude-cli", ShapeHash: "missing-secret", SeenCount: 1,
		SafeHeaders: []model.HeaderTemplate{{Name: "x-test", Values: []string{"{{SECRET:not-created}}"}}},
	}
	if err := store.CreateClientProfileCandidate(ctx, broken); err == nil {
		t.Error("引用不存在的 Secret 应被拒绝")
	}
	if got := countRefs(t, store, "client_profile_required_secret", broken.ID); got != 0 {
		t.Errorf("失败的建档留下了 %d 条 required_secret，事务没回滚干净", got)
	}
}

func TestMarkClientProfileTestedRequiresFreshMatchingExecution(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	upstream := mkUpstream(t, store, "publish-guard")
	profile := mkCandidate(t, store, upstream.ID, "claude-cli", "shape-a")

	// 不存在的 execution。
	if err := store.MarkClientProfileTested(ctx, profile.ID, "no-such-exec", profile.Revision); err == nil {
		t.Error("不存在的 execution 应被拒绝")
	}
	// resolved（非显式 profile 测试）的 execution。
	resolved := profileTestExecution(t, store, profile, upstream, "exec-resolved")
	resolved.RecipeBindingUse = model.BindingResolved
	resolved.RecipeStorage = model.RecipeStorageEmbedded
	resolved.TemplateID = "builtin:messages"
	resolved.ClientProfileID = 0
	resolved.RecipeIdentityRevision = 1
	if err := store.InsertProbeExecution(ctx, &resolved); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkClientProfileTested(ctx, profile.ID, resolved.ID, profile.Revision); err == nil {
		t.Error("resolved execution 不能作为 profile 发布依据")
	}
	// 失败的显式测试。
	failed := profileTestExecution(t, store, profile, upstream, "exec-failed")
	failed.Success, failed.Reachable = false, false
	failed.ErrorClass = model.ErrorTransient
	if err := store.InsertProbeExecution(ctx, &failed); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkClientProfileTested(ctx, profile.ID, failed.ID, profile.Revision); err == nil {
		t.Error("失败的测试不能发布")
	}
	// 测试后 profile 又被改过：identity revision 不再匹配，必须要求重测。
	good := profileTestExecution(t, store, profile, upstream, "exec-good")
	if err := store.InsertProbeExecution(ctx, &good); err != nil {
		t.Fatal(err)
	}
	profile.ShapeHash = "shape-a-changed"
	if err := store.UpdateClientProfileCandidate(ctx, profile, profile.Revision); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkClientProfileTested(ctx, profile.ID, good.ID, profile.Revision); err == nil {
		t.Error("profile 在测试后被改过，应要求重测")
	}
	// 重测后可以发布；用错的 expectedRevision 要回 409。
	fresh := profileTestExecution(t, store, profile, upstream, "exec-fresh")
	if err := store.InsertProbeExecution(ctx, &fresh); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkClientProfileTested(ctx, profile.ID, fresh.ID, profile.Revision+99); !errors.Is(err, ErrRevisionConflict) {
		t.Errorf("错的 expectedRevision error = %v, want ErrRevisionConflict", err)
	}
	if err := store.MarkClientProfileTested(ctx, profile.ID, fresh.ID, profile.Revision); err != nil {
		t.Fatalf("重测后发布应成功: %v", err)
	}
}

func loadProfile(t *testing.T, store *Store, id int64) (*model.ClientProbeProfile, error) {
	t.Helper()
	return scanClientProfile(store.db.QueryRow(`SELECT `+clientProfileCols+
		` FROM client_probe_profile WHERE id=?`, id))
}

func countRefs(t *testing.T, store *Store, table string, profileID int64) int {
	t.Helper()
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM `+table+
		` WHERE client_profile_id=?`, profileID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// profileTestExecution 造一条针对该 profile 的显式测试 execution。
// Capability 侧固定 not_applicable：显式测试不改在服务的能力状态。
func profileTestExecution(t *testing.T, store *Store, profile *model.ClientProbeProfile, upstream *model.Upstream, id string) model.ProbeExecution {
	t.Helper()
	page, err := store.ListEndpointsPage(context.Background(), model.EndpointFilter{
		UpstreamID: upstream.ID, Endpoint: model.EndpointMessages,
	})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("messages endpoint = %+v err=%v", page, err)
	}
	endpoint := page.Items[0]
	order := nextTestObservationOrder(t, store)
	return model.ProbeExecution{
		ID: id, Trigger: model.TriggerManual, UpstreamID: upstream.ID,
		UpstreamNetworkRevision:    upstream.NetworkRevision,
		UpstreamCredentialRevision: upstream.CredentialRevision,
		EndpointID:                 endpoint.ID, EndpointRevision: endpoint.Revision,
		AuthProfileRevision:    endpoint.AuthProfile.Revision,
		Endpoint:               model.EndpointMessages,
		RecipeBindingUse:       model.BindingExplicitProfileTest,
		RecipeStorage:          model.RecipeStorageProfile,
		RecipeOrigin:           model.RecipeLearned,
		ClientProfileID:        profile.ID,
		RecipeIdentityRevision: profile.Revision,
		EvidenceHash:           "evidence-" + id,
		ErrorClass:             model.ErrorNone,
		Capability:             model.CapabilityUnknown,
		Scope:                  model.ScopeUpstreamEndpoint,
		Reachable:              true, Final: true, Success: true,
		ObservationOrder: order, SentAtMS: order, DoneAtMS: order + 1,
	}
}

func nextTestObservationOrder(t *testing.T, store *Store) int64 {
	t.Helper()
	var maximum int64
	if err := store.db.QueryRow(`SELECT COALESCE(MAX(observation_order),0) FROM probe_execution`).Scan(&maximum); err != nil {
		t.Fatal(err)
	}
	return maximum + 1
}

func markTested(t *testing.T, store *Store, profile *model.ClientProbeProfile, upstream *model.Upstream) {
	t.Helper()
	current, err := loadProfile(t, store, profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	execution := profileTestExecution(t, store, current, upstream, "test-exec-"+current.ShapeHash)
	if err := store.InsertProbeExecution(context.Background(), &execution); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkClientProfileTested(context.Background(), current.ID,
		execution.ID, current.Revision); err != nil {
		t.Fatalf("提升 profile %d 为 tested: %v", current.ID, err)
	}
}
