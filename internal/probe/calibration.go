package probe

// CalibrationService 把「换头/换模板再试」做成显式状态机（§8.7、§4.10、§P0-11）。
//
// 每个候选是一次独立的 ProbeExecution：恰好一次 RoundTrip，没有隐藏重试。
// Classifier 对 401/403 只返回 try_next_auth；只有本服务穷尽鉴权候选后才写
// Endpoint config_error，且不改 Upstream Reachability。

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/probetemplate"
	"github.com/279814/relay-gate/internal/revisioncodec"
	"github.com/279814/relay-gate/internal/store"
)

// CalibrationStore 是校准状态机需要的持久化面。
type CalibrationStore interface {
	CreateCalibrationRun(ctx context.Context, run *model.CalibrationRun) error
	GetCalibrationRun(ctx context.Context, id string) (*model.CalibrationRun, error)
	StartCalibrationRun(ctx context.Context, id string, expectedRevision int64) error
	PrepareCalibrationCandidate(ctx context.Context, runID string, ordinal int,
		expectedRunRevision int64, material store.PrepareCalibrationMaterial) (*model.ProbeRecipeVersion, error)
	MarkCalibrationSendStarted(ctx context.Context, runID string, ordinal int,
		executionID string, expectedRunRevision int64) error
	InterruptCalibrationCandidate(ctx context.Context, runID string, ordinal int,
		expectedRunRevision int64) error
	AdvanceCalibrationAfterExecution(ctx context.Context, runID string, ordinal int,
		executionID string, expectedRunRevision int64) (*model.CalibrationRun, error)
	CommitCalibrationSuccess(ctx context.Context, commit model.CalibrationCommit) (*model.ProbeRecipeVersion, error)
	FinishCalibrationRun(ctx context.Context, id string, state model.CalibrationState, expectedRevision int64) error
	MaterializedRecipeID(ctx context.Context, runID string, ordinal int) (int64, error)
	GetRecipe(ctx context.Context, id int64) (*model.ProbeRecipe, error)
	GetRecipeVersion(ctx context.Context, id int64) (*model.ProbeRecipeVersion, error)
	RecipeVersionSecretRefs(ctx context.Context, versionID int64) ([]model.RequiredSecretRef, error)
	GetProbeExecution(ctx context.Context, id string) (*model.ProbeExecution, error)
	GetRoute(id int64) (*model.Route, error)
	GetUpstream(id int64) (*model.Upstream, error)
	GetModelName(id int64) (*model.ModelName, error)
	Endpoint(ctx context.Context, upstreamID int64, kind model.EndpointKind) (*model.UpstreamEndpoint, error)
	ListCalibrationRunsPage(ctx context.Context, filter model.CalibrationFilter) (model.Page[*model.CalibrationRun], error)
	ResolveProbeSecret(ctx context.Context, name string) (probetemplate.ResolvedSecret, error)
}

// CalibrationPlanOptions 区分手动与 Active 首次自动校准。
type CalibrationPlanOptions struct {
	// Manual 为 true 时任意 ProbeMode 都可 Plan。
	// Manual 为 false 时仅允许 Active 且 Endpoint 仍需校准（首次配置）。
	Manual bool
}

// CalibrationCrashPoint 是测试可注入的崩溃点（§P0-11 第 16 条）。
//
// 生产路径 crashAt 恒为空。未实现「socket 写出后但 execution 插入前」——
// 那一点在 Executor RoundTrip 与 recorder 之间，需要 Executor 级 hook；
// 见 calibration.go 文末 DeferredCrashPoints。
type CalibrationCrashPoint string

const (
	CrashAfterPrepared        CalibrationCrashPoint = "after_prepared"
	CrashAfterSendStarted     CalibrationCrashPoint = "after_send_started"
	CrashAfterExecutionCommit CalibrationCrashPoint = "after_execution_commit"
)

// DeferredCrashPoints 说明本轮未实现的崩溃注入点。
var DeferredCrashPoints = []string{
	"after_socket_before_execution_insert: 需要 ProbeExecutor 在 RoundTrip 返回后、Record 前暴露 hook；P0-11 未改 Executor 发送主链到那种粒度，避免与 P0-09/P0-10 的单次发送不变量纠缠。重启语义由 send_started 无 execution → interrupted 覆盖「可能已出网」的保守分支。",
}

// CalibrationService 见文件头。
type CalibrationService struct {
	store    CalibrationStore
	executor *Executor
	clock    Clock
	log      *slog.Logger
	builtins *BuiltinSet
	settings func() (model.Settings, error)
	capReg   *CapabilityRegistry
	// invalidator clears §9.2 RouteHealth after Auth Profile / Probe Recipe publish.
	invalidator ConfigInvalidator

	mu      sync.Mutex
	wake    chan struct{}
	crashAt CalibrationCrashPoint // 仅测试
	crashFn func(CalibrationCrashPoint)
}

// NewCalibrationService 装配校准服务。
func NewCalibrationService(st CalibrationStore, executor *Executor, clock Clock,
	log *slog.Logger, settings func() (model.Settings, error), capReg *CapabilityRegistry) *CalibrationService {

	if clock == nil {
		clock = WallClock()
	}
	if log == nil {
		log = slog.Default()
	}
	return &CalibrationService{
		store:    st,
		executor: executor,
		clock:    clock,
		log:      log,
		settings: settings,
		capReg:   capReg,
		wake:     make(chan struct{}, 1),
	}
}

// WithBuiltins 注入内置模板集合（测试用）。
func (s *CalibrationService) WithBuiltins(set *BuiltinSet) *CalibrationService {
	s.builtins = set
	return s
}

// WithInvalidator wires §9.2 RouteHealth Forget after Auth/Recipe publish.
func (s *CalibrationService) WithInvalidator(inv ConfigInvalidator) *CalibrationService {
	if s != nil {
		s.invalidator = inv
	}
	return s
}

// WithCrashAt 仅测试：在指定点调用 crashFn（通常 panic 或 cancel）。
func (s *CalibrationService) WithCrashAt(point CalibrationCrashPoint, fn func(CalibrationCrashPoint)) *CalibrationService {
	s.crashAt = point
	s.crashFn = fn
	return s
}

func (s *CalibrationService) builtinsOrLoad() (*BuiltinSet, error) {
	if s.builtins != nil {
		return s.builtins, nil
	}
	return LoadBuiltinTemplates()
}

// Plan 最多产生 3 个鉴权候选，并在发送前持久化顺序与估算成本。
func (s *CalibrationService) Plan(ctx context.Context, routeID int64, endpoint model.EndpointKind,
	opts CalibrationPlanOptions) (model.CalibrationRun, error) {

	if routeID < 1 || !endpoint.Valid() {
		return model.CalibrationRun{}, model.WrapValidation("plan calibration 参数无效")
	}
	route, err := s.store.GetRoute(routeID)
	if err != nil {
		return model.CalibrationRun{}, err
	}
	upstream, err := s.store.GetUpstream(route.UpstreamID)
	if err != nil {
		return model.CalibrationRun{}, err
	}
	if err := errDisabledProbeTarget(route, upstream); err != nil {
		return model.CalibrationRun{}, err
	}
	ep, err := s.store.Endpoint(ctx, upstream.ID, endpoint)
	if err != nil {
		return model.CalibrationRun{}, err
	}
	if !opts.Manual {
		if upstream.ProbeMode != model.ProbeModeActive {
			return model.CalibrationRun{}, model.WrapValidation("Lazy 模式只能手动启动校准")
		}
		if !NeedsAuthCalibration(ep.AuthProfile) {
			return model.CalibrationRun{}, model.WrapValidation("Endpoint 已校准，不能自动创建首次 CalibrationRun")
		}
	}

	builtins, err := s.builtinsOrLoad()
	if err != nil {
		return model.CalibrationRun{}, err
	}
	compact, err := builtins.Compact(endpoint)
	if err != nil {
		return model.CalibrationRun{}, err
	}

	modes := DefaultAuthCalibrationModes()
	if len(modes) > MaxCalibrationCandidates {
		modes = modes[:MaxCalibrationCandidates]
	}
	candidates := make([]model.CalibrationCandidate, 0, len(modes))
	for _, mode := range modes {
		candidates = append(candidates, model.CalibrationCandidate{
			AuthMode:             mode,
			SourceRecipe:         compact.Identity(),
			EstimatedInputTokens: compact.EstimatedInputTokens,
		})
	}
	run := &model.CalibrationRun{
		RouteID:    routeID,
		Endpoint:   endpoint,
		Candidates: candidates,
	}
	if err := s.store.CreateCalibrationRun(ctx, run); err != nil {
		return model.CalibrationRun{}, err
	}
	loaded, err := s.store.GetCalibrationRun(ctx, run.ID)
	if err != nil {
		return model.CalibrationRun{}, err
	}
	s.signal()
	return *loaded, nil
}

// Start 把 planned run 置为 running，并唤醒 Run 循环。
func (s *CalibrationService) Start(ctx context.Context, runID string, expectedRevision int64) (model.CalibrationRun, error) {
	planned, err := s.store.GetCalibrationRun(ctx, runID)
	if err != nil {
		return model.CalibrationRun{}, err
	}
	route, err := s.store.GetRoute(planned.RouteID)
	if err != nil {
		return model.CalibrationRun{}, err
	}
	upstream, err := s.store.GetUpstream(route.UpstreamID)
	if err != nil {
		return model.CalibrationRun{}, err
	}
	if err := errDisabledProbeTarget(route, upstream); err != nil {
		return model.CalibrationRun{}, err
	}
	if err := s.store.StartCalibrationRun(ctx, runID, expectedRevision); err != nil {
		return model.CalibrationRun{}, err
	}
	loaded, err := s.store.GetCalibrationRun(ctx, runID)
	if err != nil {
		return model.CalibrationRun{}, err
	}
	s.signal()
	return *loaded, nil
}

// Cancel 取消尚未终态的 run；不开始下一候选。
func (s *CalibrationService) Cancel(ctx context.Context, runID string, expectedRevision int64) error {
	return s.store.FinishCalibrationRun(ctx, runID, model.CalibrationCanceled, expectedRevision)
}

// Run 处理 running 的校准（可在后台 goroutine 长期运行）。
func (s *CalibrationService) Run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := s.stepOnce(ctx); err != nil && !errors.Is(err, errNoCalibrationWork) {
			s.log.Warn("calibration step", "err", err)
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-s.wake:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		}
	}
}

var errNoCalibrationWork = errors.New("no calibration work")

func (s *CalibrationService) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *CalibrationService) maybeCrash(point CalibrationCrashPoint) {
	if s.crashAt == point && s.crashFn != nil {
		s.crashFn(point)
	}
}

// stepOnce 推进一个 running run 的当前候选。
func (s *CalibrationService) stepOnce(ctx context.Context) error {
	page, err := s.listRunning(ctx)
	if err != nil {
		return err
	}
	if len(page) == 0 {
		return errNoCalibrationWork
	}
	for _, run := range page {
		if err := s.advanceRun(ctx, run); err != nil {
			return err
		}
	}
	return nil
}

func (s *CalibrationService) listRunning(ctx context.Context) ([]*model.CalibrationRun, error) {
	page, err := s.store.ListCalibrationRunsPage(ctx, model.CalibrationFilter{
		PageRequest: model.PageRequest{Limit: 20},
		State:       model.CalibrationRunning,
	})
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

func (s *CalibrationService) advanceRun(ctx context.Context, run *model.CalibrationRun) error {
	if run.State != model.CalibrationRunning {
		return nil
	}
	if run.Current < 0 || run.Current >= len(run.Candidates) {
		return s.store.FinishCalibrationRun(ctx, run.ID, model.CalibrationFailed, run.Revision)
	}
	candidate := run.Candidates[run.Current]

	switch candidate.State {
	case model.CalibrationCandidatePlanned:
		return s.prepareAndContinue(ctx, run, candidate)
	case model.CalibrationCandidatePrepared:
		return s.sendCandidate(ctx, run, candidate)
	case model.CalibrationCandidateSendStarted:
		return s.recoverSendStarted(ctx, run, candidate)
	case model.CalibrationCandidateFinished, model.CalibrationCandidateIndeterminate:
		return nil
	default:
		return fmt.Errorf("未知 candidate 状态 %s", candidate.State)
	}
}

func (s *CalibrationService) prepareAndContinue(ctx context.Context, run *model.CalibrationRun,
	candidate model.CalibrationCandidate) error {

	builtins, err := s.builtinsOrLoad()
	if err != nil {
		return err
	}
	template, err := builtins.ByID(candidate.SourceRecipe.TemplateID)
	if err != nil {
		// Source 可能已是 DB identity（不应发生在 planned）；回落 compact
		template, err = builtins.Compact(run.Endpoint)
		if err != nil {
			return err
		}
	}
	material := store.PrepareCalibrationMaterial{
		Origin:               template.Family,
		Method:               template.Method,
		FixedRawQuery:        template.RawQuery,
		Headers:              template.Headers,
		Body:                 template.Body,
		BodyIsText:           true,
		StreamExpected:       template.StreamExpected,
		TimeoutProfile:       template.TimeoutProfile,
		EstimatedInputTokens: template.EstimatedInputTokens,
		SourceTemplateID:     template.ID,
		SourceRevision:       template.Revision,
	}
	if _, err := s.store.PrepareCalibrationCandidate(ctx, run.ID, candidate.Ordinal, run.Revision, material); err != nil {
		return err
	}
	s.maybeCrash(CrashAfterPrepared)
	fresh, err := s.store.GetCalibrationRun(ctx, run.ID)
	if err != nil {
		return err
	}
	return s.sendCandidate(ctx, fresh, fresh.Candidates[fresh.Current])
}

func (s *CalibrationService) recoverSendStarted(ctx context.Context, run *model.CalibrationRun,
	candidate model.CalibrationCandidate) error {

	executionID, err := plannedExecutionIDFromCandidate(candidate)
	if err != nil {
		return err
	}
	existing, getErr := s.store.GetProbeExecution(ctx, executionID)
	if getErr == nil && existing != nil {
		// 已有 execution：从 Decision 幂等 commit/advance，零重发
		return s.finishFromExecution(ctx, run, candidate, existing)
	}
	if getErr != nil && !errors.Is(getErr, store.ErrNotFound) {
		return getErr
	}
	// 无 execution：无法证明未出网 → interrupted
	return s.store.InterruptCalibrationCandidate(ctx, run.ID, candidate.Ordinal, run.Revision)
}

func plannedExecutionIDFromCandidate(candidate model.CalibrationCandidate) (string, error) {
	if candidate.ExecutionID == "" {
		return "", model.WrapValidation("candidate 缺少 execution id")
	}
	return candidate.ExecutionID, nil
}

func (s *CalibrationService) sendCandidate(ctx context.Context, run *model.CalibrationRun,
	candidate model.CalibrationCandidate) error {

	executionID, err := plannedExecutionIDFromCandidate(candidate)
	if err != nil {
		return err
	}

	// 发送前再读一次启用状态：Plan/Start 之后可能被停用；拒绝必须早于
	// send_started 与 RoundTrip，避免把配置拒绝拖成 interrupted。
	route, err := s.store.GetRoute(run.RouteID)
	if err != nil {
		return err
	}
	upstream, err := s.store.GetUpstream(route.UpstreamID)
	if err != nil {
		return err
	}
	if err := errDisabledProbeTarget(route, upstream); err != nil {
		_ = s.store.FinishCalibrationRun(ctx, run.ID, model.CalibrationFailed, run.Revision)
		return err
	}

	if candidate.State == model.CalibrationCandidatePrepared {
		if err := s.store.MarkCalibrationSendStarted(ctx, run.ID, candidate.Ordinal, executionID, run.Revision); err != nil {
			return err
		}
		s.maybeCrash(CrashAfterSendStarted)
		fresh, getErr := s.store.GetCalibrationRun(ctx, run.ID)
		if getErr != nil {
			return getErr
		}
		run = fresh
		candidate = fresh.Candidates[fresh.Current]
	}

	// cancel 检查：不开始下一候选 / 不发送
	if ctx.Err() != nil {
		return ctx.Err()
	}
	freshCancel, err := s.store.GetCalibrationRun(ctx, run.ID)
	if err != nil {
		return err
	}
	if freshCancel.State == model.CalibrationCanceled {
		return nil
	}
	run = freshCancel
	candidate = run.Candidates[run.Current]

	route, err = s.store.GetRoute(run.RouteID)
	if err != nil {
		return err
	}
	upstream, err = s.store.GetUpstream(route.UpstreamID)
	if err != nil {
		return err
	}
	if err := errDisabledProbeTarget(route, upstream); err != nil {
		_ = s.store.FinishCalibrationRun(ctx, run.ID, model.CalibrationFailed, run.Revision)
		return err
	}
	modelName, err := s.store.GetModelName(route.ModelNameID)
	if err != nil {
		return err
	}
	endpointRow, err := s.store.Endpoint(ctx, upstream.ID, run.Endpoint)
	if err != nil {
		return err
	}

	version, err := s.store.GetRecipeVersion(ctx, candidate.MaterializedRecipe.DBVersionID)
	if err != nil {
		return err
	}
	recipeMeta, err := s.store.GetRecipe(ctx, version.RecipeID)
	if err != nil {
		return err
	}
	refs, err := s.store.RecipeVersionSecretRefs(ctx, version.ID)
	if err != nil {
		return err
	}
	compiled, err := probetemplate.Compile(run.Endpoint, *version)
	if err != nil {
		return err
	}
	explicit := ResolvedRecipe{
		Layer:    model.ResolvedRoute,
		Identity: candidate.MaterializedRecipe,
		Facts: model.RecipeBindingFacts{
			Use:                     model.BindingExplicitTest,
			ResolvedLayer:           model.ResolvedRoute,
			RouteRecipeID:           recipeMeta.ID,
			RoutePublishedVersionID: version.ID,
			RouteBindingRevision:    recipeMeta.ActiveBindingRevision,
		},
		Compiled:       compiled,
		SecretRefs:     refs,
		StreamExpected: version.StreamExpected,
		TimeoutProfile: version.TimeoutProfile,
	}

	authProfile, err := SingleAuthProfile(candidate.AuthMode, endpointRow.AuthProfile.SecretRef)
	if err != nil {
		return err
	}
	authProfile.Revision = endpointRow.AuthProfile.Revision

	settings := model.DefaultSettings()
	if s.settings != nil {
		if loaded, settingsErr := s.settings(); settingsErr == nil {
			settings = loaded
		}
	}
	timeout := version.TimeoutProfile
	if timeout == "" {
		timeout = model.TimeoutL2Standard
	}
	budget := outbound.L2BudgetForProfile(settings, timeout)
	selector := model.EvidencePolicySelector{
		Kind: model.EvidenceL2, Endpoint: run.Endpoint, TimeoutProfile: timeout,
	}
	settingsFingerprint := ""
	if policy, policyErr := revisioncodec.BuildCapabilityEvidencePolicy(settings, selector); policyErr == nil {
		settingsFingerprint = revisioncodec.ProbeSettingsFingerprint(policy)
	}
	secretHash, err := s.secretRevisionsHash(ctx, refs)
	if err != nil {
		return err
	}

	req := ExecutionRequest{
		ExecutionID:               executionID,
		Trigger:                   model.TriggerCalibration,
		Upstream:                  upstream,
		ModelName:                 modelName,
		Route:                     route,
		Endpoint:                  run.Endpoint,
		Mode:                      ObserveProbe,
		Budget:                    budget,
		ObservationOrder:          s.clock.Now().UnixMilli(),
		CalibrationRunID:          run.ID,
		CandidateOrdinal:          candidate.Ordinal,
		ExplicitRecipe:            &explicit,
		AuthOverride:              &authProfile,
		DiagnosticEndpoint:        endpointRow,
		CalibrationPolicySelector: selector,
		ProbeSettingsFingerprint:  settingsFingerprint,
		ProbeSecretRevisionsHash:  secretHash,
	}
	if req.ObservationOrder <= 0 {
		req.ObservationOrder = 1
	}

	result, err := s.executor.Execute(ctx, req)
	if err != nil {
		return err
	}
	s.maybeCrash(CrashAfterExecutionCommit)

	fresh, err := s.store.GetCalibrationRun(ctx, run.ID)
	if err != nil {
		return err
	}
	return s.finishFromExecution(ctx, fresh, fresh.Candidates[fresh.Current], &result.Execution)
}

func (s *CalibrationService) secretRevisionsHash(ctx context.Context, refs []model.RequiredSecretRef) (string, error) {
	if len(refs) == 0 {
		return revisioncodec.SecretRevisionSetHash(nil), nil
	}
	revisions := make([]model.SecretRevision, 0, len(refs))
	for _, ref := range refs {
		name := strings.TrimSpace(ref.Name)
		if name == "" {
			continue
		}
		secret, err := s.store.ResolveProbeSecret(ctx, name)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				revisions = append(revisions, model.SecretRevision{Name: name})
				continue
			}
			return "", err
		}
		revisions = append(revisions, model.SecretRevision{
			ID: secret.ID, Name: name, Revision: secret.Revision, Resolved: true,
		})
	}
	return revisioncodec.SecretRevisionSetHash(revisions), nil
}

func (s *CalibrationService) finishFromExecution(ctx context.Context, run *model.CalibrationRun,
	candidate model.CalibrationCandidate, execution *model.ProbeExecution) error {

	// Cancel/interrupt 与 Execute 并发时：execution 可能已落库，但 run 已终态。
	// 不得再 CommitSuccess（把已取消的校准固化成 Auth）或 Advance。
	fresh, err := s.store.GetCalibrationRun(ctx, run.ID)
	if err != nil {
		return err
	}
	switch fresh.State {
	case model.CalibrationCanceled, model.CalibrationInterrupted,
		model.CalibrationFailed, model.CalibrationSucceeded:
		return nil
	case model.CalibrationRunning:
		run = fresh
		if run.Current >= 0 && run.Current < len(run.Candidates) {
			candidate = run.Candidates[run.Current]
		}
	default:
		return nil
	}

	if execution.Success {
		recipeID, err := s.store.MaterializedRecipeID(ctx, run.ID, candidate.Ordinal)
		if err != nil {
			return err
		}
		recipe, err := s.store.GetRecipe(ctx, recipeID)
		if err != nil {
			return err
		}
		route, err := s.store.GetRoute(run.RouteID)
		if err != nil {
			return err
		}
		endpointRow, err := s.store.Endpoint(ctx, route.UpstreamID, run.Endpoint)
		if err != nil {
			return err
		}
		// Expected* 必须是测试当时冻在 execution 上的口径，不能用 commit 前的
		// 最新读数——否则 Secret/Auth 在 RoundTrip 后被改掉时 CAS 仍会成功。
		expectedEndpointRev := execution.EndpointRevision
		if expectedEndpointRev < 1 {
			expectedEndpointRev = endpointRow.Revision
		}
		_, err = s.store.CommitCalibrationSuccess(ctx, model.CalibrationCommit{
			RunID:                    run.ID,
			ExpectedRunRevision:      run.Revision,
			CandidateOrdinal:         candidate.Ordinal,
			ExecutionID:              execution.ID,
			Endpoint:                 *endpointRow,
			ExpectedEndpointRevision: expectedEndpointRev,
			RecipeID:                 recipe.ID,
			ExpectedRecipeRevision:   recipe.Revision,
			SelectedVersionID:        candidate.MaterializedRecipe.DBVersionID,
		})
		if err != nil {
			return err
		}
		if s.capReg != nil {
			s.capReg.InvalidateAfterCalibration(run.RouteID, route.UpstreamID, run.Endpoint)
		}
		// §9.2: CommitCalibrationSuccess publishes Probe Recipe and rewrites Auth
		// Profile — Forget RouteHealth immediately (Capability-only clear is not enough).
		if s.invalidator != nil && run.RouteID > 0 {
			s.invalidator.InvalidateRoute(run.RouteID)
		}
		return nil
	}

	_, err = s.store.AdvanceCalibrationAfterExecution(ctx, run.ID, candidate.Ordinal, execution.ID, run.Revision)
	if err != nil {
		return err
	}
	if s.capReg != nil {
		route, routeErr := s.store.GetRoute(run.RouteID)
		upstreamID := int64(0)
		if routeErr == nil {
			upstreamID = route.UpstreamID
		}
		s.capReg.InvalidateAfterCalibration(run.RouteID, upstreamID, run.Endpoint)
	}
	s.signal()
	return nil
}

// Ensure *store.Store 满足接口（编译期）。
var _ CalibrationStore = (*store.Store)(nil)
