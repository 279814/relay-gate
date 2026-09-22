package probe

// P0-14：探活管理服务。API 只编排本 Service，不直连 Store/Scheduler 具体类型。

import (
	"context"
	"fmt"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/sample"
)

// AdminStore 是探活管理所需的窄存储面。
type AdminStore interface {
	ListEndpointsPage(ctx context.Context, filter model.EndpointFilter) (model.Page[*model.UpstreamEndpoint], error)
	GetEndpoint(id int64) (*model.UpstreamEndpoint, error)
	CreateEndpoint(endpoint *model.UpstreamEndpoint) error
	UpdateEndpoint(endpoint *model.UpstreamEndpoint, expectedRevision int64) error
	DeleteEndpoint(id, expectedRevision int64) error

	CreateProbeSecret(name string, plain []byte) (*model.ProbeSecret, error)
	UpdateProbeSecret(id int64, expectedRevision int64, plain []byte) (*model.ProbeSecret, error)
	DeleteProbeSecret(id int64, expectedRevision int64) error
	ListProbeSecretsPage(ctx context.Context, filter model.ProbeSecretFilter) (model.Page[*model.ProbeSecret], error)

	ListRecipesPage(ctx context.Context, filter model.RecipeFilter) (model.Page[*model.ProbeRecipe], error)
	GetRecipe(ctx context.Context, id int64) (*model.ProbeRecipe, error)
	CreateRecipe(scope model.RecipeScope, scopeID int64, endpoint model.EndpointKind) (int64, error)
	ListRecipeVersionsPage(ctx context.Context, filter model.RecipeVersionFilter) (model.Page[*model.ProbeRecipeVersion], error)
	GetRecipeVersion(ctx context.Context, id int64) (*model.ProbeRecipeVersion, error)
	DisableRecipe(ctx context.Context, recipeID, expectedRevision int64) error
	ArchiveRecipe(ctx context.Context, recipeID, expectedRevision int64) error

	ListProbeExecutions(ctx context.Context, filter model.ProbeExecutionFilter) (model.Page[*model.ProbeExecution], error)
	GetProbeExecution(ctx context.Context, id string) (*model.ProbeExecution, error)
	ListCapabilities(ctx context.Context, filter model.CapabilityFilter) (model.Page[*model.EndpointCapability], error)
	ListReachability(ctx context.Context, filter model.ReachabilityFilter) (model.Page[*model.UpstreamReachability], error)
	ListProbeCostDaily(ctx context.Context, filter model.ProbeCostFilter) (model.Page[*model.ProbeCostDaily], error)
	ListCalibrationRunsPage(ctx context.Context, filter model.CalibrationFilter) (model.Page[*model.CalibrationRun], error)
	GetCalibrationRun(ctx context.Context, id string) (*model.CalibrationRun, error)

	GetRoute(id int64) (*model.Route, error)
	GetUpstream(id int64) (*model.Upstream, error)
	GetModelName(id int64) (*model.ModelName, error)
}

// SnapshotSource 提供选路快照与设置。
type SnapshotSource interface {
	Snapshot() (*router.Snapshot, error)
	Settings() (model.Settings, error)
}

// RuntimeStatsSource 提供 since-start 旁路诊断。
type RuntimeStatsSource interface {
	Stats() model.ProbeRuntimeStats
}

// Service 聚合探活管理能力。
type Service struct {
	store       AdminStore
	executor    *Executor
	calibrator  *CalibrationService
	snapshots   SnapshotSource
	runtime     RuntimeStatsSource
	invalidator ConfigInvalidator
}

// ConfigInvalidator 配置变更后触发调度。
type ConfigInvalidator interface {
	InvalidateUpstream(upstreamID int64)
	InvalidateRoute(routeID int64)
}

// NewService 构造探活管理服务。
func NewService(store AdminStore, executor *Executor, calibrator *CalibrationService,
	snapshots SnapshotSource, runtime RuntimeStatsSource, invalidator ConfigInvalidator) *Service {
	return &Service{
		store: store, executor: executor, calibrator: calibrator,
		snapshots: snapshots, runtime: runtime, invalidator: invalidator,
	}
}

// RunManual 为 Route 协议对应模型 Endpoint 恰好一次 manual Execute。
func (s *Service) RunManual(ctx context.Context, routeID int64) (model.ProbeExecution, error) {
	if s == nil || s.executor == nil || s.store == nil || s.snapshots == nil {
		return model.ProbeExecution{}, model.WrapValidation("manual probe 未装配")
	}
	rt, err := s.store.GetRoute(routeID)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	up, err := s.store.GetUpstream(rt.UpstreamID)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	mn, err := s.store.GetModelName(rt.ModelNameID)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	kind, ok := mn.Protocol.Endpoint()
	if !ok {
		return model.ProbeExecution{}, fmt.Errorf("协议 %q 没有对应的 Endpoint", mn.Protocol)
	}
	settings, err := s.snapshots.Settings()
	if err != nil {
		return model.ProbeExecution{}, err
	}
	order := int64(0)
	req := ExecutionRequest{
		ExecutionID: sample.NewReqID(), Trigger: model.TriggerManual,
		Upstream: up, ModelName: mn, Route: rt, Endpoint: kind,
		Mode: ObserveProbe, Budget: outbound.L2Budget(settings), ObservationOrder: order,
	}
	if src, ok := s.snapshots.(ProbeSnapshotSource); ok {
		if snap, err := src.ProbeSnapshot(); err == nil && snap != nil {
			_ = snap // expectation 装配仍由 Executor attach 路径处理；无则走 not_applicable
		} else if err == livecfg.ErrProbeSnapshotUnavailable {
			return model.ProbeExecution{}, err
		}
	}
	res, err := s.executor.Execute(ctx, req)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	if res.Execution.ID == "" {
		res.Execution.ID = req.ExecutionID
	}
	return res.Execution, nil
}

func (s *Service) ListEndpoints(ctx context.Context, f model.EndpointFilter) (model.Page[model.UpstreamEndpoint], error) {
	page, err := s.store.ListEndpointsPage(ctx, f)
	return derefAdminPage(page), err
}

func (s *Service) GetEndpoint(_ context.Context, id int64) (model.UpstreamEndpoint, error) {
	ep, err := s.store.GetEndpoint(id)
	if err != nil {
		return model.UpstreamEndpoint{}, err
	}
	return *ep, nil
}

func (s *Service) CreateEndpoint(_ context.Context, in model.UpstreamEndpoint) (model.UpstreamEndpoint, error) {
	cp := in
	if err := s.store.CreateEndpoint(&cp); err != nil {
		return model.UpstreamEndpoint{}, err
	}
	if s.invalidator != nil && cp.UpstreamID > 0 {
		s.invalidator.InvalidateUpstream(cp.UpstreamID)
	}
	return cp, nil
}

func (s *Service) UpdateEndpoint(_ context.Context, id, expectedRevision int64, in model.UpstreamEndpoint) (model.UpstreamEndpoint, error) {
	in.ID = id
	if err := s.store.UpdateEndpoint(&in, expectedRevision); err != nil {
		return model.UpstreamEndpoint{}, err
	}
	if s.invalidator != nil && in.UpstreamID > 0 {
		s.invalidator.InvalidateUpstream(in.UpstreamID)
	}
	return in, nil
}

func (s *Service) DeleteEndpoint(_ context.Context, id, expectedRevision int64) error {
	return s.store.DeleteEndpoint(id, expectedRevision)
}

func (s *Service) ListSecrets(ctx context.Context, f model.ProbeSecretFilter) (model.Page[model.ProbeSecret], error) {
	page, err := s.store.ListProbeSecretsPage(ctx, f)
	return derefAdminPage(page), err
}

func (s *Service) CreateSecret(_ context.Context, name string, plain []byte) (model.ProbeSecret, error) {
	sec, err := s.store.CreateProbeSecret(name, plain)
	if err != nil {
		return model.ProbeSecret{}, err
	}
	return *sec, nil
}

func (s *Service) UpdateSecret(_ context.Context, id, expectedRevision int64, plain []byte) (model.ProbeSecret, error) {
	sec, err := s.store.UpdateProbeSecret(id, expectedRevision, plain)
	if err != nil {
		return model.ProbeSecret{}, err
	}
	return *sec, nil
}

func (s *Service) DeleteSecret(_ context.Context, id, expectedRevision int64) error {
	return s.store.DeleteProbeSecret(id, expectedRevision)
}

func (s *Service) ListRecipes(ctx context.Context, f model.RecipeFilter) (model.Page[model.ProbeRecipe], error) {
	page, err := s.store.ListRecipesPage(ctx, f)
	return derefAdminPage(page), err
}

func (s *Service) GetRecipe(ctx context.Context, id int64) (model.ProbeRecipe, error) {
	r, err := s.store.GetRecipe(ctx, id)
	if err != nil {
		return model.ProbeRecipe{}, err
	}
	return *r, nil
}

func (s *Service) CreateRecipe(ctx context.Context, scope model.RecipeScope, scopeID int64, endpoint model.EndpointKind) (model.ProbeRecipe, error) {
	id, err := s.store.CreateRecipe(scope, scopeID, endpoint)
	if err != nil {
		return model.ProbeRecipe{}, err
	}
	return s.GetRecipe(ctx, id)
}

func (s *Service) ListVersions(ctx context.Context, f model.RecipeVersionFilter) (model.Page[model.ProbeRecipeVersion], error) {
	page, err := s.store.ListRecipeVersionsPage(ctx, f)
	return derefAdminPage(page), err
}

func (s *Service) GetVersion(ctx context.Context, versionID int64) (model.ProbeRecipeVersion, error) {
	v, err := s.store.GetRecipeVersion(ctx, versionID)
	if err != nil {
		return model.ProbeRecipeVersion{}, err
	}
	return *v, nil
}

func (s *Service) DisableRecipe(ctx context.Context, recipeID, expectedRevision int64) (model.ProbeRecipe, error) {
	if err := s.store.DisableRecipe(ctx, recipeID, expectedRevision); err != nil {
		return model.ProbeRecipe{}, err
	}
	return s.GetRecipe(ctx, recipeID)
}

func (s *Service) ArchiveRecipe(ctx context.Context, recipeID, expectedRevision int64) (model.ProbeRecipe, error) {
	if err := s.store.ArchiveRecipe(ctx, recipeID, expectedRevision); err != nil {
		return model.ProbeRecipe{}, err
	}
	return s.GetRecipe(ctx, recipeID)
}

func (s *Service) ListExecutions(ctx context.Context, f model.ProbeExecutionFilter) (model.Page[model.ProbeExecution], error) {
	page, err := s.store.ListProbeExecutions(ctx, f)
	return derefAdminPage(page), err
}

func (s *Service) GetExecution(ctx context.Context, id string) (model.ProbeExecution, error) {
	e, err := s.store.GetProbeExecution(ctx, id)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	return *e, nil
}

func (s *Service) ListCapabilities(ctx context.Context, f model.CapabilityFilter) (model.Page[model.EndpointCapability], error) {
	page, err := s.store.ListCapabilities(ctx, f)
	return derefAdminPage(page), err
}

func (s *Service) ListReachability(ctx context.Context, f model.ReachabilityFilter) (model.Page[model.UpstreamReachability], error) {
	page, err := s.store.ListReachability(ctx, f)
	return derefAdminPage(page), err
}

func (s *Service) ListCosts(ctx context.Context, f model.ProbeCostFilter) (model.Page[model.ProbeCostDaily], error) {
	page, err := s.store.ListProbeCostDaily(ctx, f)
	return derefAdminPage(page), err
}

func (s *Service) RuntimeStats(context.Context) model.ProbeRuntimeStats {
	if s == nil || s.runtime == nil {
		return model.ProbeRuntimeStats{}
	}
	return s.runtime.Stats()
}

func (s *Service) ListCalibrations(ctx context.Context, f model.CalibrationFilter) (model.Page[model.CalibrationRun], error) {
	page, err := s.store.ListCalibrationRunsPage(ctx, f)
	return derefAdminPage(page), err
}

func (s *Service) PlanCalibration(ctx context.Context, routeID int64, endpoint model.EndpointKind) (model.CalibrationRun, error) {
	if s.calibrator == nil {
		return model.CalibrationRun{}, model.WrapValidation("calibration 未装配")
	}
	return s.calibrator.Plan(ctx, routeID, endpoint, CalibrationPlanOptions{})
}

func (s *Service) StartCalibration(ctx context.Context, runID string, expectedRevision int64) (model.CalibrationRun, error) {
	if s.calibrator == nil {
		return model.CalibrationRun{}, model.WrapValidation("calibration 未装配")
	}
	return s.calibrator.Start(ctx, runID, expectedRevision)
}

func (s *Service) GetCalibration(ctx context.Context, runID string) (model.CalibrationRun, error) {
	run, err := s.store.GetCalibrationRun(ctx, runID)
	if err != nil {
		return model.CalibrationRun{}, err
	}
	return *run, nil
}

func (s *Service) CancelCalibration(ctx context.Context, runID string, expectedRevision int64) error {
	if s.calibrator == nil {
		return model.WrapValidation("calibration 未装配")
	}
	return s.calibrator.Cancel(ctx, runID, expectedRevision)
}

func derefAdminPage[T any](page model.Page[*T]) model.Page[T] {
	out := model.Page[T]{NextCursor: page.NextCursor, Items: make([]T, 0, len(page.Items))}
	for _, item := range page.Items {
		if item != nil {
			out.Items = append(out.Items, *item)
		}
	}
	return out
}
