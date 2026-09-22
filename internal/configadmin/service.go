package configadmin

// Package configadmin 提供 Upstream/ModelName/Route 的 revision-aware CRUD
// 与统一配置发布入口（P0-14）。API 只依赖本包接口，不直连 Store 枚举。

import (
	"context"

	"github.com/279814/relay-gate/internal/model"
)

// Store 是 configadmin 需要的窄存储面。
type Store interface {
	ListUpstreamsPage(ctx context.Context, filter model.UpstreamFilter) (model.Page[*model.Upstream], error)
	GetUpstream(id int64) (*model.Upstream, error)
	CreateUpstream(u *model.Upstream) error
	UpdateUpstreamWithRevision(ctx context.Context, upstream *model.Upstream, expectedRevision int64) error
	DeleteUpstream(id int64) error

	ListModelNamesPage(ctx context.Context, filter model.ModelNameFilter) (model.Page[*model.ModelName], error)
	GetModelName(id int64) (*model.ModelName, error)
	CreateModelName(m *model.ModelName) error
	UpdateModelNameWithRevision(ctx context.Context, value *model.ModelName, expectedRevision int64) error
	DeleteModelName(id int64) error

	ListRoutesPage(ctx context.Context, filter model.RouteFilter) (model.Page[*model.Route], error)
	GetRoute(id int64) (*model.Route, error)
	CreateRoute(r *model.Route) error
	UpdateRouteWithRevision(ctx context.Context, value *model.Route, expectedRevision int64) error
	DeleteRoute(id int64) error
}

// Publisher 在写提交后通知热配置刷新（可为 nil）。
type Publisher interface {
	Publish()
}

// Service 实现 Upstream/ModelName/Route 管理。
type Service struct {
	store Store
	pub   Publisher
}

// New 构造 Service。
func New(store Store, pub Publisher) *Service {
	return &Service{store: store, pub: pub}
}

func (s *Service) publish() {
	if s != nil && s.pub != nil {
		s.pub.Publish()
	}
}

func (s *Service) ListUpstreams(ctx context.Context, f model.UpstreamFilter) (model.Page[model.Upstream], error) {
	page, err := s.store.ListUpstreamsPage(ctx, f)
	return derefPage(page), err
}

func (s *Service) GetUpstream(_ context.Context, id int64) (model.Upstream, error) {
	u, err := s.store.GetUpstream(id)
	if err != nil {
		return model.Upstream{}, err
	}
	return *u, nil
}

func (s *Service) CreateUpstream(_ context.Context, in model.Upstream) (model.Upstream, error) {
	cp := in
	if err := s.store.CreateUpstream(&cp); err != nil {
		return model.Upstream{}, err
	}
	s.publish()
	return cp, nil
}

func (s *Service) UpdateUpstream(ctx context.Context, id, expectedRevision int64, in model.Upstream) (model.Upstream, error) {
	in.ID = id
	if err := s.store.UpdateUpstreamWithRevision(ctx, &in, expectedRevision); err != nil {
		return model.Upstream{}, err
	}
	s.publish()
	return in, nil
}

func (s *Service) DeleteUpstream(_ context.Context, id, _ int64) error {
	if err := s.store.DeleteUpstream(id); err != nil {
		return err
	}
	s.publish()
	return nil
}

func (s *Service) ListModelNames(ctx context.Context, f model.ModelNameFilter) (model.Page[model.ModelName], error) {
	page, err := s.store.ListModelNamesPage(ctx, f)
	return derefPage(page), err
}

func (s *Service) GetModelName(_ context.Context, id int64) (model.ModelName, error) {
	m, err := s.store.GetModelName(id)
	if err != nil {
		return model.ModelName{}, err
	}
	return *m, nil
}

func (s *Service) CreateModelName(_ context.Context, in model.ModelName) (model.ModelName, error) {
	cp := in
	if err := s.store.CreateModelName(&cp); err != nil {
		return model.ModelName{}, err
	}
	s.publish()
	return cp, nil
}

func (s *Service) UpdateModelName(ctx context.Context, id, expectedRevision int64, in model.ModelName) (model.ModelName, error) {
	in.ID = id
	if err := s.store.UpdateModelNameWithRevision(ctx, &in, expectedRevision); err != nil {
		return model.ModelName{}, err
	}
	s.publish()
	return in, nil
}

func (s *Service) DeleteModelName(_ context.Context, id, _ int64) error {
	if err := s.store.DeleteModelName(id); err != nil {
		return err
	}
	s.publish()
	return nil
}

func (s *Service) ListRoutes(ctx context.Context, f model.RouteFilter) (model.Page[model.Route], error) {
	page, err := s.store.ListRoutesPage(ctx, f)
	return derefPage(page), err
}

func (s *Service) GetRoute(_ context.Context, id int64) (model.Route, error) {
	r, err := s.store.GetRoute(id)
	if err != nil {
		return model.Route{}, err
	}
	return *r, nil
}

func (s *Service) CreateRoute(_ context.Context, in model.Route) (model.Route, error) {
	cp := in
	if err := s.store.CreateRoute(&cp); err != nil {
		return model.Route{}, err
	}
	s.publish()
	return cp, nil
}

func (s *Service) UpdateRoute(ctx context.Context, id, expectedRevision int64, in model.Route) (model.Route, error) {
	in.ID = id
	if err := s.store.UpdateRouteWithRevision(ctx, &in, expectedRevision); err != nil {
		return model.Route{}, err
	}
	s.publish()
	return in, nil
}

func (s *Service) DeleteRoute(_ context.Context, id, _ int64) error {
	if err := s.store.DeleteRoute(id); err != nil {
		return err
	}
	s.publish()
	return nil
}

func derefPage[T any](page model.Page[*T]) model.Page[T] {
	out := model.Page[T]{NextCursor: page.NextCursor, Items: make([]T, 0, len(page.Items))}
	for _, item := range page.Items {
		if item != nil {
			out.Items = append(out.Items, *item)
		}
	}
	return out
}
