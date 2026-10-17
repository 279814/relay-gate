package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/279814/relay-gate/internal/configadmin"
	"github.com/279814/relay-gate/internal/model"
)

// ConfigAdmin is the management boundary; HTTP never substitutes a freshly
// read row revision for the version held by the editing client.
type ConfigAdmin interface {
	ListUpstreams(context.Context, model.UpstreamFilter) (model.Page[model.Upstream], error)
	GetUpstream(context.Context, int64) (model.Upstream, error)
	GetUpstreamByName(context.Context, string) (model.Upstream, error)
	CreateUpstream(context.Context, model.Upstream, []configadmin.EndpointMutation) (model.Upstream, error)
	UpdateUpstream(context.Context, int64, int64, model.Upstream) (model.Upstream, error)
	DeleteUpstream(context.Context, int64, int64) error
	ListModelNames(context.Context, model.ModelNameFilter) (model.Page[model.ModelName], error)
	GetModelName(context.Context, int64) (model.ModelName, error)
	CreateModelName(context.Context, model.ModelName) (model.ModelName, error)
	UpdateModelName(context.Context, int64, int64, model.ModelName) (model.ModelName, error)
	DeleteModelName(context.Context, int64, int64) error
	ListRoutes(context.Context, model.RouteFilter) (model.Page[model.Route], error)
	ListRouteMetadata(context.Context, model.RouteFilter) (model.Page[model.RouteMetadata], error)
	GetRoute(context.Context, int64) (model.Route, error)
	CreateRoute(context.Context, model.Route) (model.Route, error)
	UpdateRoute(context.Context, int64, int64, model.Route) (model.Route, error)
	DeleteRoute(context.Context, int64, int64) error
}

var _ ConfigAdmin = (*configadmin.Service)(nil)

func (s *Server) WithConfigAdmin(admin ConfigAdmin) *Server { s.configAdmin = admin; return s }

func requireRevision(revision int64) error {
	if revision < 1 {
		return model.WrapValidation("expected_revision 必须是正整数，请刷新配置后重试")
	}
	return nil
}

func deleteRevision(r *http.Request) (int64, error) {
	values := r.URL.Query()["expected_revision"]
	if len(values) != 1 {
		return 0, requireRevision(0)
	}
	revision, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil {
		return 0, requireRevision(0)
	}
	return revision, requireRevision(revision)
}

func configPage(r *http.Request) (model.PageRequest, error) {
	page := model.PageRequest{Cursor: r.URL.Query().Get("cursor")}
	if raw, ok := r.URL.Query()["limit"]; ok {
		if len(raw) != 1 {
			return page, model.WrapValidation("limit 无效")
		}
		value, err := strconv.Atoi(raw[0])
		if err != nil || value < 1 || value > 200 {
			return page, model.WrapValidation("limit 必须在 1..200")
		}
		page.Limit = value
	}
	return page, nil
}

func configEnabled(r *http.Request) (*bool, error) {
	if raw, ok := r.URL.Query()["enabled"]; ok {
		if len(raw) != 1 || (raw[0] != "true" && raw[0] != "false") {
			return nil, model.WrapValidation("enabled 必须为 true 或 false")
		}
		value := raw[0] == "true"
		return &value, nil
	}
	return nil, nil
}

func configIDFilter(r *http.Request, name string) (int64, error) {
	if raw, ok := r.URL.Query()[name]; ok {
		if len(raw) != 1 {
			return 0, model.WrapValidation("%s 无效", name)
		}
		id, err := strconv.ParseInt(raw[0], 10, 64)
		if err != nil || id < 1 {
			return 0, model.WrapValidation("%s 无效", name)
		}
		return id, nil
	}
	return 0, nil
}

func (s *Server) publishConfigResource(w http.ResponseWriter, id, revision int64) bool {
	if err := s.publishAfterSuccessfulWrite(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "配置已保存，激活待重试，请刷新后确认", "code": "config_activation_pending", "persisted": true, "resource_id": id, "revision": revision})
		return false
	}
	return true
}
