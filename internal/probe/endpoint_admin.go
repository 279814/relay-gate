package probe

import (
	"context"
	"reflect"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// EndpointMutation is the complete ordinary editor contract. Migration
// provenance, review flags, server revisions and calibration results are absent.
type EndpointMutation struct {
	UpstreamID         int64                `json:"upstream_id"`
	Endpoint           model.EndpointKind   `json:"endpoint"`
	URLOverride        string               `json:"url_override"`
	FixedQueryTemplate string               `json:"fixed_query_template"`
	AuthProfile        EndpointAuthMutation `json:"auth_profile"`
}

type EndpointAuthMutation struct {
	Mode          model.AuthMode         `json:"mode"`
	HeaderName    string                 `json:"header_name,omitempty"`
	QueryName     string                 `json:"query_name,omitempty"`
	SecretRef     string                 `json:"secret_ref"`
	ManualHeaders []model.HeaderTemplate `json:"manual_headers,omitempty"`
}

// EndpointMutationFrom supplies a partial HTTP editor's baseline without
// copying server-owned fields into its decoder.
func EndpointMutationFrom(endpoint model.UpstreamEndpoint) EndpointMutation {
	return EndpointMutation{UpstreamID: endpoint.UpstreamID, Endpoint: endpoint.Kind,
		URLOverride: endpoint.URLOverride, FixedQueryTemplate: endpoint.FixedQueryTemplate,
		AuthProfile: EndpointAuthMutation{Mode: endpoint.AuthProfile.Mode, HeaderName: endpoint.AuthProfile.HeaderName,
			QueryName: endpoint.AuthProfile.QueryName, SecretRef: endpoint.AuthProfile.SecretRef, ManualHeaders: endpoint.AuthProfile.ManualHeaders}}
}

func (input EndpointMutation) endpoint() (model.UpstreamEndpoint, error) {
	if !input.AuthProfile.Mode.Valid() || input.AuthProfile.Mode == model.AuthModeLegacyAutoRealOnly {
		return model.UpstreamEndpoint{}, model.WrapValidation("普通 Endpoint 必须显式选择单一认证模式，不能创建迁移兼容认证")
	}
	if input.AuthProfile.SecretRef == "" {
		return model.UpstreamEndpoint{}, model.WrapValidation("auth secret_ref 必须显式指定")
	}
	return model.UpstreamEndpoint{UpstreamID: input.UpstreamID, Kind: input.Endpoint, URLMode: model.EndpointURLCanonical,
		URLOverride: input.URLOverride, FixedQueryTemplate: input.FixedQueryTemplate,
		AuthProfile: model.EndpointAuthProfile{Mode: input.AuthProfile.Mode, HeaderName: input.AuthProfile.HeaderName,
			QueryName: input.AuthProfile.QueryName, SecretRef: input.AuthProfile.SecretRef, ManualHeaders: input.AuthProfile.ManualHeaders}}, nil
}

func migrationEndpoint(endpoint model.UpstreamEndpoint) bool {
	return endpoint.URLMode != model.EndpointURLCanonical || endpoint.NeedsReview || endpoint.LegacyFullURLID != 0 ||
		endpoint.LegacyFullURLRevision != 0 || endpoint.LegacyCompatRealOnly || endpoint.AuthProfile.Mode == model.AuthModeLegacyAutoRealOnly
}

func (s *Service) CreateEndpoint(_ context.Context, input EndpointMutation) (model.UpstreamEndpoint, error) {
	endpoint, err := input.endpoint()
	if err != nil {
		return model.UpstreamEndpoint{}, err
	}
	if err = s.store.CreateEndpoint(&endpoint); err != nil {
		return model.UpstreamEndpoint{}, err
	}
	if s.invalidator != nil {
		s.invalidator.InvalidateUpstream(endpoint.UpstreamID)
	}
	return endpoint, nil
}

func (s *Service) UpdateEndpoint(_ context.Context, id, expectedRevision int64, input EndpointMutation) (model.UpstreamEndpoint, error) {
	if expectedRevision < 1 {
		return model.UpstreamEndpoint{}, model.WrapValidation("expected_revision 必须为正整数")
	}
	current, err := s.store.GetEndpoint(id)
	if err != nil {
		return model.UpstreamEndpoint{}, err
	}
	if current.Revision != expectedRevision {
		return model.UpstreamEndpoint{}, store.ErrRevisionConflict
	}
	if migrationEndpoint(*current) {
		return model.UpstreamEndpoint{}, model.WrapValidation("迁移兼容 Endpoint 只允许审核或校准，不能通过普通编辑修改")
	}
	if input.UpstreamID != current.UpstreamID {
		return model.UpstreamEndpoint{}, model.WrapValidation("Endpoint upstream_id 不可修改")
	}
	endpoint, err := input.endpoint()
	if err != nil {
		return model.UpstreamEndpoint{}, err
	}
	endpoint.ID = id
	endpoint.AuthProfile.Revision = current.AuthProfile.Revision
	before := EndpointMutationFrom(*current).AuthProfile
	requested := input.AuthProfile
	if len(before.ManualHeaders) == 0 {
		before.ManualHeaders = nil
	}
	if len(requested.ManualHeaders) == 0 {
		requested.ManualHeaders = nil
	}
	if reflect.DeepEqual(requested, before) {
		// URL-only edits preserve a verified auth result; any ordinary auth
		// mutation must be calibrated again before claiming a selected mode.
		endpoint.AuthProfile.CalibratedMode = current.AuthProfile.CalibratedMode
	}
	if err = s.store.UpdateEndpoint(&endpoint, expectedRevision); err != nil {
		return model.UpstreamEndpoint{}, err
	}
	if s.invalidator != nil && endpoint.Revision != expectedRevision {
		s.invalidator.InvalidateUpstream(endpoint.UpstreamID)
	}
	return endpoint, nil
}

// ConfirmEndpointReview changes only an existing pending URL binding. Legacy
// auth is kept intact until the separate Calibration transaction selects a mode.
func (s *Service) ConfirmEndpointReview(_ context.Context, id, expectedRevision int64, urlOverride string) (model.UpstreamEndpoint, error) {
	if expectedRevision < 1 || urlOverride == "" {
		return model.UpstreamEndpoint{}, model.WrapValidation("审核须显式指定 URL 和正数 expected_revision")
	}
	current, err := s.store.GetEndpoint(id)
	if err != nil {
		return model.UpstreamEndpoint{}, err
	}
	if current.Revision != expectedRevision {
		return model.UpstreamEndpoint{}, store.ErrRevisionConflict
	}
	if !current.NeedsReview || current.URLMode != model.EndpointURLLegacyExact {
		return model.UpstreamEndpoint{}, model.WrapValidation("Endpoint 没有待审核的旧 URL 绑定")
	}
	current.URLMode = model.EndpointURLCanonical
	current.URLOverride = urlOverride
	current.LegacyFullURLID = 0
	current.LegacyFullURLRevision = 0
	current.NeedsReview = false
	if err = s.store.UpdateEndpoint(current, expectedRevision); err != nil {
		return model.UpstreamEndpoint{}, err
	}
	if s.invalidator != nil {
		s.invalidator.InvalidateUpstream(current.UpstreamID)
	}
	return *current, nil
}
