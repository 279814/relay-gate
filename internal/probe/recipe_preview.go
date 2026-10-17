package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"strings"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/probetemplate"
)

type PreviewInput struct{ RouteID int64 }

type RedactedPreview struct {
	Method                string                    `json:"method"`
	URL                   string                    `json:"url"`
	Headers               []model.HeaderTemplate    `json:"headers"`
	BodyText              string                    `json:"body_text,omitempty"`
	BodyBase64            string                    `json:"body_base64,omitempty"`
	TemplateBodyBytes     int                       `json:"redacted_template_body_bytes"`
	TemplateHash          string                    `json:"redacted_template_hash"`
	Placeholders          []string                  `json:"placeholders"`
	ChangedFields         []string                  `json:"changed_fields"`
	InputTokenLowerBound  int                       `json:"input_token_lower_bound"`
	InputTokenUpperBound  int                       `json:"input_token_upper_bound"`
	InputBoundKnown       bool                      `json:"input_bound_known"`
	OutputTokenUpperBound int                       `json:"output_token_upper_bound"`
	OutputBoundKnown      bool                      `json:"output_bound_known"`
	CurrentLayer          model.RecipeResolvedLayer `json:"current_layer"`
}

// Preview values never consult a Secret resolver, credential length or clock.
// Even session/timestamp values are fixed so previews are repeatable.
type previewValues struct {
	mn    *model.ModelName
	route *model.Route
	used  map[string]bool
}

const previewSecret = "__RELAY_REDACTED_SECRET__"

func (v *previewValues) ResolveValue(_ context.Context, name string) (probetemplate.ResolvedValue, error) {
	v.used[name] = true
	value := ""
	switch {
	case name == "UPSTREAM_API_KEY" || strings.HasPrefix(name, "SECRET:"):
		value = previewSecret
	case name == "SESSION_ID":
		value = "probe-preview-session"
	case name == "TIMESTAMP":
		value = "2000-01-01T00:00:00Z"
	case v.mn != nil && name == "UPSTREAM_MODEL":
		value = upstreamModel(v.mn, v.route)
	case v.mn != nil && name == "MODEL_NAME":
		value = v.mn.Name
	case v.mn != nil && name == "PROBE_PROMPT":
		value = probePrompt(v.mn)
	default:
		return probetemplate.ResolvedValue{}, model.WrapValidation("预览缺少模型上下文或含不支持的占位符")
	}
	return probetemplate.ResolvedValue{Plain: []byte(value), Revision: 1}, nil
}

type previewURLHasher struct{}

func (previewURLHasher) SumRequestURL(raw []byte) string {
	sum := sha256.Sum256(append([]byte("relay-gate/redacted-preview-url/v1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}

func (s *Service) adminProbeSnapshot() (*livecfg.ProbeSnapshot, error) {
	source, ok := s.snapshots.(ProbeSnapshotSource)
	if !ok {
		return nil, livecfg.ErrProbeSnapshotUnavailable
	}
	return source.ProbeSnapshot()
}

func (s *Service) adminPreviewSnapshot() (*livecfg.ProbeSnapshot, error) {
	// A preview must not trigger TTL loading of routing credentials. It reads the
	// already published non-secret view; activation-pending remains fail-closed.
	source, ok := s.snapshots.(interface {
		CachedProbeSnapshot() (*livecfg.ProbeSnapshot, error)
	})
	if !ok {
		return nil, livecfg.ErrProbeSnapshotUnavailable
	}
	return source.CachedProbeSnapshot()
}

func previewTarget(snap *livecfg.ProbeSnapshot, recipe model.ProbeRecipe, routeID int64) (*model.ProbeUpstreamConfig, *model.Route, *model.ModelName, error) {
	upstreamID := recipe.ScopeID
	if recipe.ScopeType == model.RecipeScopeRoute {
		if routeID != 0 && routeID != recipe.ScopeID {
			return nil, nil, nil, model.WrapValidation("route_id 与 Recipe 作用域不一致")
		}
		routeID = recipe.ScopeID
	}
	var route *model.Route
	var mn *model.ModelName
	if routeID > 0 {
		route = snap.Routes[routeID]
		if route == nil {
			return nil, nil, nil, model.WrapValidation("预览 Route 不存在")
		}
		if recipe.ScopeType == model.RecipeScopeUpstream && route.UpstreamID != upstreamID {
			return nil, nil, nil, model.WrapValidation("Route 不属于该 Upstream")
		}
		upstreamID = route.UpstreamID
		mn = snap.ModelNames[route.ModelNameID]
	}
	if recipe.Endpoint != model.EndpointModels {
		if route == nil || mn == nil {
			return nil, nil, nil, model.WrapValidation("模型端点必须提供该站的 Route")
		}
		endpoint, ok := mn.Protocol.Endpoint()
		if !ok || (endpoint != recipe.Endpoint && !(recipe.Endpoint == model.EndpointCountTokens && mn.Protocol == model.ProtoAnthropic)) {
			return nil, nil, nil, model.WrapValidation("Route 协议与 Recipe Endpoint 不一致")
		}
	}
	up := snap.Upstreams[upstreamID]
	if up == nil {
		return nil, nil, nil, model.WrapValidation("Recipe Upstream 不存在")
	}
	return up, route, mn, nil
}

func redactedRendered(ctx context.Context, snap *livecfg.ProbeSnapshot, up *model.ProbeUpstreamConfig, endpoint model.EndpointKind, compiled *probetemplate.CompiledRecipe, values *previewValues) (probetemplate.RenderedRequest, string, error) {
	rendered, err := compiled.Render(ctx, values)
	if err != nil {
		return rendered, "", err
	}
	ep, err := snap.Endpoint(ctx, up.ID, endpoint)
	if err != nil {
		return rendered, "", err
	}
	// Legacy encrypted full URLs cannot be safely previewed without decrypting
	// authentication material. Review/migrate the Endpoint before this operation.
	if ep.URLMode == model.EndpointURLLegacyExact {
		return rendered, "", model.WrapValidation("legacy_exact Endpoint 须先审核转换才能预览")
	}
	target, err := outbound.NewResolver(previewURLHasher{}).Resolve(ctx, outbound.ResolveInput{Upstream: up, Endpoint: ep, IncomingRawQuery: rendered.RawQuery, Values: values, Use: outbound.ResolveSyntheticProbe})
	if err != nil {
		return rendered, "", err
	}
	if err := outbound.ApplyAuth(ctx, rendered.Header, outbound.AuthInput{Profile: target.AuthProfile, Values: values, Use: outbound.ResolveSyntheticProbe}); err != nil {
		return rendered, "", err
	}
	return rendered, target.RawURL, nil
}

func (s *Service) Preview(ctx context.Context, versionID int64, in PreviewInput) (RedactedPreview, error) {
	version, err := s.GetVersion(ctx, versionID)
	if err != nil {
		return RedactedPreview{}, err
	}
	recipe, err := s.GetRecipe(ctx, version.RecipeID)
	if err != nil {
		return RedactedPreview{}, err
	}
	return s.previewVersion(ctx, version, recipe, in)
}

func (s *Service) previewVersion(ctx context.Context, version model.ProbeRecipeVersion, recipe model.ProbeRecipe, in PreviewInput) (RedactedPreview, error) {
	compiled, err := probetemplate.Compile(recipe.Endpoint, version)
	if err != nil {
		return RedactedPreview{}, err
	}
	snap, err := s.adminPreviewSnapshot()
	if err != nil {
		return RedactedPreview{}, err
	}
	up, route, mn, err := previewTarget(snap, recipe, in.RouteID)
	if err != nil {
		return RedactedPreview{}, err
	}
	values := &previewValues{mn: mn, route: route, used: map[string]bool{}}
	rendered, url, err := redactedRendered(ctx, snap, up, recipe.Endpoint, compiled, values)
	if err != nil {
		return RedactedPreview{}, err
	}
	out := RedactedPreview{Method: rendered.Method, URL: url, TemplateBodyBytes: len(rendered.Body), Headers: []model.HeaderTemplate{}, Placeholders: []string{}, ChangedFields: []string{}}
	if version.BodyIsText {
		out.BodyText = string(rendered.Body)
	} else {
		out.BodyBase64 = base64.StdEncoding.EncodeToString(rendered.Body)
	}
	for _, name := range sortedHeaderNames(rendered.Header) {
		out.Headers = append(out.Headers, model.HeaderTemplate{Name: name, Values: rendered.Header.Values(name)})
	}
	canonical, _ := json.Marshal(struct {
		Method, URL string
		Headers     []model.HeaderTemplate
		Body        []byte
	}{rendered.Method, url, out.Headers, rendered.Body})
	sum := sha256.Sum256(append([]byte("relay-gate/redacted-template/v1\x00"), canonical...))
	out.TemplateHash = hex.EncodeToString(sum[:])
	for placeholder := range values.used {
		out.Placeholders = append(out.Placeholders, placeholder)
	}
	sort.Strings(out.Placeholders)
	if recipe.Endpoint != model.EndpointModels {
		out.InputBoundKnown = !bytes.Contains(version.Body, []byte("{{SECRET:")) && !bytes.Contains(version.Body, []byte("{{UPSTREAM_API_KEY}}"))
		if out.InputBoundKnown {
			out.InputTokenUpperBound = len(rendered.Body) + 128
		}
		out.OutputTokenUpperBound = ProbeRequestOutputTokenLimit(rendered.Body)
		out.OutputBoundKnown = out.OutputTokenUpperBound > 0 || recipe.Endpoint == model.EndpointCountTokens
	}
	if recipe.Endpoint == model.EndpointModels {
		out.InputBoundKnown = true
		out.OutputBoundKnown = true
	}
	currentResolver := NewRecipeResolver(snapshotRecipeSource{snap}).WithNotFound(func(err error) bool { return errors.Is(err, errSnapshotRecipeNotFound) })
	routeID := int64(0)
	if route != nil {
		routeID = route.ID
	}
	current, err := currentResolver.Resolve(ctx, RecipeQuery{UpstreamID: up.ID, RouteID: routeID, Endpoint: recipe.Endpoint})
	if err != nil {
		return RedactedPreview{}, err
	}
	out.CurrentLayer = current.Layer
	baseline, baselineURL, err := redactedRendered(ctx, snap, up, recipe.Endpoint, current.Compiled, &previewValues{mn: mn, route: route, used: map[string]bool{}})
	if err != nil {
		return RedactedPreview{}, err
	}
	if rendered.Method != baseline.Method {
		out.ChangedFields = append(out.ChangedFields, "method")
	}
	if url != baselineURL {
		out.ChangedFields = append(out.ChangedFields, "url")
	}
	if !reflect.DeepEqual(rendered.Header, baseline.Header) {
		out.ChangedFields = append(out.ChangedFields, "headers")
	}
	if !bytes.Equal(rendered.Body, baseline.Body) {
		out.ChangedFields = append(out.ChangedFields, "body")
	}
	return out, nil
}

func sortedHeaderNames(headers http.Header) []string {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
