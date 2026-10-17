package probe

import (
	"context"
	"sort"
	"strings"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

type SampleCandidateSource interface {
	GetSample(int64) (*model.Sample, error)
}

// SampleRecipeCandidate is an unpersisted safe draft. Scope selection, testing
// and publishing are separate explicit actions in the administration service.
type SampleRecipeCandidate struct {
	SampleID   int64
	UpstreamID int64
	Endpoint   model.EndpointKind
	Version    model.ProbeRecipeVersion
	Skipped    []string
}

type SampleCandidateBuilder struct{ samples SampleCandidateSource }

func NewSampleCandidateBuilder(samples SampleCandidateSource) *SampleCandidateBuilder {
	return &SampleCandidateBuilder{samples: samples}
}

func (builder *SampleCandidateBuilder) BuildSampleCandidate(ctx context.Context, id int64) (SampleRecipeCandidate, error) {
	var result SampleRecipeCandidate
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if builder == nil || builder.samples == nil {
		return result, model.WrapValidation("样本候选服务未装配")
	}
	smp, err := builder.samples.GetSample(id)
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if smp == nil {
		return result, model.WrapValidation("样本不可用")
	}
	var endpoint model.EndpointKind
	for _, kind := range []model.EndpointKind{model.EndpointModels, model.EndpointMessages, model.EndpointResponses, model.EndpointChatCompletions, model.EndpointCountTokens} {
		if smp.Endpoint == string(kind) || smp.Endpoint == kind.CanonicalPath() {
			endpoint = kind
			break
		}
	}
	if !endpoint.Valid() || smp.InMethod != endpoint.Method() ||
		(smp.InPath != "" && smp.InPath != endpoint.CanonicalPath()) ||
		(smp.InHeaders.Get("Content-Encoding") != "" && !strings.EqualFold(smp.InHeaders.Get("Content-Encoding"), "identity")) {
		return result, model.WrapValidation("样本协议、方法或正文编码不能安全导入")
	}
	shape, reason := SanitizeRequestShape(endpoint, health.AttemptRequestView{
		Header: smp.InHeaders, RawQuery: smp.InQuery, Body: smp.InBody, BodyTruncated: smp.Truncated.Has(model.TruncInBody),
	})
	if reason != "" {
		return result, model.WrapValidation("样本形状不能安全导入: %s", reason)
	}
	shape, err = sanitizeLearnedShape(endpoint, shape)
	if err != nil {
		return result, err
	}
	version := model.ProbeRecipeVersion{Origin: model.RecipeManual, Method: endpoint.Method(), FixedRawQuery: shape.FixedRawQuery,
		Headers: shape.SafeHeaders, Body: shape.BodyTemplate, BodyIsText: true, StreamExpected: learnedStreamExpected(shape.BodyTemplate), TimeoutProfile: defaultTimeoutProfile(endpoint)}
	if err := version.ValidateForEndpoint(endpoint); err != nil {
		return result, err
	}
	retained := map[string]bool{}
	for _, header := range version.Headers {
		retained[header.Name] = true
	}
	skipped := map[string]bool{}
	for name := range smp.InHeaders {
		name = strings.ToLower(name)
		if retained[name] {
			continue
		}
		switch {
		case model.IsAuthHeader(name), name == "cookie", name == "proxy-authorization":
			skipped[name] = true
		case name == "host", name == "content-length", name == "connection", name == "transfer-encoding", name == "accept-encoding", name == "content-encoding":
			skipped[name] = true
		default:
			skipped["unapproved_headers"] = true
		}
	}
	result = SampleRecipeCandidate{SampleID: id, UpstreamID: smp.UpstreamID, Endpoint: endpoint, Version: version, Skipped: make([]string, 0, len(skipped))}
	for name := range skipped {
		result.Skipped = append(result.Skipped, name)
	}
	sort.Strings(result.Skipped)
	return result, nil
}
