package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/router"
)

func TestOutboundHeadersReuseCapturedTargetCredentials(t *testing.T) {
	const captured = "fixture-captured-target-credential"
	upstream := &model.Upstream{ID: 1, BaseURL: "https://example.test", APIKey: "fixture-other-config-generation", CredentialRevision: 2}
	endpoint := &model.UpstreamEndpoint{ID: 2, UpstreamID: 1, Kind: model.EndpointMessages, URLMode: model.EndpointURLCanonical,
		Revision: 1, AuthProfile: model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "upstream_api_key", Revision: 1}}
	target, err := outbound.NewResolver(testHasher{}).Resolve(context.Background(), outbound.ResolveInput{
		Upstream: &model.ProbeUpstreamConfig{ID: 1, BaseURL: upstream.BaseURL}, Endpoint: endpoint,
		Values: outbound.Values{UpstreamAPIKey: []byte(captured), CredentialRevision: 1}, Use: outbound.ResolveRealForward,
	})
	if err != nil {
		t.Fatal(err)
	}
	header, err := (&Handler{}).outboundHeaders(httptest.NewRequest(http.MethodPost, "/v1/messages", nil),
		&router.Candidate{Upstream: upstream}, target, model.ProtoAnthropic)
	if err != nil {
		t.Fatal(err)
	}
	if header.Get("Authorization") != "Bearer "+captured {
		t.Fatal("authentication reread credentials outside the captured target")
	}
}
