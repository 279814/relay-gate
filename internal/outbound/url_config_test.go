package outbound

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

// §6.5: the Endpoint's own URL configuration errors carry ErrURLConfig so
// real forwarding can treat them as route-local, while keeping ErrValidation
// and not becoming auth errors.
func TestResolve_URLConfigErrorsAreMarked(t *testing.T) {
	values := Values{UpstreamAPIKey: []byte("sk-up-test-key"), CredentialRevision: 1}
	cases := []struct {
		name    string
		baseURL string
		query   string
		values  ValueResolver
	}{
		{name: "malformed template", query: "key={{UPSTREAM_API_KEY"},
		{name: "unknown placeholder", query: "key={{NOPE}}"},
		{name: "bad base URL", baseURL: "not-a-url"},
		{name: "missing Secret source", query: "key={{SECRET:site-token}}"},
		{name: "unsupported placeholder", query: "model={{UPSTREAM_MODEL}}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := testUpstream()
			if tc.baseURL != "" {
				upstream.BaseURL = tc.baseURL
			}
			endpoint := canonicalEndpoint(model.EndpointMessages)
			endpoint.FixedQueryTemplate = tc.query
			err := resolveErr(t, ResolveInput{Upstream: upstream, Endpoint: endpoint, Values: values})
			if !errors.Is(err, ErrURLConfig) || !errors.Is(err, model.ErrValidation) {
				t.Fatalf("want ErrURLConfig + ErrValidation, got %v", err)
			}
			if errors.Is(err, ErrAuthConfig) {
				t.Fatalf("URL config error must not be ErrAuthConfig: %v", err)
			}
		})
	}
}

type failingSecrets struct{}

func (failingSecrets) ResolveProbeSecret(context.Context, string) (probetemplate.ResolvedSecret, error) {
	return probetemplate.ResolvedSecret{}, errors.New("database is locked")
}

// Failures that are not this Endpoint's configuration stay unmarked: a Secret
// store read error, an unwired resolver, and the empty-key sentinel.
func TestResolve_NonURLConfigErrorsAreNotMarked(t *testing.T) {
	endpoint := canonicalEndpoint(model.EndpointMessages)
	endpoint.FixedQueryTemplate = "key={{SECRET:site-token}}"
	err := resolveErr(t, ResolveInput{Upstream: testUpstream(), Endpoint: endpoint,
		Values: Values{Secrets: failingSecrets{}}})
	if errors.Is(err, ErrURLConfig) {
		t.Errorf("Secret store read error must not be ErrURLConfig: %v", err)
	}

	_, err = NewResolver(nil).Resolve(context.Background(), ResolveInput{
		Upstream: testUpstream(), Endpoint: canonicalEndpoint(model.EndpointMessages), Use: ResolveRealForward})
	if err == nil || errors.Is(err, ErrURLConfig) {
		t.Errorf("unwired resolver must fail without ErrURLConfig, got %v", err)
	}

	endpoint = canonicalEndpoint(model.EndpointMessages)
	endpoint.FixedQueryTemplate = "key={{UPSTREAM_API_KEY}}"
	err = resolveErr(t, ResolveInput{Upstream: testUpstream(), Endpoint: endpoint, Values: Values{}})
	if !errors.Is(err, ErrUpstreamAPIKeyEmpty) || errors.Is(err, ErrURLConfig) {
		t.Errorf("empty key keeps its own sentinel, got %v", err)
	}
}
