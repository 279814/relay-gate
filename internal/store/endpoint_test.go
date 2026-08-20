package store

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestLegacyCreateUpstreamAtomicallyCreatesCanonicalEndpoints(t *testing.T) {
	store := testStore(t)
	upstream := &model.Upstream{
		Name: "bundle", BaseURL: "https://bundle.example", APIKey: "sk-bundle", Enabled: true,
		AuthStyle: model.AuthBearer,
	}
	if err := store.CreateUpstream(upstream); err != nil {
		t.Fatal(err)
	}
	page, err := store.ListEndpointsPage(context.Background(), model.EndpointFilter{UpstreamID: upstream.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 5 {
		t.Fatalf("endpoint count = %d, want 5", len(page.Items))
	}
	seen := map[model.EndpointKind]bool{}
	for _, endpoint := range page.Items {
		seen[endpoint.Kind] = true
		if endpoint.AuthProfile.Mode != model.AuthModeBearer || endpoint.AuthProfile.SecretRef != "upstream_api_key" {
			t.Fatalf("endpoint auth = %+v", endpoint.AuthProfile)
		}
		if endpoint.Revision != 1 || endpoint.AuthProfile.Revision != 1 {
			t.Fatalf("endpoint revisions = %+v", endpoint)
		}
	}
	for _, kind := range []model.EndpointKind{model.EndpointModels, model.EndpointMessages, model.EndpointResponses, model.EndpointChatCompletions, model.EndpointCountTokens} {
		if !seen[kind] {
			t.Errorf("missing endpoint %s", kind)
		}
	}
	got, err := store.GetUpstream(upstream.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != 1 || got.NetworkRevision != 1 || got.CredentialRevision != 1 {
		t.Fatalf("upstream revisions = %+v", got)
	}
}

func TestCreateUpstreamWithEndpointsRollsBackWholeBundle(t *testing.T) {
	store := testStore(t)
	upstream := &model.Upstream{Name: "rollback", BaseURL: "https://rollback.example", APIKey: "sk-rollback", Enabled: true}
	endpoints := canonicalEndpointBundle(upstream)
	endpoints[3].Kind = model.EndpointKind("invalid")
	if err := store.CreateUpstreamWithEndpoints(context.Background(), upstream, endpoints); !errors.Is(err, model.ErrValidation) {
		t.Fatalf("error = %v, want validation", err)
	}
	var upstreams, endpointCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM upstream WHERE name='rollback'`).Scan(&upstreams); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM upstream_endpoint`).Scan(&endpointCount); err != nil {
		t.Fatal(err)
	}
	if upstreams != 0 || endpointCount != 0 {
		t.Fatalf("partial bundle persisted: upstream=%d endpoints=%d", upstreams, endpointCount)
	}
}

func TestEndpointUpdateUsesRevisionCAS(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "endpoint-cas")
	page, err := store.ListEndpointsPage(context.Background(), model.EndpointFilter{
		UpstreamID: upstream.ID, Endpoint: model.EndpointMessages,
	})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("list endpoint = %v, err=%v", page.Items, err)
	}
	endpoint := page.Items[0]
	endpoint.FixedQueryTemplate = "beta=true"
	if err := store.UpdateEndpoint(endpoint, 1); err != nil {
		t.Fatal(err)
	}
	if endpoint.Revision != 2 {
		t.Fatalf("updated revision = %d", endpoint.Revision)
	}
	endpoint.FixedQueryTemplate = "beta=false"
	if err := store.UpdateEndpoint(endpoint, 1); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale update error = %v", err)
	}
	got, err := store.GetEndpoint(endpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.FixedQueryTemplate != "beta=true" || got.Revision != 2 {
		t.Fatalf("stale write changed endpoint: %+v", got)
	}
}
