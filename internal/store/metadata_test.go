package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func metadataSite(t *testing.T, st *Store, name string) *model.Upstream {
	t.Helper()
	u := &model.Upstream{Name: name, BaseURL: "https://metadata.example", APIKey: "metadata-credential-never-selected", Enabled: true, ProbeMode: model.ProbeModeLazy}
	var endpoints []*model.UpstreamEndpoint
	for _, kind := range []model.EndpointKind{model.EndpointModels, model.EndpointMessages, model.EndpointResponses, model.EndpointChatCompletions, model.EndpointCountTokens} {
		endpoints = append(endpoints, &model.UpstreamEndpoint{Kind: kind, URLMode: model.EndpointURLCanonical, AuthProfile: model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "upstream_api_key"}})
	}
	if err := st.CreateUpstreamWithEndpoints(context.Background(), u, endpoints); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestRouteMetadataPageIsBoundedCompleteAndDoesNotReadCredentials(t *testing.T) {
	st := testStore(t)
	mn := mkModelName(t, st, "metadata-model", model.ProtoAnthropic)
	for i := 0; i < 205; i++ {
		u := metadataSite(t, st, fmt.Sprintf("metadata-%03d", i))
		r := &model.Route{ModelNameID: mn.ID, UpstreamID: u.ID, Enabled: true, Priority: (i % 3) + 1, Weight: 100}
		if err := st.CreateRoute(r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.db.Exec(`UPDATE upstream SET api_key_enc='bad-credential',probe_headers='invalid-json',proxy_url='https://user:private-proxy-password@proxy.example' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	first, err := st.ListRouteMetadataPage(context.Background(), model.RouteFilter{PageRequest: model.PageRequest{Limit: 200}})
	if err != nil || len(first.Items) != 200 || first.NextCursor == "" {
		t.Fatalf("first metadata page count=%d err=%v", len(first.Items), err)
	}
	seen := make(map[int64]bool)
	for _, item := range first.Items {
		seen[item.Route.ID] = true
		if !item.UpstreamExists || !item.ModelExists || !item.UpstreamEnabled || !item.ModelEnabled || item.UpstreamNetworkRevision != 1 || item.ModelName != mn.Name {
			t.Fatalf("incomplete metadata for route %d", item.Route.ID)
		}
	}
	last, err := st.ListRouteMetadataPage(context.Background(), model.RouteFilter{PageRequest: model.PageRequest{Limit: 200, Cursor: first.NextCursor}})
	if err != nil || len(last.Items) != 5 || last.NextCursor != "" {
		t.Fatalf("last page count=%d err=%v", len(last.Items), err)
	}
	for _, item := range last.Items {
		if seen[item.Route.ID] {
			t.Fatal("metadata page repeated route")
		}
		seen[item.Route.ID] = true
	}
	if len(seen) != 205 {
		t.Fatalf("routes=%d", len(seen))
	}
	raw, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"metadata-credential-never-selected", "private-proxy-password", "invalid-json", "bad-credential", "api_key"} {
		if strings.Contains(string(raw), value) {
			t.Fatal("metadata selected or exposed a credential-bearing column")
		}
	}
	defaultPage, err := st.ListRouteMetadataPage(context.Background(), model.RouteFilter{})
	if err != nil || len(defaultPage.Items) != 50 {
		t.Fatalf("default page count=%d err=%v", len(defaultPage.Items), err)
	}
	disabled := false
	for _, filter := range []model.RouteFilter{
		{PageRequest: model.PageRequest{Limit: 201}},
		{PageRequest: model.PageRequest{Cursor: first.NextCursor}, UpstreamID: 1},
		{PageRequest: model.PageRequest{Cursor: first.NextCursor}, Enabled: &disabled},
	} {
		if _, err := st.ListRouteMetadataPage(context.Background(), filter); err == nil {
			t.Fatal("invalid or changed metadata filter reused cursor")
		}
	}
	routes, err := st.ListRoutesPage(context.Background(), model.RouteFilter{PageRequest: model.PageRequest{Limit: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListRouteMetadataPage(context.Background(), model.RouteFilter{PageRequest: model.PageRequest{Cursor: routes.NextCursor}}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-resource cursor accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := st.ListRouteMetadataPage(ctx, model.RouteFilter{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled metadata read=%v", err)
	}
}

func TestUpstreamNameLookupReadsOnlyTheUniqueTarget(t *testing.T) {
	st := testStore(t)
	broken := metadataSite(t, st, "broken-other-site")
	target := metadataSite(t, st, "exact-target")
	if _, err := st.db.Exec(`UPDATE upstream SET api_key_enc='broken-envelope' WHERE id=?`, broken.ID); err != nil {
		t.Fatal(err)
	}
	up, err := st.GetUpstreamByName(context.Background(), target.Name)
	if err != nil || up.ID != target.ID || up.Revision != target.Revision || up.APIKey != target.APIKey {
		t.Fatal("exact name lookup read unrelated credentials or lost identity")
	}
	if _, err := st.GetUpstreamByName(context.Background(), "missing-target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing name=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := st.GetUpstreamByName(ctx, target.Name); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lookup=%v", err)
	}
}
