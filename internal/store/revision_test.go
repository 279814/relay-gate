package store

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestRevisionAwareConfigurationUpdatesSeparateRowAndSemanticRevisions(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "revision-upstream")
	modelName := mkModelName(t, store, "revision-model", model.ProtoAnthropic)
	route := &model.Route{ModelNameID: modelName.ID, UpstreamID: upstream.ID, Enabled: true}
	if err := store.CreateRoute(route); err != nil {
		t.Fatal(err)
	}

	upstream.Name = "revision-upstream-display"
	if err := store.UpdateUpstreamWithRevision(context.Background(), upstream, 1); err != nil {
		t.Fatal(err)
	}
	if upstream.Revision != 2 || upstream.NetworkRevision != 1 || upstream.CredentialRevision != 1 {
		t.Fatalf("display update revisions = %+v", upstream)
	}
	upstream.APIKey = "sk-new-credential"
	if err := store.UpdateUpstreamWithRevision(context.Background(), upstream, 2); err != nil {
		t.Fatal(err)
	}
	if upstream.Revision != 3 || upstream.NetworkRevision != 1 || upstream.CredentialRevision != 2 {
		t.Fatalf("credential update revisions = %+v", upstream)
	}
	upstream.APIKey = ""
	upstream.BaseURL = "https://revision-new.example"
	if err := store.UpdateUpstreamWithRevision(context.Background(), upstream, 3); err != nil {
		t.Fatal(err)
	}
	if upstream.Revision != 4 || upstream.NetworkRevision != 2 || upstream.CredentialRevision != 2 {
		t.Fatalf("network update revisions = %+v", upstream)
	}
	if err := store.UpdateUpstreamWithRevision(context.Background(), upstream, 3); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale upstream update = %v", err)
	}

	route.Priority = 2
	if err := store.UpdateRouteWithRevision(context.Background(), route, 1); err != nil {
		t.Fatal(err)
	}
	if route.Revision != 2 || route.CapabilityRevision != 1 {
		t.Fatalf("priority update revisions = %+v", route)
	}
	route.UpstreamModel = "mapped-model"
	if err := store.UpdateRouteWithRevision(context.Background(), route, 2); err != nil {
		t.Fatal(err)
	}
	if route.Revision != 3 || route.CapabilityRevision != 2 {
		t.Fatalf("mapping update revisions = %+v", route)
	}

	modelName.ProbePrompt = "new prompt"
	if err := store.UpdateModelNameWithRevision(context.Background(), modelName, 1); err != nil {
		t.Fatal(err)
	}
	if modelName.Revision != 2 || modelName.CapabilityRevision != 2 {
		t.Fatalf("model capability update revisions = %+v", modelName)
	}
}

func TestLegacyUpdateAdaptersAlsoAdvanceRevisions(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "legacy-revision")
	upstream.Name = "legacy-revision-renamed"
	upstream.APIKey = ""
	if err := store.UpdateUpstream(upstream); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetUpstream(upstream.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != 2 {
		t.Fatalf("legacy adapter revision = %d", got.Revision)
	}
}
