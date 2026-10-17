package livecfg

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
	"github.com/279814/relay-gate/internal/store"
)

func TestAuthOnlyProbeSecretChangesSemanticTokenAndSnapshotBinding(t *testing.T) {
	ctx := context.Background()
	cipher, _ := store.NewCipher("auth-only-snapshot-test-master")
	st, err := store.Open(filepath.Join(t.TempDir(), "auth-snapshot.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	up := &model.Upstream{Name: "auth-only", BaseURL: "https://auth-only.example.test", APIKey: "temporary-main-upstream-credential", Enabled: true}
	if err := st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	name := &model.ModelName{Name: "auth-only-model", Protocol: model.ProtoAnthropic, Enabled: true}
	if err := st.CreateModelName(name); err != nil {
		t.Fatal(err)
	}
	route := &model.Route{UpstreamID: up.ID, ModelNameID: name.ID, Enabled: true}
	if err := st.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	secret, err := st.CreateProbeSecret("only-auth", []byte("temporary-auth-only-old-credential"))
	if err != nil {
		t.Fatal(err)
	}
	ep, err := st.Endpoint(ctx, up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	ep.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "probe:only-auth", Revision: ep.AuthProfile.Revision}
	ep.LegacyCompatRealOnly = false
	if err := st.UpdateEndpoint(ep, ep.Revision); err != nil {
		t.Fatal(err)
	}
	source := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := source.Refresh(); err != nil {
		t.Fatal(err)
	}
	old, err := source.ProbeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if old.Endpoints[up.ID][model.EndpointMessages].FixedQueryTemplate != "" {
		t.Fatal("fixture unexpectedly included a query Secret")
	}
	target := model.SemanticTarget{Scope: model.RecipeScopeRoute, UpstreamID: up.ID, RouteID: route.ID, Endpoint: model.EndpointMessages}
	identity := model.RecipeIdentity{Storage: model.RecipeStorageEmbedded, Origin: model.RecipeBasic, TemplateID: "auth-only-fixture", Revision: 1}
	facts := model.RecipeBindingFacts{Use: model.BindingResolved, ResolvedLayer: model.ResolvedEmbedded}
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL2, Endpoint: model.EndpointMessages, TimeoutProfile: model.TimeoutL2Standard}
	before, err := old.SemanticExpectation(target, identity, facts, selector)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := st.UpdateProbeSecret(secret.ID, secret.Revision, []byte("temporary-auth-only-new-credential"))
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Refresh(); err != nil {
		t.Fatal(err)
	}
	fresh, err := source.ProbeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	after, err := fresh.SemanticExpectation(target, identity, facts, selector)
	if err != nil {
		t.Fatal(err)
	}
	if before.ObservationToken == after.ObservationToken || revisioncodec.SecretRevisionSetHash(before.Revision.ProbeSecrets) == revisioncodec.SecretRevisionSetHash(after.Revision.ProbeSecrets) {
		t.Fatal("Auth-only Secret update was absent from the semantic token/Secret hash")
	}
	oldEP, _ := old.Endpoint(ctx, up.ID, model.EndpointMessages)
	newEP, _ := fresh.Endpoint(ctx, up.ID, model.EndpointMessages)
	if len(oldEP.BoundSecrets) != 1 || len(newEP.BoundSecrets) != 1 || oldEP.BoundSecrets[0].Revision != secret.Revision || newEP.BoundSecrets[0].Revision != updated.Revision {
		t.Fatal("old/new published generations did not retain their own binding revision")
	}
	newEP.BoundSecrets[0].ID = -1
	if fresh.Endpoints[up.ID][model.EndpointMessages].BoundSecrets[0].ID != secret.ID {
		t.Fatal("Endpoint getter exposed mutable binding slice from the published generation")
	}
}
