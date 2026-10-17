package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

func boundEndpointFixture(t *testing.T) (*Store, *model.UpstreamEndpoint, *model.ProbeSecret) {
	t.Helper()
	st := testStore(t)
	up := mkUpstream(t, st, "bound-endpoint")
	secret, err := st.CreateProbeSecret("bound-auth", []byte("temporary-original-bound-auth-secret"))
	if err != nil {
		t.Fatal(err)
	}
	ep, err := st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	ep.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "probe:bound-auth", Revision: ep.AuthProfile.Revision}
	ep.LegacyCompatRealOnly = false
	if err := st.UpdateEndpoint(ep, ep.Revision); err != nil {
		t.Fatal(err)
	}
	return st, ep, secret
}

func endpointFromBundle(t *testing.T, st *Store, id int64) *model.UpstreamEndpoint {
	t.Helper()
	bundle, err := st.LoadConfigBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, ep := range bundle.Endpoints {
		if ep.ID == id {
			return ep
		}
	}
	t.Fatal("endpoint missing from bundle")
	return nil
}

func requireEndpointBinding(t *testing.T, ep *model.UpstreamEndpoint, id, revision int64) {
	t.Helper()
	if len(ep.BoundSecrets) != 1 || ep.BoundSecrets[0] != (model.SecretRevision{ID: id, Name: "bound-auth", Revision: revision, Resolved: true}) {
		t.Fatal("Endpoint did not capture its exact current Secret identity/revision")
	}
}

func TestEndpointGettersAndBundleFreezeCurrentBindingMetadataWithoutPlaintext(t *testing.T) {
	st, created, secret := boundEndpointFixture(t)
	old := endpointFromBundle(t, st, created.ID)
	requireEndpointBinding(t, old, secret.ID, secret.Revision)
	for _, get := range []func() (*model.UpstreamEndpoint, error){
		func() (*model.UpstreamEndpoint, error) { return st.GetEndpoint(created.ID) },
		func() (*model.UpstreamEndpoint, error) {
			return st.Endpoint(context.Background(), created.UpstreamID, created.Kind)
		},
	} {
		ep, err := get()
		if err != nil {
			t.Fatal(err)
		}
		requireEndpointBinding(t, ep, secret.ID, secret.Revision)
		raw, err := json.Marshal(ep)
		if err != nil || strings.Contains(string(raw), "temporary-original-bound-auth-secret") || strings.Contains(string(raw), "BoundSecrets") || strings.Contains(string(raw), "bound_secrets") {
			t.Fatal("Endpoint DTO serialized private credential binding internals")
		}
	}
	updated, err := st.UpdateProbeSecret(secret.ID, secret.Revision, []byte("temporary-updated-bound-auth-secret"))
	if err != nil {
		t.Fatal(err)
	}
	fresh := endpointFromBundle(t, st, created.ID)
	requireEndpointBinding(t, fresh, secret.ID, updated.Revision)
	requireEndpointBinding(t, old, secret.ID, secret.Revision)
	values := (outbound.Values{Secrets: st}).WithBindings(old.BoundSecrets)
	if _, err := values.ResolveValue(context.Background(), "SECRET:bound-auth"); !errors.Is(err, outbound.ErrURLConfig) {
		t.Fatalf("old captured revision resolved a newer Secret: %v", err)
	}
	values = (outbound.Values{Secrets: st}).WithBindings(fresh.BoundSecrets)
	if value, err := values.ResolveValue(context.Background(), "SECRET:bound-auth"); err != nil || string(value.Plain) != "temporary-updated-bound-auth-secret" {
		t.Fatal("fresh captured revision could not resolve its own Secret")
	}
}

func TestEndpointOldBindingRejectsDeletedAndRecreatedName(t *testing.T) {
	st, ep, secret := boundEndpointFixture(t)
	old := endpointFromBundle(t, st, ep.ID)
	requireEndpointBinding(t, old, secret.ID, secret.Revision)
	ep.AuthProfile.SecretRef = "upstream_api_key"
	if err := st.UpdateEndpoint(ep, ep.Revision); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteProbeSecret(secret.ID, secret.Revision); err != nil {
		t.Fatal(err)
	}
	recreated, err := st.CreateProbeSecret(secret.Name, []byte("temporary-recreated-bound-auth-secret"))
	if err != nil || recreated.ID == secret.ID {
		t.Fatal("failed to recreate a distinct Secret identity")
	}
	ep.AuthProfile.SecretRef = "probe:bound-auth"
	if err := st.UpdateEndpoint(ep, ep.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := (outbound.Values{Secrets: st}).WithBindings(old.BoundSecrets).ResolveValue(context.Background(), "SECRET:bound-auth"); !errors.Is(err, outbound.ErrURLConfig) {
		t.Fatalf("old binding accepted a same-name new identity: %v", err)
	}
	fresh, err := st.GetEndpoint(ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	requireEndpointBinding(t, fresh, recreated.ID, recreated.Revision)
}

func TestAuthBindingStartupRepairRunsOnceAndNeverRebindsMissingMetadata(t *testing.T) {
	st, ep, secret := boundEndpointFixture(t)
	path := st.path
	if _, err := st.db.Exec(`DELETE FROM setting WHERE key='auth_secret_bindings_v1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DELETE FROM endpoint_active_secret_ref WHERE endpoint_id=?`, ep.ID); err != nil {
		t.Fatal(err)
	}
	st.Close()
	c, _ := NewCipher("test-passphrase-at-least-16-chars")
	first, err := Open(path, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { first.Close() })
	bound, err := first.GetEndpoint(ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	requireEndpointBinding(t, bound, secret.ID, secret.Revision)
	var marker int
	if err := first.db.QueryRow(`SELECT COUNT(*) FROM setting WHERE key='auth_secret_bindings_v1'`).Scan(&marker); err != nil || marker != 1 {
		t.Fatal("one-time Auth binding migration marker missing")
	}
	if _, err := first.db.Exec(`DELETE FROM endpoint_active_secret_ref WHERE endpoint_id=?`, ep.ID); err != nil {
		t.Fatal(err)
	}
	if err := first.DeleteProbeSecret(secret.ID, secret.Revision); err != nil {
		t.Fatal(err)
	}
	recreated, err := first.CreateProbeSecret(secret.Name, []byte("temporary-post-marker-recreated-secret"))
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	c, _ = NewCipher("test-passphrase-at-least-16-chars")
	second, err := Open(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	unbound, err := second.GetEndpoint(ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(unbound.BoundSecrets) != 0 {
		t.Fatal("restart silently bound a recreated same-name Secret after the migration marker")
	}
	if _, err := (outbound.Values{Secrets: second}).WithBindings(unbound.BoundSecrets).ResolveValue(context.Background(), "SECRET:bound-auth"); !errors.Is(err, outbound.ErrURLConfig) {
		t.Fatal("dirty missing binding did not fail closed")
	}
	if err := second.UpdateEndpoint(unbound, unbound.Revision); err != nil {
		t.Fatal(err)
	}
	rebound, err := second.GetEndpoint(ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	requireEndpointBinding(t, rebound, recreated.ID, recreated.Revision)
}

func TestMissingLegacyAuthSecretDoesNotBlockAdministrativeStartup(t *testing.T) {
	st, ep, secret := boundEndpointFixture(t)
	path := st.path
	if _, err := st.db.Exec(`DELETE FROM setting WHERE key='auth_secret_bindings_v1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DELETE FROM endpoint_active_secret_ref WHERE endpoint_id=?`, ep.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteProbeSecret(secret.ID, secret.Revision); err != nil {
		t.Fatal(err)
	}
	st.Close()
	c, _ := NewCipher("test-passphrase-at-least-16-chars")
	reopened, err := Open(path, c)
	if err != nil {
		t.Fatalf("unresolved legacy Auth stopped the management process: %v", err)
	}
	defer reopened.Close()
	unbound, err := reopened.GetEndpoint(ep.ID)
	if err != nil || len(unbound.BoundSecrets) != 0 {
		t.Fatal("missing legacy Secret was bound or hidden")
	}
}

func TestAuthBindingUpgradeInvalidatesOldSemanticsOnceWithoutReplacingBoundIdentity(t *testing.T) {
	st, ep, secret := boundEndpointFixture(t)
	ep.FixedQueryTemplate = "site_token={{SECRET:bound-auth}}"
	if err := st.UpdateEndpoint(ep, ep.Revision); err != nil {
		t.Fatal(err)
	}
	before, err := st.GetEndpoint(ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	token := func(currentStore *Store, endpoint *model.UpstreamEndpoint) string {
		t.Helper()
		tx, err := currentStore.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		current, err := currentSemanticRevision(context.Background(), tx, &model.SemanticExpectation{
			Target:         model.SemanticTarget{Scope: model.RecipeScopeUpstream, UpstreamID: endpoint.UpstreamID, Endpoint: endpoint.Kind},
			PolicySelector: model.EvidencePolicySelector{Kind: model.EvidenceL2, Endpoint: endpoint.Kind, TimeoutProfile: model.TimeoutL2Standard},
			Revision: model.SemanticRevision{
				RecipeIdentity:        model.RecipeIdentity{Storage: model.RecipeStorageEmbedded, Origin: model.RecipeBasic, TemplateID: "auth-upgrade-fixture", Revision: 1},
				RecipeBindingRevision: 1, ProbeSecrets: endpoint.BoundSecrets,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return revisioncodec.NewObservationToken(current)
	}
	oldToken := token(st, before)
	// The reference already existed through a query: SecretHash alone cannot
	// invalidate evidence made while Auth SecretRef was still ignored.
	if _, err := st.db.Exec(`DELETE FROM setting WHERE key=?`, authBindingUpgradeMarker); err != nil {
		t.Fatal(err)
	}
	path := st.path
	st.Close()
	c, _ := NewCipher("test-passphrase-at-least-16-chars")
	upgraded, err := Open(path, c)
	if err != nil {
		t.Fatal(err)
	}
	after, err := upgraded.GetEndpoint(ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	requireEndpointBinding(t, after, secret.ID, secret.Revision)
	if after.Revision != before.Revision+1 || after.AuthProfile.Revision != before.AuthProfile.Revision+1 || token(upgraded, after) == oldToken {
		t.Fatal("one-time upgrade kept evidence from the old ignored-Auth implementation current")
	}
	if revisioncodec.SecretRevisionSetHash(before.BoundSecrets) != revisioncodec.SecretRevisionSetHash(after.BoundSecrets) {
		t.Fatal("fixture changed the Secret set instead of proving the Auth revision invalidation")
	}
	upgradedToken := token(upgraded, after)
	upgraded.Close()
	c, _ = NewCipher("test-passphrase-at-least-16-chars")
	restarted, err := Open(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	again, err := restarted.GetEndpoint(ep.ID)
	if err != nil || again.Revision != after.Revision || again.AuthProfile.Revision != after.AuthProfile.Revision || token(restarted, again) != upgradedToken {
		t.Fatal("second restart repeated the Auth upgrade or changed its bound identity")
	}
}

func TestAuthBindingUpgradeNeverReplacesAnExistingMismatchedIdentity(t *testing.T) {
	st, ep, _ := boundEndpointFixture(t)
	other, err := st.CreateProbeSecret("different-name", []byte("temporary-different-bound-identity"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE endpoint_active_secret_ref SET secret_id=? WHERE endpoint_id=?`, other.ID, ep.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DELETE FROM setting WHERE key=?`, authBindingUpgradeMarker); err != nil {
		t.Fatal(err)
	}
	path := st.path
	st.Close()
	c, _ := NewCipher("test-passphrase-at-least-16-chars")
	reopened, err := Open(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	current, err := reopened.GetEndpoint(ep.ID)
	if err != nil || len(current.BoundSecrets) != 1 || current.BoundSecrets[0].ID != other.ID || current.BoundSecrets[0].Resolved {
		t.Fatal("one-time upgrade silently replaced a mismatched existing identity by its current name")
	}
}

func TestAuthBindingUpgradeDoesNotAuthorizeDirtyAuthFields(t *testing.T) {
	st, ep, _ := boundEndpointFixture(t)
	if _, err := st.db.Exec(`UPDATE upstream_endpoint SET auth_header_name=? WHERE id=?`, "X-Unsafe\r\nHeader", ep.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DELETE FROM endpoint_active_secret_ref WHERE endpoint_id=?`, ep.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DELETE FROM setting WHERE key=?`, authBindingUpgradeMarker); err != nil {
		t.Fatal(err)
	}
	path := st.path
	st.Close()
	c, _ := NewCipher("test-passphrase-at-least-16-chars")
	reopened, err := Open(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	current, err := reopened.GetEndpoint(ep.ID)
	if err != nil || len(current.BoundSecrets) != 0 || current.Revision != ep.Revision || current.AuthProfile.Revision != ep.AuthProfile.Revision {
		t.Fatal("dirty historical Auth fields acquired a binding or an executable upgrade")
	}
}
