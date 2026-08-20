package store

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestProbeSecretCRUDNeverListsCiphertextAndUsesRevisionCAS(t *testing.T) {
	store := testStore(t)
	secret, err := store.CreateProbeSecret("tenant_token", []byte("very-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	if secret.Revision != 1 || secret.Masked == "very-secret-value" || secret.Fingerprint == "" {
		t.Fatalf("secret metadata = %+v", secret)
	}
	page, err := store.ListProbeSecretsPage(context.Background(), model.ProbeSecretFilter{NamePrefix: "tenant"})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("list = %+v err=%v", page, err)
	}
	resolved, err := store.ResolveProbeSecret(context.Background(), "tenant_token")
	if err != nil || !bytes.Equal(resolved.Plain, []byte("very-secret-value")) || resolved.ID != secret.ID {
		t.Fatalf("resolved = %+v err=%v", resolved, err)
	}
	updated, err := store.UpdateProbeSecret(secret.ID, 1, []byte("rotated-secret-value"))
	if err != nil || updated.Revision != 2 || updated.Fingerprint == secret.Fingerprint {
		t.Fatalf("updated = %+v err=%v", updated, err)
	}
	if _, err := store.UpdateProbeSecret(secret.ID, 1, []byte("stale")); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale update = %v", err)
	}
}

func TestRecipeVersionIsImmutableAndSecretBindingDoesNotReattachByName(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "recipe-upstream")
	secret, err := store.CreateProbeSecret("custom_auth", []byte("secret-one"))
	if err != nil {
		t.Fatal(err)
	}
	recipeID, err := store.CreateRecipe(model.RecipeScopeUpstream, upstream.ID, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	version := &model.ProbeRecipeVersion{
		RecipeID: recipeID, Origin: model.RecipeManual, Method: "GET",
		Headers:        []model.HeaderTemplate{{Name: "X-Custom-Auth", Values: []string{"{{SECRET:custom_auth}}"}}},
		TimeoutProfile: model.TimeoutL1,
	}
	if err := store.AddRecipeVersion(version, 1); err != nil {
		t.Fatal(err)
	}
	if version.ID == 0 || version.Version != 1 {
		t.Fatalf("version = %+v", version)
	}
	var boundID, boundRevision int64
	if err := store.db.QueryRow(`SELECT bound_secret_id_snapshot,bound_revision_snapshot
		FROM recipe_version_required_secret WHERE recipe_version_id=? AND name='custom_auth'`, version.ID).
		Scan(&boundID, &boundRevision); err != nil {
		t.Fatal(err)
	}
	if boundID != secret.ID || boundRevision != 1 {
		t.Fatalf("bound secret = %d/%d", boundID, boundRevision)
	}
	if _, err := store.db.Exec(`UPDATE probe_recipe_version SET method='HEAD' WHERE id=?`, version.ID); err == nil {
		t.Fatal("immutable version UPDATE succeeded")
	}
	if _, err := store.db.Exec(`DELETE FROM probe_recipe_version WHERE id=?`, version.ID); err == nil {
		t.Fatal("immutable version DELETE succeeded")
	}
	if err := store.DeleteProbeSecret(secret.ID, 1); err != nil {
		t.Fatalf("draft-only historical ref should not block delete: %v", err)
	}
	recreated, err := store.CreateProbeSecret("custom_auth", []byte("secret-two"))
	if err != nil {
		t.Fatal(err)
	}
	if recreated.ID == secret.ID {
		t.Fatal("SQLite reused secret identity")
	}
	var resolvedID *int64
	if err := store.db.QueryRow(`SELECT resolved_secret_id FROM recipe_version_required_secret
		WHERE recipe_version_id=? AND name='custom_auth'`, version.ID).Scan(&resolvedID); err != nil {
		t.Fatal(err)
	}
	if resolvedID != nil {
		t.Fatalf("same-name recreation reattached old version to id=%d", *resolvedID)
	}
}

func TestArchivedRecipeAllowsNewBindingWithoutDeletingHistory(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "archive-recipe")
	first, err := store.CreateRecipe(model.RecipeScopeUpstream, upstream.ID, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ArchiveRecipe(context.Background(), first, 1); err != nil {
		t.Fatal(err)
	}
	second, err := store.CreateRecipe(model.RecipeScopeUpstream, upstream.ID, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("new binding reused archived identity")
	}
	if _, err := store.GetRecipe(context.Background(), first); err != nil {
		t.Fatalf("archived history disappeared: %v", err)
	}
}
