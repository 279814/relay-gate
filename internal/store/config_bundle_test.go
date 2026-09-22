package store

import (
	"context"
	"testing"
)

func TestLoadConfigBundle_AtomicSameGenerationRows(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "bundle")
	bundle, err := store.LoadConfigBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Upstreams) == 0 {
		t.Fatal("expected upstreams")
	}
	found := false
	for _, up := range bundle.Upstreams {
		if up.ID == upstream.ID {
			found = true
			if up.APIKey == "" {
				t.Fatal("routing bundle must decrypt api key for outbound")
			}
			if up.NetworkRevision != upstream.NetworkRevision {
				t.Fatalf("network revision=%d", up.NetworkRevision)
			}
		}
	}
	if !found {
		t.Fatal("upstream missing from bundle")
	}
	if len(bundle.Endpoints) == 0 {
		t.Fatal("endpoints should be materialized with upstream")
	}
	if bundle.SecretRevisions == nil {
		t.Fatal("secret revisions map must be non-nil")
	}
}
