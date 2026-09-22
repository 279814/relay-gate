package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSchemaFiveLegacyVariants(t *testing.T) {
	cipher, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []legacySchemaVariant{
		legacySchemaM2, legacySchemaM6PreColumn, legacySchemaM6PreIndex, legacySchemaM6Current,
	} {
		t.Run(string(variant), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "legacy.db")
			legacy := openDatabaseAtPath(t, path)
			loadLegacyVariantFixture(t, legacy, variant)
			_ = legacy.Close()
			st, err := Open(path, cipher)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			state, err := inspectSchemaState(context.Background(), st.db)
			if err != nil {
				t.Fatal(err)
			}
			if state.Version != 5 {
				t.Fatalf("version=%d fp=%s", state.Version, state.Fingerprint)
			}
			t.Logf("fp=%s", state.Fingerprint)
		})
	}
}
