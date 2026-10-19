package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestDiagnosticKeysReadOnlyCredentialsWithoutPageOrConfigurationDefaults(t *testing.T) {
	st := testStore(t)
	for i := 1; i <= 205; i++ {
		metadataSite(t, st, fmt.Sprintf("diagnostic-key-%03d", i))
	}
	if _, err := st.db.Exec(`UPDATE upstream SET enabled=0,probe_headers='bad-json',base_url='invalid-url' WHERE id=205`); err != nil {
		t.Fatal(err)
	}
	keys, err := st.DiagnosticRedactionKeys(context.Background())
	if err != nil || len(keys) != 205 {
		t.Fatalf("complete credential set size=%d err=%v", len(keys), err)
	}
	for _, key := range keys {
		if key != "metadata-credential-never-selected" {
			t.Fatal("credential command did not decrypt the selected credential column")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := st.DiagnosticRedactionKeys(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled credential read=%v", err)
	}
	if _, err := st.db.Exec(`UPDATE upstream SET api_key_enc='broken-envelope' WHERE id=205`); err != nil {
		t.Fatal(err)
	}
	if partial, err := st.DiagnosticRedactionKeys(context.Background()); err == nil || partial != nil {
		t.Fatal("unreadable credential returned a partial redaction set")
	}
}

func TestDiagnosticKeysIncludeCurrentProbeSecretsAndRejectPartialSets(t *testing.T) {
	for _, invalid := range []string{"", "corrupt", "short"} {
		t.Run("probe-secret-"+invalid, func(t *testing.T) {
			st := testStore(t)
			metadataSite(t, st, "diagnostic-site")
			const plain = "synthetic-current-probe-secret"
			secret, err := st.CreateProbeSecret("diagnostic-probe", []byte(plain))
			if err != nil {
				t.Fatal(err)
			}
			keys, err := st.DiagnosticRedactionKeys(context.Background())
			found := false
			for _, key := range keys {
				found = found || key == plain
			}
			if err != nil || len(keys) != 2 || !found {
				t.Fatal("current ProbeSecret missing from complete diagnostic credential set")
			}
			if invalid == "" {
				return
			}
			if invalid == "short" {
				if _, err := st.UpdateProbeSecret(secret.ID, secret.Revision, []byte("short-key")); err != nil {
					t.Fatal(err)
				}
			} else if _, err := st.db.Exec(`UPDATE probe_secret SET value_enc='broken-envelope' WHERE id=?`, secret.ID); err != nil {
				t.Fatal(err)
			}
			if partial, err := st.DiagnosticRedactionKeys(context.Background()); err == nil || partial != nil {
				t.Fatal("invalid ProbeSecret returned partial diagnostic keys")
			}
		})
	}
}
