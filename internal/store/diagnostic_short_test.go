package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestDiagnosticKeyReadRejectsHistoricalUnredactableCredential(t *testing.T) {
	st := testStore(t)
	up := metadataSite(t, st, "diagnostic-historical-short")
	for _, length := range []int{model.MinRedactableKeyLen - 1, model.MinRedactableKeyLen} {
		key := strings.Repeat("x", length)
		encrypted, err := st.cipher.Encrypt(key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.Exec(`UPDATE upstream SET api_key_enc=? WHERE id=?`, encrypted, up.ID); err != nil {
			t.Fatal(err)
		}
		keys, err := st.DiagnosticRedactionKeys(context.Background())
		if length < model.MinRedactableKeyLen {
			if !errors.Is(err, model.ErrValidation) || keys != nil {
				t.Fatal("historical short credential was accepted although diagnostic redaction ignores it")
			}
			if strings.Contains(err.Error(), key) {
				t.Fatal("short credential leaked through error")
			}
		} else if err != nil || len(keys) != 1 || keys[0] != key {
			t.Fatal("redactable boundary credential was rejected")
		}
	}
}
