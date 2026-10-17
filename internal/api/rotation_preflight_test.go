package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/store"
)

func TestMasterRotation_RejectsInvalidPersistedRelayBeforeBackupOrPreparation(t *testing.T) {
	for _, damage := range []string{"invalid-json", "null-json", "wrong-master", "corrupt-envelope", "plaintext"} {
		t.Run(damage, func(t *testing.T) {
			s, h, session, keys := newRotationFixture(t)
			directory := filepath.Dir(s.st.DatabasePath())
			path := credential.CredentialsFile(directory)
			var invalid []byte
			if damage == "invalid-json" {
				invalid = []byte("invalid")
			} else if damage == "null-json" {
				invalid = []byte("null")
			} else {
				doc, err := credential.LoadPersistedFile(directory)
				if err != nil {
					t.Fatal(err)
				}
				doc.RelayKey = "v1:damaged:AAAA"
				if damage == "plaintext" {
					doc.RelayKey = "rk-plaintext-not-valid-for-online-rotation"
				} else if damage == "wrong-master" {
					doc.RelayKey, err = store.SealEnvelopeUnder("unrelated-persisted-master-long-enough", "rk-persisted-relay-fixture")
					if err != nil {
						t.Fatal(err)
					}
				}
				invalid, err = json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, invalid, 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(keys.Path())
			if err != nil {
				t.Fatal(err)
			}
			response := doSession(t, h, http.MethodPost, "/admin/api/credentials/rotate-master",
				`{"password":"`+testAdminPW+`","new_master":"new-master-must-not-commit"}`, session)
			if response.Code != http.StatusInternalServerError {
				t.Errorf("invalid persisted relay accepted: HTTP %d", response.Code)
			}
			status, err := keys.Status()
			if err != nil || status.Phase != keyring.PhaseIdle || status.HasPending || s.runState.InMaintenance() {
				t.Errorf("preflight failure advanced rotation or retained maintenance: phase=%s err=%v", status.Phase, err)
			}
			rid, err := store.CommittedMasterRotation(s.st.DatabasePath())
			if err != nil || rid != "" {
				t.Errorf("preflight failure committed database rotation: %v", err)
			}
			after, err := os.ReadFile(keys.Path())
			if err != nil || !bytes.Equal(before, after) {
				t.Error("preflight failure changed keyring")
			}
			credentials, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(credentials, invalid) {
				t.Error("preflight failure silently replaced damaged persisted credentials")
			}
			if _, err := os.Stat(filepath.Join(directory, "backups")); !os.IsNotExist(err) {
				t.Error("invalid source credentials were archived before preflight")
			}
			if err := s.st.ValidateEncryptedState(); err != nil {
				t.Errorf("preflight failure changed database encryption: %v", err)
			}
		})
	}
}
