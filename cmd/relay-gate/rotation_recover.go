package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/store"
)

// recoverMasterRotation applies §12.7 startup recovery before the Store and
// live Cipher exist. prepared rolls forward instead of aborting when SQLite
// already committed the same rotation_id; the persisted Relay Key envelope is
// resealed under pending first so activation never leaves it openable only by
// the retired key.
func recoverMasterRotation(dataDir, dbPath string) (bool, keyring.Status, error) {
	kr := keyring.Open(dataDir)
	st, err := kr.Status()
	if err != nil {
		return false, keyring.Status{}, err
	}
	var dbRID string
	if st.Phase == keyring.PhasePrepared || st.Phase == keyring.PhaseDBCommitted {
		dbRID, err = store.CommittedMasterRotation(dbPath)
		if err != nil {
			return true, st, fmt.Errorf("读取 SQLite rotation_id: %w", err)
		}
		if st.Phase == keyring.PhaseDBCommitted || (st.RotationID != "" && st.RotationID == dbRID) {
			if err := resealPersistedRelayUnderPending(kr, dataDir); err != nil {
				return true, st, err
			}
		}
	}
	return kr.RecoverUnfinishedAgainst(dbRID)
}

// resealPersistedRelayUnderPending rewrites bootstrap-credentials.json's
// relay_key under the pending master when it still opens only under the
// active one. Idempotent; never logs key material.
func resealPersistedRelayUnderPending(kr *keyring.File, dataDir string) error {
	doc, err := credential.LoadPersistedFile(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !credential.IsRelayKeyEnvelope(doc.RelayKey) {
		return nil
	}
	pending, err := kr.LoadPending()
	if err != nil {
		return err
	}
	next, err := store.NewCipher(pending)
	if err != nil {
		return err
	}
	if _, err := credential.OpenPersistedRelayKey(doc.RelayKey, next); err == nil {
		return nil
	}
	_, active, err := kr.LoadActive()
	if err != nil {
		return err
	}
	prev, err := store.NewCipher(active)
	if err != nil {
		return err
	}
	plain, err := credential.OpenPersistedRelayKey(doc.RelayKey, prev)
	if err != nil {
		return fmt.Errorf("Relay Key 信封在新旧 Master Key 下均无法打开: %w", err)
	}
	enc, err := store.SealEnvelopeUnder(pending, plain)
	if err != nil {
		return err
	}
	return credential.ReplacePersistedRelayKey(dataDir, enc)
}
