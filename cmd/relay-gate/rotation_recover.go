package main

import (
	"context"
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
	if st.Phase == keyring.PhasePrepared || st.Phase == keyring.PhaseDBCommitted || st.Phase == keyring.PhaseKeyActivated {
		dbRID, err = store.CommittedMasterRotation(dbPath)
		if err != nil {
			return true, st, fmt.Errorf("读取 SQLite rotation_id: %w", err)
		}
	}
	rollForward := st.RotationID != "" && st.RotationID == dbRID
	return kr.RecoverUnfinishedValidated(dbRID, func(master string) error {
		if err := store.ValidateDatabaseEncryption(context.Background(), dbPath, master); err != nil {
			return err
		}
		current, err := kr.Status()
		if err != nil {
			return err
		}
		if rollForward && current.HasPending {
			if err := resealPersistedRelayUnderPending(kr, dataDir); err != nil {
				return err
			}
		}
		return verifyPersistedRelayMaster(dataDir, master)
	})
}

func verifyPersistedRelayMaster(dataDir, master string) error {
	doc, err := credential.LoadPersistedFile(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if doc.RelayKey == "" || !credential.IsRelayKeyEnvelope(doc.RelayKey) {
		return nil
	}
	cipher, err := store.NewCipher(master)
	if err != nil {
		return err
	}
	if _, err := credential.OpenPersistedRelayKey(doc.RelayKey, cipher); err != nil {
		return fmt.Errorf("持久 Relay Key 与候选 Master Key 不匹配: %w", err)
	}
	return nil
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
	if doc.RelayKey == "" {
		return nil
	}
	pending, err := kr.LoadPending()
	if err != nil {
		return err
	}
	if !credential.IsRelayKeyEnvelope(doc.RelayKey) {
		sealed, err := store.SealEnvelopeUnder(pending, doc.RelayKey)
		if err != nil {
			return err
		}
		return credential.ReplacePersistedRelayKey(dataDir, sealed)
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
