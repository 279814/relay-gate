package keyring

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// RotationPhase tracks Master Key rotation (§12.7).
type RotationPhase string

const (
	PhaseIdle         RotationPhase = ""
	PhasePrepared     RotationPhase = "prepared"
	PhaseDBCommitted  RotationPhase = "db_committed"
	PhaseKeyActivated RotationPhase = "key_activated"
	PhaseCleaned      RotationPhase = "cleaned"
)

// Status is a non-secret snapshot of the keyring.
type Status struct {
	KeyID         string        `json:"key_id"`
	HasPending    bool          `json:"has_pending"`
	Phase         RotationPhase `json:"phase"`
	RotationID    string        `json:"rotation_id,omitempty"`
	FormatVersion int           `json:"format_version"`
}

// Status returns key metadata without exposing key material.
func (f *File) Status() (Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.readLocked()
	if err != nil {
		return Status{}, err
	}
	return Status{
		KeyID: doc.KeyID, HasPending: doc.Pending != "",
		Phase: doc.Phase, RotationID: doc.RotationID,
		FormatVersion: doc.FormatVersion,
	}, nil
}

// BeginRotation writes pending key + rotation_id at phase=prepared (§12.7 step 6).
func (f *File) BeginRotation(newMaster string) (rotationID string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.readLocked()
	if err != nil {
		return "", err
	}
	if doc.Phase != PhaseIdle && doc.Phase != PhaseCleaned && doc.Phase != "" {
		return "", fmt.Errorf("rotation already in progress: %s", doc.Phase)
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	rotationID = hex.EncodeToString(buf)
	newID := "mk_" + rotationID[:12]
	doc.Pending = newMaster
	doc.Phase = PhasePrepared
	doc.RotationID = rotationID
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	doc.History = append(doc.History, historyEntry{
		At: doc.UpdatedAt, Action: "rotate_prepared", KeyID: newID,
	})
	if err := f.writeLocked(doc); err != nil {
		return "", err
	}
	return rotationID, nil
}

// MarkDBCommitted advances prepared → db_committed after SQLite re-encrypt.
func (f *File) MarkDBCommitted(rotationID string) error {
	return f.advance(rotationID, PhasePrepared, PhaseDBCommitted, "rotate_db_committed")
}

// ActivatePending promotes pending to active (db_committed → key_activated).
func (f *File) ActivatePending(rotationID string) (newKeyID string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.readLocked()
	if err != nil {
		return "", err
	}
	if doc.RotationID != rotationID || doc.Phase != PhaseDBCommitted {
		return "", fmt.Errorf("cannot activate: phase=%s rotation=%s", doc.Phase, doc.RotationID)
	}
	if doc.Pending == "" {
		return "", fmt.Errorf("no pending key")
	}
	newKeyID = "mk_" + rotationID[:12]
	doc.Active = doc.Pending
	doc.KeyID = newKeyID
	doc.Pending = ""
	doc.Phase = PhaseKeyActivated
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	doc.History = append(doc.History, historyEntry{
		At: doc.UpdatedAt, Action: "rotate_key_activated", KeyID: newKeyID,
	})
	return newKeyID, f.writeLocked(doc)
}

// MarkCleaned finishes rotation (key_activated → cleaned) after full verify.
func (f *File) MarkCleaned(rotationID string) error {
	return f.advance(rotationID, PhaseKeyActivated, PhaseCleaned, "rotate_cleaned")
}

// AbortPrepared drops pending when still at prepared (DB not committed).
func (f *File) AbortPrepared(rotationID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.readLocked()
	if err != nil {
		return err
	}
	if doc.RotationID != rotationID || doc.Phase != PhasePrepared {
		return fmt.Errorf("cannot abort: phase=%s", doc.Phase)
	}
	doc.Pending = ""
	doc.Phase = PhaseIdle
	doc.RotationID = ""
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	doc.History = append(doc.History, historyEntry{
		At: doc.UpdatedAt, Action: "rotate_aborted", KeyID: doc.KeyID,
	})
	return f.writeLocked(doc)
}

// RecoverUnfinished inspects a clean keyring without a database verifier.
// Incomplete rotations fail closed; production recovery supplies the committed
// database rotation ID and real validator to RecoverUnfinishedValidated.
func (f *File) RecoverUnfinished() (holdMaintenance bool, st Status, err error) {
	return f.RecoverUnfinishedAgainst("")
}

// RecoverUnfinishedAgainst retains the original entry point, but incomplete
// rotations now require RecoverUnfinishedValidated and a real database verifier.
func (f *File) RecoverUnfinishedAgainst(dbRotationID string) (holdMaintenance bool, st Status, err error) {
	return f.RecoverUnfinishedValidated(dbRotationID, nil)
}

// RecoverUnfinishedValidated advances only after the matching master has opened
// every protected database value. The callback runs without the keyring mutex:
// database validation must not hold a filesystem/state lock across SQLite I/O.
// The data-directory instance lock and maintenance admission fence remain the
// caller's responsibility. Failures retain the last recoverable journal phase.
func (f *File) RecoverUnfinishedValidated(dbRotationID string, verify func(master string) error) (holdMaintenance bool, st Status, err error) {
	st, err = f.Status()
	if err != nil {
		return false, Status{}, err
	}
	if st.Phase == PhaseIdle || st.Phase == PhaseCleaned {
		return false, st, nil
	}
	if verify == nil {
		return true, st, fmt.Errorf("unfinished rotation requires encrypted-state verification")
	}
	if st.Phase == PhasePrepared && st.RotationID != dbRotationID {
		_, active, err := f.LoadActive()
		if err != nil {
			return true, st, err
		}
		if err := verify(active); err != nil {
			return true, st, fmt.Errorf("verify uncommitted rotation: %w", err)
		}
		if err := f.AbortPrepared(st.RotationID); err != nil {
			return true, st, err
		}
		st, err = f.Status()
		return err != nil, st, err
	}
	if st.RotationID == "" || st.RotationID != dbRotationID {
		return true, st, fmt.Errorf("keyring and database rotation IDs do not match")
	}
	if st.Phase == PhasePrepared || st.Phase == PhaseDBCommitted {
		pending, err := f.LoadPending()
		if err != nil {
			return true, st, err
		}
		if err := verify(pending); err != nil {
			return true, st, fmt.Errorf("verify committed rotation before activation: %w", err)
		}
		if st.Phase == PhasePrepared {
			if err := f.MarkDBCommitted(st.RotationID); err != nil {
				return true, st, err
			}
			st.Phase = PhaseDBCommitted
		}
		if _, err := f.ActivatePending(st.RotationID); err != nil {
			return true, st, err
		}
		st, err = f.Status()
		if err != nil {
			return true, Status{}, err
		}
	}
	if st.Phase == PhaseKeyActivated {
		_, active, err := f.LoadActive()
		if err != nil {
			return true, st, err
		}
		if err := verify(active); err != nil {
			return true, st, fmt.Errorf("verify active rotation before cleanup: %w", err)
		}
		if err := f.MarkCleaned(st.RotationID); err != nil {
			return true, st, err
		}
		st, err = f.Status()
		return err != nil, st, err
	}
	return true, st, fmt.Errorf("unsupported rotation phase %q", st.Phase)
}

// LoadPending returns the pending master key during rotation.
func (f *File) LoadPending() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.readLocked()
	if err != nil {
		return "", err
	}
	if doc.Pending == "" {
		return "", fmt.Errorf("no pending key")
	}
	return doc.Pending, nil
}

func (f *File) advance(rotationID string, from, to RotationPhase, action string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.readLocked()
	if err != nil {
		return err
	}
	if doc.RotationID != rotationID || doc.Phase != from {
		return fmt.Errorf("cannot advance %s→%s: phase=%s rotation=%s", from, to, doc.Phase, doc.RotationID)
	}
	doc.Phase = to
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	doc.History = append(doc.History, historyEntry{
		At: doc.UpdatedAt, Action: action, KeyID: doc.KeyID,
	})
	if to == PhaseCleaned {
		doc.RotationID = ""
	}
	return f.writeLocked(doc)
}
