package keyring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrNotInitialized means no keyring file exists yet.
var ErrNotInitialized = errors.New("keyring not initialized")

// File is the on-disk Master Key root (§12.4).
//
// Permissions: parent dir 0700, file 0600. Master Key is never stored in SQLite.
type File struct {
	mu   sync.Mutex
	path string
}

type document struct {
	FormatVersion int            `json:"format_version"`
	KeyID         string         `json:"key_id"`
	Active        string         `json:"active"`
	Pending       string         `json:"pending,omitempty"`
	UpdatedAt     string         `json:"updated_at"`
	History       []historyEntry `json:"history,omitempty"`
	Phase         RotationPhase  `json:"phase,omitempty"`
	RotationID    string         `json:"rotation_id,omitempty"`
}

type historyEntry struct {
	At     string `json:"at"`
	Action string `json:"action"`
	KeyID  string `json:"key_id"`
}

// Open returns a File handle rooted at dataDir/secrets/keyring.json.
func Open(dataDir string) *File {
	return &File{path: filepath.Join(dataDir, "secrets", "keyring.json")}
}

// Path returns the absolute keyring path.
func (f *File) Path() string { return f.path }

// EnsureInitialized creates a keyring with masterKey if missing.
func (f *File) EnsureInitialized(keyID, masterKey string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := os.Lstat(f.path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	doc := document{
		FormatVersion: 1,
		KeyID:         keyID,
		Active:        masterKey,
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		History: []historyEntry{{
			At: time.Now().UTC().Format(time.RFC3339Nano), Action: "bootstrap", KeyID: keyID,
		}},
	}
	return f.writeLocked(doc)
}

// LoadActive returns key_id and active master key plaintext.
func (f *File) LoadActive() (keyID, master string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.readLocked()
	if err != nil {
		return "", "", err
	}
	if doc.Active == "" || doc.KeyID == "" {
		return "", "", fmt.Errorf("%w: empty active key", ErrNotInitialized)
	}
	return doc.KeyID, doc.Active, nil
}

func (f *File) readLocked() (document, error) {
	raw, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return document{}, ErrNotInitialized
	}
	if err != nil {
		return document{}, err
	}
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return document{}, fmt.Errorf("parse keyring: %w", err)
	}
	return doc, nil
}

func (f *File) writeLocked(doc document) error {
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := f.path + ".tmp"
	_ = os.Remove(tmp)
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, f.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Chmod(filepath.Dir(f.path), 0o700)
	return nil
}
