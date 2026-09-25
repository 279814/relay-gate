package keyring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

func (f *File) previousPath() string {
	return filepath.Join(filepath.Dir(f.path), "keyring.previous")
}

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
	dir := filepath.Dir(f.path)

	// Write + file fsync the new document first. If this fails, current and
	// keyring.previous stay untouched (§12.7).
	tmp := f.path + ".tmp"
	_ = os.Remove(tmp)
	if err := writeSyncedFile(tmp, raw, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	// Promote a verified copy of the current file to keyring.previous before
	// the atomic rename of the new document.
	if err := f.preservePreviousLocked(); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	if err := os.Rename(tmp, f.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Chmod(dir, 0o700)
	return syncDirectory(dir)
}

// preservePreviousLocked copies the current keyring to keyring.previous only
// after it parses successfully. A later failed write leaves current and this
// previous copy intact.
func (f *File) preservePreviousLocked() error {
	raw, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("verify keyring before previous: %w", err)
	}
	prev := f.previousPath()
	tmp := prev + ".tmp"
	_ = os.Remove(tmp)
	if err := writeSyncedFile(tmp, raw, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, prev); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDirectory(filepath.Dir(f.path))
}

func writeSyncedFile(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	// File fsync before rename (§12.7).
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	// Directory fsync after rename (§12.7). Windows may not support it; the
	// file Sync above still runs. Skip Sync errors only on Windows.
	if err := directory.Sync(); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return nil
}
