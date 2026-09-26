package credential

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/279814/relay-gate/internal/keyring"
)

// Bootstrap phases (§12.3).
const (
	PhasePrepared             = "prepared"
	PhaseCredentialsPersisted = "credentials_persisted"
	PhaseDisplayed            = "displayed"
)

var (
	// ErrBootstrapComplete means credentials were already delivered (displayed).
	ErrBootstrapComplete = errors.New("凭据已交付；长期服务不得重复输出")
	// ErrBootstrapIncomplete tells the long-running server to refuse start.
	ErrBootstrapIncomplete = errors.New("凭据未完成 bootstrap；请运行: relay-gate credentials bootstrap")
)

// CrashPoint injects a crash after a named phase for tests.
type CrashPoint string

const (
	CrashAfterPrepared             CrashPoint = "after_prepared"
	CrashAfterCredentialsPersisted CrashPoint = "after_credentials_persisted"
)

// Displayed is the one-time plaintext triple shown to the operator.
type Displayed struct {
	AdminPassword string
	RelayKey      string
	MasterKey     string
	MasterKeyID   string
}

type journalDoc struct {
	FormatVersion int    `json:"format_version"`
	Phase         string `json:"phase"`
	MasterKeyID   string `json:"master_key_id,omitempty"`
	UpdatedAt     string `json:"updated_at"`
}

// Bootstrap owns the data-dir exclusive journal for first credentials (§12.3).
type Bootstrap struct {
	DataDir string
	Out     io.Writer // where plaintext credentials are printed (usually stdout)
	Now     func() time.Time
	// CrashAfter is test-only; production must leave empty.
	CrashAfter CrashPoint
}

func (b *Bootstrap) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func (b *Bootstrap) secretsDir() string {
	return SecretsDir(b.DataDir)
}

func (b *Bootstrap) journalPath() string {
	return filepath.Join(b.secretsDir(), "credentials-bootstrap.journal")
}

func (b *Bootstrap) credentialsPath() string {
	return CredentialsFile(b.DataDir)
}

// Phase returns the current journal phase, or empty if no journal.
func (b *Bootstrap) Phase() (string, error) {
	doc, err := b.readJournal()
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return doc.Phase, nil
}

// Completed reports whether bootstrap reached displayed.
func (b *Bootstrap) Completed() (bool, error) {
	phase, err := b.Phase()
	if err != nil {
		return false, err
	}
	return phase == PhaseDisplayed, nil
}

// Run executes or resumes credentials bootstrap.
//
// Recovery (§12.3): if credentials_persisted but not displayed, revoke the
// undelivered admin password and Relay Key, keep Master Key, regenerate the
// two, persist, and print all three again.
func (b *Bootstrap) Run() (Displayed, error) {
	if b.DataDir == "" {
		return Displayed{}, errors.New("需要 data 目录")
	}
	if b.Out == nil {
		b.Out = io.Discard
	}
	if err := ensureSecretsDir(b.DataDir); err != nil {
		return Displayed{}, err
	}
	unlock, err := b.acquireLock()
	if err != nil {
		return Displayed{}, err
	}
	defer unlock()

	phase, err := b.Phase()
	if err != nil {
		return Displayed{}, err
	}
	switch phase {
	case PhaseDisplayed:
		return Displayed{}, ErrBootstrapComplete
	case PhaseCredentialsPersisted:
		return b.resumeUndelivered()
	case PhasePrepared, "":
		return b.freshInstall()
	default:
		return Displayed{}, fmt.Errorf("未知 bootstrap 阶段 %q", phase)
	}
}

func (b *Bootstrap) freshInstall() (Displayed, error) {
	if err := b.writeJournal(journalDoc{
		FormatVersion: 1,
		Phase:         PhasePrepared,
		UpdatedAt:     b.now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return Displayed{}, err
	}
	if b.CrashAfter == CrashAfterPrepared {
		return Displayed{}, errInjectedCrash
	}

	admin, err := randomHex(24)
	if err != nil {
		return Displayed{}, err
	}
	relay, err := randomRelayKey()
	if err != nil {
		return Displayed{}, err
	}
	master, err := randomHex(32)
	if err != nil {
		return Displayed{}, err
	}
	keyID := masterKeyID(master)

	kr := keyring.Open(b.DataDir)
	if err := kr.EnsureInitialized(keyID, master); err != nil {
		return Displayed{}, fmt.Errorf("写入 keyring: %w", err)
	}
	// If keyring already existed from a prior prepared crash, keep its master.
	if id, existing, loadErr := kr.LoadActive(); loadErr == nil && existing != "" {
		master = existing
		keyID = id
	}

	hash, err := HashAdminPassword(admin)
	if err != nil {
		return Displayed{}, err
	}
	if err := b.writeCredentials(Persisted{
		FormatVersion:     1,
		AdminPasswordHash: hash,
		RelayKey:          relay,
		MasterKeyID:       keyID,
		UpdatedAt:         b.now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return Displayed{}, err
	}
	if err := b.writeJournal(journalDoc{
		FormatVersion: 1,
		Phase:         PhaseCredentialsPersisted,
		MasterKeyID:   keyID,
		UpdatedAt:     b.now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return Displayed{}, err
	}
	if b.CrashAfter == CrashAfterCredentialsPersisted {
		return Displayed{}, errInjectedCrash
	}
	return b.display(Displayed{
		AdminPassword: admin,
		RelayKey:      relay,
		MasterKey:     master,
		MasterKeyID:   keyID,
	})
}

func (b *Bootstrap) resumeUndelivered() (Displayed, error) {
	kr := keyring.Open(b.DataDir)
	keyID, master, err := kr.LoadActive()
	if err != nil {
		return Displayed{}, fmt.Errorf("恢复 Master Key: %w", err)
	}

	admin, err := randomHex(24)
	if err != nil {
		return Displayed{}, err
	}
	relay, err := randomRelayKey()
	if err != nil {
		return Displayed{}, err
	}
	hash, err := HashAdminPassword(admin)
	if err != nil {
		return Displayed{}, err
	}
	if err := b.writeCredentials(Persisted{
		FormatVersion:     1,
		AdminPasswordHash: hash,
		RelayKey:          relay,
		MasterKeyID:       keyID,
		UpdatedAt:         b.now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return Displayed{}, err
	}
	if err := b.writeJournal(journalDoc{
		FormatVersion: 1,
		Phase:         PhaseCredentialsPersisted,
		MasterKeyID:   keyID,
		UpdatedAt:     b.now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return Displayed{}, err
	}
	if b.CrashAfter == CrashAfterCredentialsPersisted {
		return Displayed{}, errInjectedCrash
	}
	return b.display(Displayed{
		AdminPassword: admin,
		RelayKey:      relay,
		MasterKey:     master,
		MasterKeyID:   keyID,
	})
}

func (b *Bootstrap) display(d Displayed) (Displayed, error) {
	fmt.Fprintf(b.Out, "ADMIN_PASSWORD=%s\n", d.AdminPassword)
	fmt.Fprintf(b.Out, "RELAY_KEYS=%s\n", d.RelayKey)
	fmt.Fprintf(b.Out, "ENCRYPTION_KEY=%s\n", d.MasterKey)
	fmt.Fprintf(b.Out, "# 以上三项只显示一次。长期容器不得重复输出。\n")
	if err := b.writeJournal(journalDoc{
		FormatVersion: 1,
		Phase:         PhaseDisplayed,
		MasterKeyID:   d.MasterKeyID,
		UpdatedAt:     b.now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return Displayed{}, err
	}
	return d, nil
}

// LoadPersisted returns the delivered credential material for long-running start.
func (b *Bootstrap) LoadPersisted() (Persisted, error) {
	ok, err := b.Completed()
	if err != nil {
		return Persisted{}, err
	}
	if !ok {
		return Persisted{}, ErrBootstrapIncomplete
	}
	doc, err := LoadPersistedFile(b.DataDir)
	if err != nil {
		return Persisted{}, err
	}
	if doc.AdminPasswordHash == "" || doc.RelayKey == "" {
		return Persisted{}, ErrBootstrapIncomplete
	}
	return doc, nil
}

var errInjectedCrash = errors.New("injected bootstrap crash")

func (b *Bootstrap) readJournal() (journalDoc, error) {
	raw, err := os.ReadFile(b.journalPath())
	if err != nil {
		return journalDoc{}, err
	}
	var doc journalDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return journalDoc{}, fmt.Errorf("解析 bootstrap journal: %w", err)
	}
	return doc, nil
}

func (b *Bootstrap) writeJournal(doc journalDoc) error {
	return writeJSON0600(b.journalPath(), doc)
}

func (b *Bootstrap) writeCredentials(doc Persisted) error {
	return writeJSON0600(b.credentialsPath(), doc)
}

func writeJSON0600(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// Same-directory temp + file fsync + rename so a crash mid-write cannot
	// truncate an existing secrets / journal file (matches keyring §12.7).
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	if err := writeSyncedFile(tmp, raw, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Chmod(path, 0o600)
	// Directory fsync after rename (§12.7), same as keyring.
	return syncDirAfterJSONRename(filepath.Dir(path))
}

// syncDirAfterJSONRename is syncDirectory; tests may replace it to observe the call.
var syncDirAfterJSONRename = syncDirectory

// writeSyncedFile writes content then fsyncs before close so rename of a
// same-directory temp file promotes durable bytes (same pattern as keyring).
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

func randomHex(nbytes int) (string, error) {
	buf := make([]byte, nbytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func randomRelayKey() (string, error) {
	h, err := randomHex(24)
	if err != nil {
		return "", err
	}
	return "rk-" + h, nil
}

func masterKeyID(master string) string {
	sum := sha256.Sum256([]byte(master))
	return hex.EncodeToString(sum[:])[:16]
}
