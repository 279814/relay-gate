package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/keyring"
)

// Migration journal phases (§12.8). Independent from bootstrap journal.
const (
	MigPhasePrepared  = "prepared"
	MigPhaseImported  = "imported"
	MigPhaseCompleted = "completed"
)

var (
	// ErrMigrationComplete means legacy env was already imported; do not re-import.
	ErrMigrationComplete = errors.New("旧凭据迁移已完成；不得再次导入覆盖轮换结果")
	// ErrMigrationAmbiguous means evidence is insufficient to choose migrate vs fresh.
	ErrMigrationAmbiguous = errors.New("无法识别旧部署：需要同时具备旧环境变量证据与数据库/未完成 migration journal；勿静默猜测")
	// ErrMigrationRefused means bootstrap already delivered a fresh install.
	ErrMigrationRefused = errors.New("已完成 credentials bootstrap；拒绝再用环境变量迁移覆盖")
)

// MigrationCrashPoint injects a crash after a named migration phase (tests only).
type MigrationCrashPoint string

const (
	MigCrashAfterPrepared MigrationCrashPoint = "after_prepared"
	MigCrashAfterImported MigrationCrashPoint = "after_imported"
)

type migrationJournalDoc struct {
	FormatVersion int    `json:"format_version"`
	Phase         string `json:"phase"`
	MasterKeyID   string `json:"master_key_id,omitempty"`
	UpdatedAt     string `json:"updated_at"`
}

// Migration imports legacy ENCRYPTION_KEY / ADMIN_PASSWORD / RELAY_KEYS into
// Keyring + Argon2id hash under data/secrets/ without generating a second random set.
type Migration struct {
	DataDir   string
	DBPath    string // schema / on-disk evidence of a prior deploy
	EncKey    string
	AdminPW   string
	RelayKeys []string
	Out       io.Writer // tips only; never secrets
	Now       func() time.Time
	// CrashAfter is test-only.
	CrashAfter MigrationCrashPoint
}

func (m *Migration) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Migration) secretsDir() string {
	return SecretsDir(m.DataDir)
}

func (m *Migration) journalPath() string {
	return filepath.Join(m.secretsDir(), "credentials-migration.journal")
}

func (m *Migration) Phase() (string, error) {
	doc, err := m.readJournal()
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return doc.Phase, nil
}

// Completed reports whether migration reached completed.
func (m *Migration) Completed() (bool, error) {
	phase, err := m.Phase()
	if err != nil {
		return false, err
	}
	return phase == MigPhaseCompleted, nil
}

// Run executes or resumes legacy credential migration (§12.8).
func (m *Migration) Run() error {
	if m.DataDir == "" {
		return errors.New("需要 data 目录")
	}
	if m.Out == nil {
		m.Out = io.Discard
	}
	if err := os.MkdirAll(m.secretsDir(), 0o700); err != nil {
		return err
	}

	// Reuse bootstrap lock so migrate/bootstrap cannot race on the same secrets dir.
	b := &Bootstrap{DataDir: m.DataDir}
	unlock, err := b.acquireLock()
	if err != nil {
		return err
	}
	defer unlock()

	phase, err := m.Phase()
	if err != nil {
		return err
	}
	switch phase {
	case MigPhaseCompleted:
		return ErrMigrationComplete
	case MigPhaseImported:
		return m.finishImported()
	case MigPhasePrepared, "":
		if err := m.requireEvidence(phase); err != nil {
			return err
		}
		return m.importLegacy()
	default:
		return fmt.Errorf("未知 migration 阶段 %q", phase)
	}
}

func (m *Migration) requireEvidence(phase string) error {
	// Never treat "empty keyring + empty credentials" alone as migrate-or-fresh.
	boot := &Bootstrap{DataDir: m.DataDir}
	bootPhase, err := boot.Phase()
	if err != nil {
		return err
	}
	if bootPhase == PhaseDisplayed {
		return ErrMigrationRefused
	}

	enc := strings.TrimSpace(m.EncKey)
	admin := strings.TrimSpace(m.AdminPW)
	relays := nonEmpty(m.RelayKeys)
	envOK := len(enc) >= 16 && len(admin) >= 8 && len(relays) > 0

	dbEvidence := false
	if p := strings.TrimSpace(m.DBPath); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			dbEvidence = true
		}
	}
	resumeJournal := phase == MigPhasePrepared

	if !envOK {
		return fmt.Errorf("%w：缺少 ENCRYPTION_KEY / ADMIN_PASSWORD / RELAY_KEYS", ErrMigrationAmbiguous)
	}
	if !dbEvidence && !resumeJournal {
		return fmt.Errorf("%w：未找到数据库文件作为旧部署证据（传入 --db）", ErrMigrationAmbiguous)
	}
	return nil
}

func (m *Migration) importLegacy() error {
	enc := strings.TrimSpace(m.EncKey)
	admin := strings.TrimSpace(m.AdminPW)
	relays := nonEmpty(m.RelayKeys)
	relay := relays[0]
	keyID := sha256KeyID(enc)

	if err := m.writeJournal(migrationJournalDoc{
		FormatVersion: 1,
		Phase:         MigPhasePrepared,
		UpdatedAt:     m.now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return err
	}
	if m.CrashAfter == MigCrashAfterPrepared {
		return errInjectedMigrationCrash
	}

	kr := keyring.Open(m.DataDir)
	if err := kr.EnsureInitialized(keyID, enc); err != nil {
		return fmt.Errorf("写入 keyring（保留 SHA-256 派生解密）: %w", err)
	}
	if id, existing, loadErr := kr.LoadActive(); loadErr == nil && existing != "" {
		// Keep existing master if keyring already present (prepared crash resume).
		enc = existing
		keyID = id
	}

	hash, err := HashAdminPassword(admin)
	if err != nil {
		return err
	}
	if err := WritePersisted(m.DataDir, Persisted{
		FormatVersion:     1,
		AdminPasswordHash: hash,
		RelayKey:          relay,
		MasterKeyID:       keyID,
		UpdatedAt:         m.now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return err
	}
	if err := m.writeJournal(migrationJournalDoc{
		FormatVersion: 1,
		Phase:         MigPhaseImported,
		MasterKeyID:   keyID,
		UpdatedAt:     m.now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return err
	}
	if m.CrashAfter == MigCrashAfterImported {
		return errInjectedMigrationCrash
	}
	return m.complete()
}

func (m *Migration) finishImported() error {
	doc, err := LoadPersistedFile(m.DataDir)
	if err != nil || doc.AdminPasswordHash == "" {
		return fmt.Errorf("migration imported 但 credentials 缺失；拒绝静默重新生成: %w", err)
	}
	return m.complete()
}

func (m *Migration) complete() error {
	doc, err := LoadPersistedFile(m.DataDir)
	if err != nil {
		return err
	}
	if err := m.writeJournal(migrationJournalDoc{
		FormatVersion: 1,
		Phase:         MigPhaseCompleted,
		MasterKeyID:   doc.MasterKeyID,
		UpdatedAt:     m.now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return err
	}
	// Tip only — never echo secrets.
	fmt.Fprintf(m.Out, "旧凭据迁移完成。请从环境变量删除 ENCRYPTION_KEY / RELAY_KEYS / ADMIN_PASSWORD（哈希已写入 data/secrets；后续启动勿再次导入）。\n")
	return nil
}

var errInjectedMigrationCrash = errors.New("injected migration crash")

func (m *Migration) readJournal() (migrationJournalDoc, error) {
	raw, err := os.ReadFile(m.journalPath())
	if err != nil {
		return migrationJournalDoc{}, err
	}
	var doc migrationJournalDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return migrationJournalDoc{}, fmt.Errorf("解析 migration journal: %w", err)
	}
	return doc, nil
}

func (m *Migration) writeJournal(doc migrationJournalDoc) error {
	return writeJSON0600(m.journalPath(), doc)
}

func nonEmpty(keys []string) []string {
	var out []string
	for _, k := range keys {
		if k = strings.TrimSpace(k); k != "" {
			out = append(out, k)
		}
	}
	return out
}

func sha256KeyID(master string) string {
	sum := sha256.Sum256([]byte(master))
	return hex.EncodeToString(sum[:])[:16]
}
