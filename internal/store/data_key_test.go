package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func TestDataKey_NewSamplesUseIndependentStableKey(t *testing.T) {
	st := testStore(t)
	smp := mkSample(time.Now().UnixMilli())
	smp.InBody = []byte("private sample body")
	if err := st.InsertSample(smp); err != nil {
		t.Fatal(err)
	}
	var before []byte
	if err := st.db.QueryRow(`SELECT in_body FROM sample_request WHERE id=?`, smp.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(before, []byte("v2:")) {
		t.Fatalf("sample must use independent-key v2 envelope, got %q", before[:min(24, len(before))])
	}
	if _, err := st.cipher.DecryptEnvelope(string(before)); err == nil {
		t.Fatal("Master Key directly decrypted sample body")
	}
	if err := st.RewrapDirectSecrets("replacement-master-for-data-key-tests", "data-key-rotation"); err != nil {
		t.Fatal(err)
	}
	var after []byte
	if err := st.db.QueryRow(`SELECT in_body FROM sample_request WHERE id=?`, smp.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("Master rotation rewrote sample body instead of only wrapping its Data Key")
	}
	if err := st.ActivateMaster("replacement-master-for-data-key-tests"); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSample(smp.ID)
	if err != nil || !bytes.Equal(got.InBody, smp.InBody) {
		t.Fatalf("rotation changed body: %v", err)
	}
}

func TestDataKey_BackupRejectsAuthenticatedBodyCorruption(t *testing.T) {
	st := testStore(t)
	sample := mkSample(42)
	if err := st.InsertSample(sample); err != nil {
		t.Fatal(err)
	}
	state, err := inspectSchemaState(context.Background(), st.db)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := st.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	backup, err := createMigrationBackup(context.Background(), conn, st.path, MigrationBackupSpec{SourceSchema: 8, TargetSchema: 9, SourceFingerprint: state.Fingerprint, LegacyCipherID: st.cipher.KeyID(), SourceValidator: "schema-8-data-key-v2", PairedBuildID: "fixture-build", ReaderContract: "schema-8-data-key-v2-reader"})
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", backup.DatabasePath+connPragmas)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE sample_request SET in_body='v2:corrupt:AAAA'`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	backup.Manifest.DatabaseSize, backup.Manifest.DatabaseSHA256, err = fileEvidence(backup.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(backup.Manifest)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(context.Background(), st.path, backup.ManifestPath, st.cipher); err == nil {
		t.Fatal("backup checker accepted authenticated sample damage with matching file SHA")
	}
}

func TestDataKey_LegacyMultipartMigrationPreservesPlaintext(t *testing.T) {
	st := testStore(t)
	var raw bytes.Buffer
	raw.WriteString("v1m:" + st.cipher.KeyID() + ":\n")
	want := []byte("old multipart sample body")
	for _, plain := range [][]byte{want[:7], want[7:]} {
		frame, err := st.cipher.EncryptEnvelope(string(plain))
		if err != nil {
			t.Fatal(err)
		}
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(frame)))
		raw.Write(length[:])
		raw.WriteString(frame)
	}
	id := insertRawSampleGroup(t, st, "legacy-multipart", time.Now().UnixMilli(), nil, nil, raw.Bytes())
	if _, err := st.MigrateSampleEnvelopes(); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSample(id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.RespBody, want) {
		t.Fatalf("multipart migration returned ciphertext instead of body: prefix=%q", got.RespBody[:min(24, len(got.RespBody))])
	}
}

func TestDataKey_OpenRejectsCorruptSampleCiphertext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt-sample.db")
	c, _ := NewCipher("test-data-key-master-long-enough")
	st, err := Open(path, c)
	if err != nil {
		t.Fatal(err)
	}
	smp := &model.Sample{ReqID: "corrupt-body", TSRecv: time.Now().UnixMilli(), InMethod: "POST", InPath: "/v1/messages", InBody: []byte("sensitive"), Outcome: model.OutcomeOK}
	if err := st.InsertSample(smp); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := st.db.QueryRow(`SELECT in_body FROM sample_request WHERE id=?`, smp.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-3] ^= 1
	if _, err := st.db.Exec(`UPDATE sample_request SET in_body=? WHERE id=?`, raw, smp.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	newCipher, _ := NewCipher("test-data-key-master-long-enough")
	reopened, err := Open(path, newCipher)
	if err == nil {
		reopened.Close()
		t.Fatal("startup accepted damaged encrypted sample")
	}
	if strings.Contains(err.Error(), "sensitive") {
		t.Fatal("sample plaintext leaked in error")
	}
}

func TestDataKey_StandaloneValidationNeverCreatesMissingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-created.db")
	if err := ValidateDatabaseEncryption(context.Background(), path, "standalone-validation-master-long"); err == nil {
		t.Fatal("empty or missing database accepted as verified encrypted state")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("read-only verification created the missing database")
	}
}

func TestDataKey_StandaloneValidationPreservesDatabaseAndWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "read-only-validation.db")
	const master = "read-only-validation-master-long-enough"
	c, _ := NewCipher(master)
	st, err := Open(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.InsertSample(mkSample(42)); err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		raw, err := os.ReadFile(path + suffix)
		if err == nil {
			before[suffix] = raw
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if err := ValidateDatabaseEncryption(context.Background(), path, master); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		raw, err := os.ReadFile(path + suffix)
		want, existed := before[suffix]
		if !existed && os.IsNotExist(err) {
			continue
		}
		// SQLite's read-only WAL reader may update internal SHM read marks;
		// database/WAL content and sidecar lifecycle must remain unchanged.
		if err != nil || !existed || (suffix != "-shm" && !bytes.Equal(raw, want)) {
			t.Fatalf("read-only validator changed database artifact %q", suffix)
		}
	}
}
