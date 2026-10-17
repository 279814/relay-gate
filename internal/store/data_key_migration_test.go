package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/security"
)

func legacyMultipartFixture(t *testing.T, c *Cipher, parts ...[]byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	raw.WriteString("v1m:" + c.KeyID() + ":\n")
	for _, plain := range parts {
		enc, err := c.EncryptEnvelope(string(plain))
		if err != nil {
			t.Fatal(err)
		}
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(enc)))
		raw.Write(length[:])
		raw.WriteString(enc)
	}
	return raw.Bytes()
}

func TestDataKey_SchemaSevenMigrationPreservesEveryBodyAndSecurityEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema7.db")
	c, _ := NewCipher("schema-seven-existing-master-key")
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaSeven(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	in := []byte("legacy single-frame input")
	wrapped, err := c.EncryptEnvelope(string(in))
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte("legacy multipart reply"), 100000)
	multipart := legacyMultipartFixture(t, c, want[:1000000], want[1000000:2000000], want[2000000:])
	fixture := &Store{db: db, cipher: c}
	id := insertRawSampleGroup(t, fixture, "schema7-history", 42, []byte(wrapped), []byte("plain out body"), multipart)
	if _, err := db.Exec(`INSERT INTO security_finding(id,at_ms,severity,category,summary,detail) VALUES ('legacy-finding',42,'high','fixture','metadata','sensitive conversation snippet')`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	st, err := Open(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := st.GetSample(id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.InBody, in) || string(got.OutBody) != "plain out body" || !bytes.Equal(got.RespBody, want) {
		t.Fatal("schema8 migration changed historical body bytes")
	}
	findings, err := st.ListSecurityFindings("high", 1)
	if err != nil || len(findings) != 1 || findings[0].Detail != "sensitive conversation snippet" {
		t.Fatalf("security evidence changed: %v", err)
	}
	var raw []byte
	if err := st.db.QueryRow(`SELECT detail FROM security_finding WHERE id='legacy-finding'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("conversation")) || !bytes.HasPrefix(raw, []byte("v2:")) {
		t.Fatal("security detail stayed plaintext")
	}
	if n, err := st.MigrateSampleEnvelopes(); err != nil || n != 0 {
		t.Fatalf("migration is not idempotent: rows=%d err=%v", n, err)
	}
	if err := st.ValidateEncryptedState(); err != nil {
		t.Fatal(err)
	}
}

func TestDataKey_MigrationFailureRollsBackKeyAndSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken-schema7.db")
	c, _ := NewCipher("schema-seven-corrupt-master-key")
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaSeven(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	broken := []byte("v1:" + c.KeyID() + ":invalid")
	insertRawSampleGroup(t, &Store{db: db}, "broken-history", 42, broken, nil, nil)
	db.Close()
	if st, err := Open(path, c); err == nil {
		st.Close()
		t.Fatal("corrupt legacy envelope migrated successfully")
	}
	db = openDatabaseAtPath(t, path)
	defer db.Close()
	state, err := inspectSchemaState(context.Background(), db)
	if err != nil || state.Version != 7 {
		t.Fatalf("failed migration changed schema: %+v %v", state, err)
	}
	var keys int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE name='data_key'`).Scan(&keys); err != nil || keys != 0 {
		t.Fatalf("failed migration left a Data Key table: %d %v", keys, err)
	}
	var after []byte
	if err := db.QueryRow(`SELECT in_body FROM sample_request`).Scan(&after); err != nil || !bytes.Equal(after, broken) {
		t.Fatal("failed migration modified legacy ciphertext")
	}
}

// Earlier startup migration mistook v1m as plaintext and put a v1 wrapper
// around the entire encrypted object. Recover that authenticated historical
// representation instead of preserving ciphertext as the user's response.
func TestDataKey_MigrationRepairsHistoricallyDoubleWrappedMultipart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested-legacy.db")
	c, _ := NewCipher("nested-history-master-long-enough")
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaSeven(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	want := []byte("original multipart response")
	inner := legacyMultipartFixture(t, c, want[:8], want[8:])
	outer, err := c.EncryptEnvelope(string(inner))
	if err != nil {
		t.Fatal(err)
	}
	insertRawSampleGroup(t, &Store{db: db}, "nested-old-migration", 42, nil, nil, []byte(outer))
	db.Close()
	st, err := Open(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := st.GetSample(1)
	if err != nil || !bytes.Equal(got.RespBody, want) {
		t.Fatalf("historical double wrapper was not recovered: %v", err)
	}
}

func TestDataKey_MigrationPreservesAuthenticatedEmptyLegacyBody(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-legacy.db")
	c, _ := NewCipher("empty-legacy-master-long-enough")
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaSeven(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	empty, err := c.EncryptEnvelope("")
	if err != nil {
		t.Fatal(err)
	}
	insertRawSampleGroup(t, &Store{db: db}, "empty-legacy", 42, []byte(empty), nil, nil)
	db.Close()
	st, err := Open(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := st.GetSample(1)
	if err != nil || len(got.InBody) != 0 {
		t.Fatalf("empty legacy body changed: %v", err)
	}
}

func TestDataKey_MultipartAuthenticatesOrderLengthAndObject(t *testing.T) {
	st := testStore(t)
	want := bytes.Repeat([]byte("frame"), 500)
	var output bytes.Buffer
	if err := encryptDataStream(st.cipher, sampleKeyPurpose, &output, bytes.NewReader(want), int64(len(want)), 1024); err != nil {
		t.Fatal(err)
	}
	raw := output.Bytes()
	headerEnd := bytes.IndexByte(raw, '\n') + 1
	firstEnd := headerEnd + 4 + int(binary.BigEndian.Uint32(raw[headerEnd:headerEnd+4]))
	secondEnd := firstEnd + 4 + int(binary.BigEndian.Uint32(raw[firstEnd:firstEnd+4]))
	reordered := append([]byte(nil), raw[:headerEnd]...)
	reordered = append(reordered, raw[firstEnd:secondEnd]...)
	reordered = append(reordered, raw[headerEnd:firstEnd]...)
	reordered = append(reordered, raw[secondEnd:]...)
	for name, mutated := range map[string][]byte{"removed frame": raw[:secondEnd], "reordered frames": reordered, "extra frame": append(append([]byte(nil), raw...), raw[headerEnd:firstEnd]...)} {
		t.Run(name, func(t *testing.T) {
			if _, err := decryptDataMultipart(st.cipher, sampleKeyPurpose, mutated); err == nil {
				t.Fatal("multipart corruption was accepted")
			}
		})
	}
	var different bytes.Buffer
	if err := encryptDataStream(st.cipher, sampleKeyPurpose, &different, bytes.NewReader(want), int64(len(want)), 1024); err != nil {
		t.Fatal(err)
	}
	other := different.Bytes()
	otherStart := bytes.IndexByte(other, '\n') + 1
	grafted := append([]byte(nil), raw...)
	copy(grafted[headerEnd:firstEnd], other[otherStart:otherStart+(firstEnd-headerEnd)])
	if _, err := decryptDataMultipart(st.cipher, sampleKeyPurpose, grafted); err == nil {
		t.Fatal("cross-object frame graft was accepted")
	}
}

func TestDataKey_StartupRejectsMissingKeyAndHeaderDowngrade(t *testing.T) {
	for _, corruption := range []string{"missing key", "downgraded magic"} {
		t.Run(corruption, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "damaged.db")
			c, _ := NewCipher("missing-data-key-master-long-enough")
			st, err := Open(path, c)
			if err != nil {
				t.Fatal(err)
			}
			if corruption == "missing key" {
				_, err = st.db.Exec(`DELETE FROM data_key WHERE purpose='sample'`)
			} else {
				smp := mkSample(time.Now().UnixMilli())
				if err := st.InsertSample(smp); err != nil {
					t.Fatal(err)
				}
				_, err = st.db.Exec(`UPDATE sample_request SET in_body=CAST('w2:' AS BLOB)||substr(CAST(in_body AS BLOB),4)`)
			}
			if err != nil {
				t.Fatal(err)
			}
			st.Close()
			fresh, _ := NewCipher("missing-data-key-master-long-enough")
			if reopened, err := Open(path, fresh); err == nil {
				reopened.Close()
				t.Fatal("startup accepted missing key or a downgraded encryption header")
			}
		})
	}
}

func TestDataKey_SecurityDetailsUseSeparatePurposeKey(t *testing.T) {
	st := testStore(t)
	if err := st.InsertSecurityFinding(security.Finding{ID: "high", AtMS: 2, Severity: security.SeverityHigh, Detail: "private evidence"}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertSecurityFinding(security.Finding{ID: "low", AtMS: 1, Severity: security.SeverityLow, Detail: "another evidence"}); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := st.db.QueryRow(`SELECT detail FROM security_finding WHERE id='high'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if _, err := st.cipher.decryptDataBlob(sampleKeyPurpose, raw); err == nil {
		t.Fatal("Sample Data Key accepted Security Data Key evidence")
	}
	got, err := st.ListSecurityFindings("high", 1)
	if err != nil || len(got) != 1 || got[0].Detail != "private evidence" {
		t.Fatalf("severity/pagination/decryption contract changed: %v", err)
	}
	var sampleID, securityID string
	st.db.QueryRow(`SELECT key_id FROM data_key WHERE purpose='sample'`).Scan(&sampleID)
	st.db.QueryRow(`SELECT key_id FROM data_key WHERE purpose='security'`).Scan(&securityID)
	if sampleID == securityID {
		t.Fatal("sample and security share a Data Key")
	}
}
