package store

import (
	"bytes"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func TestSampleEnvelope_RoundTripAndLegacyMigration(t *testing.T) {
	st := testStore(t)

	// Legacy plaintext row (simulates pre-envelope history).
	plain := []byte(`{"model":"legacy-keep-me","secret":"do-not-drop"}`)
	legacyID := insertRawSampleGroup(t, st, "legacy-1", time.Now().UnixMilli(), plain, plain, plain)

	// Readable before migration (dual-read plaintext).
	got, err := st.GetSample(legacyID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.InBody, plain) {
		t.Fatalf("legacy read: %q", got.InBody)
	}

	n, err := st.MigrateSampleEnvelopes()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("migrated=%d want 1", n)
	}

	// Raw storage must be enveloped; plaintext must not remain.
	var rawIn []byte
	if err := st.db.QueryRow(`SELECT in_body FROM sample_request WHERE id=?`, legacyID).Scan(&rawIn); err != nil {
		t.Fatal(err)
	}
	if !IsSampleEnvelope(rawIn) {
		t.Fatalf("expected envelope, got prefix %q", string(rawIn[:min(8, len(rawIn))]))
	}
	if bytes.Contains(rawIn, []byte("do-not-drop")) {
		t.Fatal("plaintext secret still visible in stored BLOB")
	}
	var rawOut, rawResp []byte
	if err := st.db.QueryRow(`SELECT out_body, resp_body FROM sample_attempt WHERE request_id=?`, legacyID).Scan(&rawOut, &rawResp); err != nil {
		t.Fatal(err)
	}
	if !IsSampleEnvelope(rawOut) || !IsSampleEnvelope(rawResp) {
		t.Fatal("attempt bodies must be enveloped by migration")
	}

	got2, err := st.GetSample(legacyID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2.InBody, plain) || !bytes.Equal(got2.OutBody, plain) || !bytes.Equal(got2.RespBody, plain) {
		t.Fatalf("history content changed after migration: %+v", got2)
	}

	// Second pass is a no-op; no rows dropped.
	n2, err := st.MigrateSampleEnvelopes()
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Fatalf("second migrate=%d", n2)
	}
	count, err := st.CountSamples()
	if err != nil || count < 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}

	// New writes are enveloped immediately.
	fresh := mkSample(time.Now().UnixMilli())
	fresh.InBody = []byte(`{"model":"fresh"}`)
	if err := st.InsertSample(fresh); err != nil {
		t.Fatal(err)
	}
	var rawFresh []byte
	if err := st.db.QueryRow(`SELECT in_body FROM sample_request WHERE id=?`, fresh.ID).Scan(&rawFresh); err != nil {
		t.Fatal(err)
	}
	if !IsSampleEnvelope(rawFresh) {
		t.Fatal("new insert should use envelope")
	}
	got3, err := st.GetSample(fresh.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got3.InBody, fresh.InBody) {
		t.Fatalf("fresh roundtrip: %q", got3.InBody)
	}
}

func TestSampleEnvelope_BinarySafe(t *testing.T) {
	st := testStore(t)
	bin := []byte{0x00, 0x01, 0xff, 'a', 'b', 0x7f}
	s := &model.Sample{
		TSRecv: time.Now().UnixMilli(), Endpoint: "/v1/messages",
		InMethod: "POST", InPath: "/v1/messages",
		InBody: bin, OutBody: bin, RespBody: bin,
		Outcome: model.OutcomeOK,
	}
	if err := st.InsertSample(s); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSample(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.InBody, bin) {
		t.Fatalf("binary roundtrip failed: %v", got.InBody)
	}
}
