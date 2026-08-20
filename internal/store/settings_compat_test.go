package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestDecodeLegacySettingsExpandsOldStageKeysAndNewKeysWin(t *testing.T) {
	raw := []byte(`{
		"real_first_token_sec": 900,
		"real_first_byte_sec": 901,
		"l2_first_token_sec": 240,
		"l2_first_event_sec": 241,
		"count_tokens_sec": 75,
		"count_tokens_connect_sec": 31
	}`)
	settings, err := DecodeLegacySettings(raw)
	if err != nil {
		t.Fatal(err)
	}
	if settings.RealResponseHeaderSec != 900 || settings.RealFirstByteSec != 901 || settings.RealFirstSemanticSec != 900 {
		t.Fatalf("real legacy expansion/new priority = %+v", settings)
	}
	if settings.L2ResponseHeaderSec != 240 || settings.L2FirstByteSec != 240 || settings.L2FirstEventSec != 241 || settings.L2FirstSemanticSec != 240 {
		t.Fatalf("L2 legacy expansion/new priority = %+v", settings)
	}
	if settings.CountTokensConnectSec != 31 || settings.CountTokensTotalSec != 75 {
		t.Fatalf("count_tokens legacy expansion/new priority = %+v", settings)
	}
}

func TestSettingsAndRunStateRevisionCAS(t *testing.T) {
	store := testStore(t)
	settings, revision, err := store.GetSettingsWithRevision()
	if err != nil {
		t.Fatal(err)
	}
	if revision != 0 {
		t.Fatalf("missing settings revision = %d, want 0", revision)
	}
	settings.L1ConnectSec++
	newRevision, err := store.SaveSettingsWithRevision(settings, revision)
	if err != nil {
		t.Fatal(err)
	}
	if newRevision != 1 {
		t.Fatalf("new settings revision = %d", newRevision)
	}
	if _, err := store.SaveSettingsWithRevision(settings, revision); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale settings save = %v", err)
	}

	state, stateRevision, err := store.GetRunStateWithRevision()
	if err != nil || state != model.RunStateRunning || stateRevision != 1 {
		t.Fatalf("initial run state = %q/%d err=%v", state, stateRevision, err)
	}
	stateRevision, err = store.SetRunStateWithRevision(model.RunStatePaused, stateRevision)
	if err != nil || stateRevision != 2 {
		t.Fatalf("pause = revision %d err=%v", stateRevision, err)
	}
	unchanged, err := store.SetRunStateWithRevision(model.RunStatePaused, stateRevision)
	if err != nil || unchanged != stateRevision {
		t.Fatalf("no-op pause = revision %d err=%v", unchanged, err)
	}
	if _, err := store.SetRunStateWithRevision(model.RunStateRunning, 1); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale run-state update = %v", err)
	}
}

func TestDecodeLegacySettingsRejectsUnknownAndTrailingJSON(t *testing.T) {
	for _, raw := range []string{
		`{"real_connect_sec":30,"mystery":1}`,
		`{"real_connect_sec":30} {"real_connect_sec":31}`,
	} {
		if _, err := DecodeLegacySettings([]byte(raw)); !errors.Is(err, model.ErrValidation) {
			t.Fatalf("DecodeLegacySettings(%s) error = %v, want validation", raw, err)
		}
	}
}

func TestEncodeSettingsOmitsLegacyStageKeys(t *testing.T) {
	settings := model.DefaultSettings()
	encoded, err := encodeSettings(settings)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, legacy := range []string{"real_first_token_sec", "l2_first_token_sec", "count_tokens_sec"} {
		if _, ok := fields[legacy]; ok {
			t.Errorf("encoded settings retained legacy key %q: %s", legacy, encoded)
		}
	}
	for _, current := range []string{"real_first_semantic_sec", "l2_first_semantic_sec", "count_tokens_total_sec"} {
		if _, ok := fields[current]; !ok {
			t.Errorf("encoded settings omitted current key %q: %s", current, encoded)
		}
	}
	if strings.Contains(string(encoded), "mystery") {
		t.Fatal("unexpected field in encoded settings")
	}
}
