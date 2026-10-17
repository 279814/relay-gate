package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

const keySettings = "settings"

func decodeSettingsDocument(raw []byte, target any) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return model.WrapValidation("settings 必须是合法 JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return model.WrapValidation("settings 字段无效")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return model.WrapValidation("settings 后存在多余 JSON")
	}
	return nil
}

// Normal reads accept only the current runtime model. Legacy syntax belongs
// exclusively to the controlled startup/import decoder below.
func decodeCurrentSettings(raw []byte) (model.Settings, error) {
	settings := model.DefaultSettings()
	err := decodeSettingsDocument(raw, &settings)
	return settings, err
}

func usableSettings(settings model.Settings, err error) (model.Settings, error) {
	if err != nil {
		return model.Settings{}, err
	}
	if err := settings.Validate(); err != nil {
		return model.DefaultSettings(), nil
	}
	return settings, nil
}

// DecodeLegacySettings is used only by startup normalization and historical
// migration readers. Explicit new stage keys win over the old coarse aliases.
func DecodeLegacySettings(raw []byte) (model.Settings, error) {
	document := struct {
		model.Settings
		RealFirstToken *int  `json:"real_first_token_sec"`
		L2FirstToken   *int  `json:"l2_first_token_sec"`
		CountTokens    *int  `json:"count_tokens_sec"`
		ProbeEnabled   *bool `json:"probe_enabled"`
	}{Settings: model.DefaultSettings()}
	if err := decodeSettingsDocument(raw, &document); err != nil {
		return model.Settings{}, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return model.Settings{}, model.WrapValidation("settings 必须是合法 JSON object")
	}
	present := func(name string) bool {
		for key, value := range fields {
			if strings.EqualFold(key, name) && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return true
			}
		}
		return false
	}
	fill := func(name string, target *int, legacy *int) {
		if legacy != nil && !present(name) {
			*target = *legacy
		}
	}
	fill("real_response_header_sec", &document.RealResponseHeaderSec, document.RealFirstToken)
	fill("real_first_byte_sec", &document.RealFirstByteSec, document.RealFirstToken)
	fill("real_first_semantic_sec", &document.RealFirstSemanticSec, document.RealFirstToken)
	fill("l2_response_header_sec", &document.L2ResponseHeaderSec, document.L2FirstToken)
	fill("l2_first_byte_sec", &document.L2FirstByteSec, document.L2FirstToken)
	fill("l2_first_event_sec", &document.L2FirstEventSec, document.L2FirstToken)
	fill("l2_first_semantic_sec", &document.L2FirstSemanticSec, document.L2FirstToken)
	fill("count_tokens_connect_sec", &document.CountTokensConnectSec, document.CountTokens)
	fill("count_tokens_total_sec", &document.CountTokensTotalSec, document.CountTokens)
	return document.Settings, nil
}

func encodeSettings(settings model.Settings) ([]byte, error) { return json.Marshal(settings) }

// Initialization occurs under the existing instance lock before a listener or
// Source is exposed. It never opens or rewrites a backup database.
func initializeCurrentSettings(ctx context.Context, db *sql.DB) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT value,revision FROM setting WHERE key=?`, keySettings).Scan(&raw, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		encoded, encodeErr := encodeSettings(model.DefaultSettings())
		if encodeErr != nil {
			return encodeErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO setting(key,value,updated_at,revision) VALUES (?,?,?,1)`, keySettings, string(encoded), nowMS()); err != nil {
			return err
		}
		return tx.Commit()
	}
	if err != nil {
		return err
	}
	if _, currentErr := decodeCurrentSettings(raw); currentErr == nil {
		return tx.Commit()
	}
	settings, err := DecodeLegacySettings(raw)
	if err != nil {
		return err
	}
	encoded, err := encodeSettings(settings)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE setting SET value=?,updated_at=?,revision=revision+1 WHERE key=? AND revision=?`, string(encoded), nowMS(), keySettings, revision); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetSettings() (model.Settings, error) {
	settings, _, err := s.GetSettingsWithRevision()
	return settings, err
}

func (s *Store) GetSettingsWithRevision() (model.Settings, int64, error) {
	var raw string
	var revision int64
	err := s.db.QueryRow(`SELECT value,revision FROM setting WHERE key=?`, keySettings).Scan(&raw, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return model.DefaultSettings(), 0, nil
	}
	if err != nil {
		return model.Settings{}, 0, err
	}
	settings, err := usableSettings(decodeCurrentSettings([]byte(raw)))
	return settings, revision, err
}

func (s *Store) SaveSettingsWithRevision(settings model.Settings, expectedRevision int64) (newRevision int64, err error) {
	if expectedRevision < 0 {
		return 0, model.WrapValidation("expected revision 不能为负")
	}
	if err := settings.Validate(); err != nil {
		return 0, err
	}
	encoded, err := encodeSettings(settings)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var raw string
	var revision int64
	scanErr := tx.QueryRow(`SELECT value,revision FROM setting WHERE key=?`, keySettings).Scan(&raw, &revision)
	if errors.Is(scanErr, sql.ErrNoRows) {
		if expectedRevision != 0 {
			return 0, ErrRevisionConflict
		}
		if _, err = tx.Exec(`INSERT INTO setting(key,value,updated_at,revision) VALUES (?,?,?,1)`, keySettings, string(encoded), nowMS()); err != nil {
			return 0, err
		}
		if err = tx.Commit(); err != nil {
			return 0, err
		}
		return 1, nil
	}
	if scanErr != nil {
		return 0, scanErr
	}
	if revision != expectedRevision {
		return 0, ErrRevisionConflict
	}
	current, err := decodeCurrentSettings([]byte(raw))
	if err != nil {
		return 0, err
	}
	if reflect.DeepEqual(current, settings) {
		if err = tx.Commit(); err != nil {
			return 0, err
		}
		return revision, nil
	}
	newRevision = revision + 1
	result, err := tx.Exec(`UPDATE setting SET value=?,updated_at=?,revision=? WHERE key=? AND revision=?`, string(encoded), nowMS(), newRevision, keySettings, revision)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if affected != 1 {
		return 0, ErrRevisionConflict
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return newRevision, nil
}

func (s *Store) GetRunStateWithRevision() (model.RunState, int64, error) {
	var state model.RunState
	var revision int64
	err := s.db.QueryRow(`SELECT state,revision FROM run_state WHERE singleton=1`).Scan(&state, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RunStateRunning, 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	if !state.Valid() {
		return "", 0, fmt.Errorf("%w: run_state=%q", ErrUnknownSchema, state)
	}
	return state, revision, nil
}

func (s *Store) SetRunStateWithRevision(state model.RunState, expectedRevision int64) (newRevision int64, err error) {
	if !state.Valid() {
		return 0, fmt.Errorf("%w: state 必须是 running 或 paused，收到 %q", model.ErrValidation, state)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	var current model.RunState
	var currentRevision int64
	if err = tx.QueryRow(`SELECT state,revision FROM run_state WHERE singleton=1`).Scan(&current, &currentRevision); err != nil {
		return 0, err
	}
	if currentRevision != expectedRevision {
		return 0, ErrRevisionConflict
	}
	if current == state {
		if err = tx.Commit(); err != nil {
			return 0, err
		}
		return currentRevision, nil
	}
	newRevision = currentRevision + 1
	updatedAt := nowMS()
	result, err := tx.Exec(`UPDATE run_state SET state=?,revision=?,updated_at=? WHERE singleton=1 AND revision=?`,
		state, newRevision, updatedAt, currentRevision)
	if err != nil {
		return 0, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return 0, ErrRevisionConflict
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return newRevision, nil
}
