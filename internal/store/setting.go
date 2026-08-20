package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/279814/relay-gate/internal/model"
)

const (
	keySettings = "settings"
	keyRunState = "run_state"
)

// GetSettings 读全局设置。未初始化时返回默认值（不写库），
// 让首次启动不依赖任何初始化步骤。
func (s *Store) GetSettings() (model.Settings, error) {
	var raw string
	err := s.db.QueryRow(`SELECT value FROM setting WHERE key = ?`, keySettings).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return model.DefaultSettings(), nil
	}
	if err != nil {
		return model.Settings{}, err
	}

	return DecodeLegacySettings([]byte(raw))
}

// DecodeLegacySettings is the only decoder allowed to accept the three
// pre-P0 timeout keys. API DTOs use their own strict current-schema decoder.
func DecodeLegacySettings(raw []byte) (model.Settings, error) {
	var present map[string]json.RawMessage
	if err := json.Unmarshal(raw, &present); err != nil {
		return model.Settings{}, model.WrapValidation("settings 不是合法 JSON: %v", err)
	}
	if present == nil {
		return model.Settings{}, model.WrapValidation("settings 必须是 JSON object")
	}

	type settingsAlias model.Settings
	decoded := settingsAlias(model.DefaultSettings())
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return model.Settings{}, model.WrapValidation("settings 字段无效: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return model.Settings{}, model.WrapValidation("settings 后存在多余 JSON")
	}
	out := model.Settings(decoded)

	if _, legacy := present["real_first_token_sec"]; legacy {
		if _, current := present["real_response_header_sec"]; !current {
			out.RealResponseHeaderSec = out.RealFirstTokenSec
		}
		if _, current := present["real_first_byte_sec"]; !current {
			out.RealFirstByteSec = out.RealFirstTokenSec
		}
		if _, current := present["real_first_semantic_sec"]; !current {
			out.RealFirstSemanticSec = out.RealFirstTokenSec
		}
	} else {
		out.RealFirstTokenSec = out.RealFirstSemanticSec
	}
	if _, legacy := present["l2_first_token_sec"]; legacy {
		if _, current := present["l2_response_header_sec"]; !current {
			out.L2ResponseHeaderSec = out.L2FirstTokenSec
		}
		if _, current := present["l2_first_byte_sec"]; !current {
			out.L2FirstByteSec = out.L2FirstTokenSec
		}
		if _, current := present["l2_first_event_sec"]; !current {
			out.L2FirstEventSec = out.L2FirstTokenSec
		}
		if _, current := present["l2_first_semantic_sec"]; !current {
			out.L2FirstSemanticSec = out.L2FirstTokenSec
		}
	} else {
		out.L2FirstTokenSec = out.L2FirstSemanticSec
	}
	if _, legacy := present["count_tokens_sec"]; legacy {
		if _, current := present["count_tokens_connect_sec"]; !current {
			out.CountTokensConnectSec = out.CountTokensSec
		}
		if _, current := present["count_tokens_total_sec"]; !current {
			out.CountTokensTotalSec = out.CountTokensSec
		}
	} else {
		out.CountTokensSec = out.CountTokensTotalSec
	}
	return out, nil
}

func encodeSettings(settings model.Settings) ([]byte, error) {
	raw, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	delete(fields, "real_first_token_sec")
	delete(fields, "l2_first_token_sec")
	delete(fields, "count_tokens_sec")
	return json.Marshal(fields)
}

// SaveSettings 校验后写入。校验失败返回 model.ErrValidation，API 层回 400。
func (s *Store) SaveSettings(st model.Settings) error {
	// Legacy API adapter: its three coarse knobs remain authoritative until
	// P0-14 migrates the handler to the stage-specific DTO.
	st.RealResponseHeaderSec = st.RealFirstTokenSec
	st.RealFirstByteSec = st.RealFirstTokenSec
	st.RealFirstSemanticSec = st.RealFirstTokenSec
	st.L2ResponseHeaderSec = st.L2FirstTokenSec
	st.L2FirstByteSec = st.L2FirstTokenSec
	st.L2FirstEventSec = st.L2FirstTokenSec
	st.L2FirstSemanticSec = st.L2FirstTokenSec
	st.CountTokensConnectSec = st.CountTokensSec
	st.CountTokensTotalSec = st.CountTokensSec
	if err := st.Validate(); err != nil {
		return err
	}
	_, revision, err := s.GetSettingsWithRevision()
	if err != nil {
		return err
	}
	_, err = s.SaveSettingsWithRevision(st, revision)
	return err
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
	settings, err := DecodeLegacySettings([]byte(raw))
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
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	var currentRaw string
	var currentRevision int64
	scanErr := tx.QueryRow(`SELECT value,revision FROM setting WHERE key=?`, keySettings).Scan(&currentRaw, &currentRevision)
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
	if currentRevision != expectedRevision {
		return 0, ErrRevisionConflict
	}
	current, decodeErr := DecodeLegacySettings([]byte(currentRaw))
	if decodeErr != nil {
		return 0, decodeErr
	}
	if reflect.DeepEqual(current, settings) {
		if err = tx.Commit(); err != nil {
			return 0, err
		}
		return currentRevision, nil
	}
	newRevision = currentRevision + 1
	result, err := tx.Exec(`UPDATE setting SET value=?,updated_at=?,revision=? WHERE key=? AND revision=?`,
		string(encoded), nowMS(), newRevision, keySettings, currentRevision)
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

// RunState remains a source-compatible alias until P0-17 removes the legacy
// Store-facing API.
type RunState = model.RunState

const (
	StateRunning RunState = model.RunStateRunning
	StatePaused  RunState = model.RunStatePaused
)

// GetRunState 读运行状态，默认 running。
// 状态持久化的意义在于「暂停时重启不会自动跑起来」（§4.8）。
func (s *Store) GetRunState() (RunState, error) {
	state, _, err := s.GetRunStateWithRevision()
	return state, err
}

func (s *Store) SetRunState(st RunState) error {
	_, revision, err := s.GetRunStateWithRevision()
	if err != nil {
		return err
	}
	_, err = s.SetRunStateWithRevision(st, revision)
	return err
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
	if _, err = tx.Exec(`INSERT INTO setting(key,value,updated_at,revision) VALUES (?,?,?,1)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at,revision=setting.revision+1`,
		keyRunState, state, updatedAt); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return newRevision, nil
}
