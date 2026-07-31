package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

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

	// 以默认值为基底再反序列化：这样新增配置项时，老记录里缺的字段
	// 会拿到默认值而不是 0。若不这么做，一次版本升级就会把所有超时变成 0。
	out := model.DefaultSettings()
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return model.Settings{}, fmt.Errorf("settings 不是合法 JSON: %w", err)
	}
	return out, nil
}

// SaveSettings 校验后写入。校验失败返回 model.ErrValidation，API 层回 400。
func (s *Store) SaveSettings(st model.Settings) error {
	if err := st.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO setting (key, value, updated_at) VALUES (?,?,?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		keySettings, string(b), nowMS())
	return err
}

// RunState 是服务总闸（§4.8）。
type RunState string

const (
	StateRunning RunState = "running"
	StatePaused  RunState = "paused"
)

// GetRunState 读运行状态，默认 running。
// 状态持久化的意义在于「暂停时重启不会自动跑起来」（§4.8）。
func (s *Store) GetRunState() (RunState, error) {
	var raw string
	err := s.db.QueryRow(`SELECT value FROM setting WHERE key = ?`, keyRunState).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return StateRunning, nil
	}
	if err != nil {
		return "", err
	}
	if RunState(raw) == StatePaused {
		return StatePaused, nil
	}
	return StateRunning, nil
}

func (s *Store) SetRunState(st RunState) error {
	if st != StateRunning && st != StatePaused {
		return fmt.Errorf("%w: state 必须是 running 或 paused，收到 %q", model.ErrValidation, st)
	}
	_, err := s.db.Exec(`INSERT INTO setting (key, value, updated_at) VALUES (?,?,?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		keyRunState, string(st), nowMS())
	return err
}
