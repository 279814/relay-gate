package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

var ErrInvalidCursor = errors.New("分页 cursor 或 limit 无效")

const (
	pageCursorVersion = 1
	defaultPageLimit  = 50
	maximumPageLimit  = 200
)

type pageCursor struct {
	Version           int      `json:"v"`
	Resource          string   `json:"resource"`
	FilterFingerprint string   `json:"filter"`
	Keys              []string `json:"keys"`
	// EvaluatedAtMS 固定本次翻页的判定时刻，供依赖「当前时间」的 filter 使用。
	// 不参与 filter 指纹：它是同一次翻页的延续，不是 filter 变了。
	// 0 表示该资源的 filter 与时间无关。
	EvaluatedAtMS int64 `json:"at,omitempty"`
}

func normalizePageLimit(limit int) (int, error) {
	if limit == 0 {
		return defaultPageLimit, nil
	}
	if limit < 1 || limit > maximumPageLimit {
		return 0, fmt.Errorf("%w: limit 必须在 1..%d", ErrInvalidCursor, maximumPageLimit)
	}
	return limit, nil
}

func encodePageCursor(resource string, filter any, keys ...string) (string, error) {
	return encodePageCursorAt(resource, filter, 0, keys...)
}

// encodePageCursorAt 额外把判定时刻写进 cursor。
//
// 给依赖「当前时间」的 filter 用（如 Capability 的 Expired）：若每页都重新取
// 当前时间，翻页途中状态改变的行会改变结果集 —— 分页是 keyset，后续页只读
// 游标之后的行，于是那一行永远读不到，表现为静默漏项且不报错。
func encodePageCursorAt(resource string, filter any, evaluatedAtMS int64, keys ...string) (string, error) {
	fingerprint, err := pageFilterFingerprint(filter)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(pageCursor{
		Version: pageCursorVersion, Resource: resource,
		FilterFingerprint: fingerprint, Keys: append([]string(nil), keys...),
		EvaluatedAtMS: evaluatedAtMS,
	})
	if err != nil {
		return "", fmt.Errorf("编码分页 cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodePageCursor(encoded, resource string, filter any, keyCount int) ([]string, error) {
	keys, _, err := decodePageCursorAt(encoded, resource, filter, keyCount)
	return keys, err
}

// decodePageCursorAt 同时取回判定时刻。首页（encoded 为空）返回 0，
// 调用方据此取当前时间并写进下一页的 cursor。
func decodePageCursorAt(encoded, resource string, filter any, keyCount int) ([]string, int64, error) {
	if encoded == "" {
		return nil, 0, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: base64: %v", ErrInvalidCursor, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var cursor pageCursor
	if err := decoder.Decode(&cursor); err != nil {
		return nil, 0, fmt.Errorf("%w: JSON: %v", ErrInvalidCursor, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, 0, fmt.Errorf("%w: cursor 含多余 JSON", ErrInvalidCursor)
	}
	fingerprint, err := pageFilterFingerprint(filter)
	if err != nil {
		return nil, 0, err
	}
	if cursor.Version != pageCursorVersion || cursor.Resource != resource ||
		cursor.FilterFingerprint != fingerprint || len(cursor.Keys) != keyCount ||
		cursor.EvaluatedAtMS < 0 {
		return nil, 0, ErrInvalidCursor
	}
	return append([]string(nil), cursor.Keys...), cursor.EvaluatedAtMS, nil
}

// cursorID 解析 cursor 里的一个正整数 ID 键。cursor 是客户端可见的，
// 里面的数字未必还是数字 —— 解析不出来按坏 cursor 报，不能当成 0 继续查。
func cursorID(key string) (int64, error) {
	id, err := strconv.ParseInt(key, 10, 64)
	if err != nil || id < 1 {
		return 0, ErrInvalidCursor
	}
	return id, nil
}

func pageFilterFingerprint(filter any) (string, error) {
	encoded, err := json.Marshal(filter)
	if err != nil {
		return "", fmt.Errorf("编码分页 filter: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
