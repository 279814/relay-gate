package transform

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// ExecutionFilter selects only diagnostics still retained in this process.
// It does not query durable request logs or reconstruct past executions.
type ExecutionFilter struct {
	RouteID, EndpointID, VersionID int64
	Mode, Phase                    string
	OK                             *bool
	AfterMS, BeforeMS              int64
}

type ExecutionPage struct {
	Executions []ExecutionRecord `json:"executions"`
	Total      int               `json:"total"`
	NextCursor string            `json:"next_cursor"`
	Limit      int               `json:"limit"`
	Scope      string            `json:"scope"`
}

type executionCursor struct {
	Version  int             `json:"v"`
	Filter   ExecutionFilter `json:"filter"`
	Sequence uint64          `json:"seq"`
	At       time.Time       `json:"at"`
	ID       string          `json:"id"`
}

// ExecutionsPage counts and reads one bounded ring snapshot under the same lock.
// The anchor must remain present: eviction/restart requires an explicit reload,
// rather than silently treating a cursor as the beginning of a new history.
func (r *Registry) ExecutionsPage(filter ExecutionFilter, limit int, encoded string) (ExecutionPage, error) {
	page := ExecutionPage{Executions: []ExecutionRecord{}, Scope: "current_run_retained"}
	if limit == 0 {
		limit = 50
	}
	page.Limit = limit
	if limit < 1 || limit > 200 {
		return page, fmt.Errorf("execution limit must be 1..200")
	}
	var cursor executionCursor
	if encoded != "" {
		if len(encoded) > 2048 {
			return page, fmt.Errorf("execution cursor invalid")
		}
		payload, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return page, fmt.Errorf("execution cursor invalid")
		}
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&cursor) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) || cursor.Version != 1 || !sameExecutionFilter(cursor.Filter, filter) || cursor.Sequence == 0 {
			return page, fmt.Errorf("execution cursor/filter invalid")
		}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	start := 0
	if encoded != "" {
		found := false
		for i, record := range r.execs {
			if record.sequence == cursor.Sequence && record.ID == cursor.ID && record.At.Equal(cursor.At) {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return page, fmt.Errorf("execution cursor expired; reload current-run diagnostics")
		}
	}
	var last ExecutionRecord
	for i, record := range r.execs {
		if !filter.matches(record) {
			continue
		}
		page.Total++
		if i < start {
			continue
		}
		if len(page.Executions) < limit {
			copy := record
			copy.HitRules = append([]string(nil), record.HitRules...)
			page.Executions = append(page.Executions, copy)
			last = record
		} else if page.NextCursor == "" {
			payload, err := json.Marshal(executionCursor{Version: 1, Filter: filter, Sequence: last.sequence, At: last.At, ID: last.ID})
			if err != nil {
				return page, err
			}
			page.NextCursor = base64.RawURLEncoding.EncodeToString(payload)
		}
	}
	return page, nil
}

func sameExecutionFilter(a, b ExecutionFilter) bool {
	if (a.OK == nil) != (b.OK == nil) || a.OK != nil && *a.OK != *b.OK {
		return false
	}
	a.OK, b.OK = nil, nil
	return a == b
}
func (f ExecutionFilter) matches(record ExecutionRecord) bool {
	return (f.RouteID == 0 || f.RouteID == record.RouteID) &&
		(f.EndpointID == 0 || f.EndpointID == record.EndpointID) &&
		(f.VersionID == 0 || f.VersionID == record.VersionID) &&
		(f.Mode == "" || f.Mode == record.Mode) && (f.Phase == "" || f.Phase == record.Phase) &&
		(f.OK == nil || *f.OK == record.OK) && (f.AfterMS == 0 || record.At.UnixMilli() >= f.AfterMS) &&
		(f.BeforeMS == 0 || record.At.UnixMilli() <= f.BeforeMS)
}
