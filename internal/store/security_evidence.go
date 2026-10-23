package store

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/279814/relay-gate/internal/model"
)

// SecurityEvidence references one existing raw upstream response. No finding
// domain body is written, and unavailable never means a redacted Detail is raw.
type SecurityEvidence struct {
	Available bool        `json:"available"`
	Reason    string      `json:"reason"`
	SampleID  int64       `json:"sample_id,omitempty"`
	AttemptID int64       `json:"attempt_id,omitempty"`
	Status    int         `json:"status,omitempty"`
	Headers   http.Header `json:"headers,omitempty"`
	Body      []byte      `json:"body,omitempty"`
}

func (s *Store) SecurityFindingEvidence(ctx context.Context, id string, includeBody bool) (SecurityEvidence, error) {
	result := SecurityEvidence{Reason: "untrusted_finding"}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var source, reqID, scanner, rules, incomplete string
	var routeID, upstreamID, bytes int64
	var truncated bool
	err = tx.QueryRowContext(ctx, `SELECT source,req_id,route_id,upstream_id,scanner_version,rule_version,bytes_scanned,incomplete_reason,truncated FROM security_finding WHERE id=?`, id).Scan(&source, &reqID, &routeID, &upstreamID, &scanner, &rules, &bytes, &incomplete, &truncated)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	if source != "passive" || reqID == "" || routeID < 1 || upstreamID < 1 || scanner == "" || rules == "" || bytes < 1 {
		return result, nil
	}
	if truncated || incomplete != "" {
		result.Reason = "incomplete_scan"
		return result, nil
	}
	// Count every same-identity attempt, including legacy/non-raw ones. Never
	// silently choose the newest row, retry, current Route or approximate time.
	rows, err := tx.QueryContext(ctx, `SELECT a.request_id,a.id,a.truncated,COALESCE(m.response_capture_view,'legacy'),COALESCE(m.metadata_version,0)
 FROM sample_request r JOIN sample_attempt a ON a.request_id=r.id LEFT JOIN sample_attempt_metadata m ON m.owner_id=a.id
 WHERE r.req_id=? AND a.route_id=? AND a.upstream_id=? LIMIT 2`, reqID, routeID, upstreamID)
	if err != nil {
		return result, err
	}
	count := 0
	var flags int
	var view string
	var version int
	for rows.Next() {
		count++
		if err := rows.Scan(&result.SampleID, &result.AttemptID, &flags, &view, &version); err != nil {
			rows.Close()
			return SecurityEvidence{}, err
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return SecurityEvidence{}, err
	}
	if count != 1 {
		result = SecurityEvidence{Reason: "sample_missing_or_ambiguous"}
		return result, nil
	}
	if version < 1 || view != "upstream_response" || model.TruncFlags(flags)&model.TruncRespBody != 0 {
		return SecurityEvidence{Reason: "original_response_unavailable"}, nil
	}
	result.Available = true
	result.Reason = "original_upstream_response"
	if includeBody {
		var headers string
		var sealed []byte
		if err := tx.QueryRowContext(ctx, `SELECT resp_status,resp_headers,resp_body FROM sample_attempt WHERE id=?`, result.AttemptID).Scan(&result.Status, &headers, &sealed); err != nil {
			return SecurityEvidence{}, err
		}
		result.Headers, err = unmarshalJSONHeaders(headers)
		if err != nil {
			return SecurityEvidence{}, err
		}
		result.Body, err = decryptSampleBody(s.cipher, sealed)
		if err != nil {
			return SecurityEvidence{}, err
		}
	}
	return result, tx.Commit()
}
