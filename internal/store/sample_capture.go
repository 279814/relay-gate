package store

import (
	"database/sql"

	"github.com/279814/relay-gate/internal/model"
)

func validSampleCaptureView(view string) bool {
	switch view {
	case "legacy", "upstream_response", "upstream_attempt_prefix", "no_response", "omitted_secret", "omitted_unverified":
		return true
	}
	return false
}

// Legacy/direct Store callers do not become raw merely because this binary
// knows how to capture raw responses. Only an explicit actual capture marker
// is saved, in the existing sample transaction with its owning attempt row.
func insertSampleCaptureMetadata(tx *sql.Tx, a *model.SampleAttempt) error {
	view := a.ResponseCaptureView
	if view != "" && (!validSampleCaptureView(view) || (view != "legacy" && a.Metadata.Version != 1)) {
		return model.WrapValidation("sample capture marker/version 无效")
	}
	if err := insertAttemptMetadata(tx, "sample_attempt_metadata", a.ID, a.Metadata); err != nil {
		return err
	}
	if view == "" || view == "legacy" {
		return nil
	}
	_, err := tx.Exec(`UPDATE sample_attempt_metadata SET response_capture_view=? WHERE owner_id=?`, view, a.ID)
	return err
}
