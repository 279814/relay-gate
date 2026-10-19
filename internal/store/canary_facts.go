package store

import (
	"context"
	"database/sql"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

func insertCanaryExecutionTx(ctx context.Context, tx *sql.Tx, e *model.ProbeExecution) error {
	c := e.Canary
	if c == nil {
		return nil
	}
	hash, err := revisioncodec.NewCanaryEvidenceHash(*c)
	if err != nil {
		return err
	}
	if hash != c.EvidenceHash || c.ExecutionID != e.ID || e.RouteID <= 0 || e.UpstreamID <= 0 ||
		c.Source == model.CanaryManual && e.Trigger != model.TriggerManual || c.Source == model.CanaryPeriodic && e.Trigger != model.TriggerScheduled ||
		e.Endpoint != model.EndpointMessages && e.Endpoint != model.EndpointResponses && e.Endpoint != model.EndpointChatCompletions ||
		c.Verdict == "passed" && (!e.Success || !e.NormalEndSeen || e.ObserverIncomplete) {
		return model.WrapValidation("Canary 不可变事实与本次执行不匹配")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO canary_execution(`+canaryExecutionCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.ExecutionID, c.Source, c.PolicyRevision, c.ExpectationVersion, c.NonceSHA256, c.ExpectedTool, c.Verdict, c.NonceMatched, c.ToolMatched, c.InputUsagePresent, c.OutputUsagePresent, c.EvidenceHash)
	return err
}

func verifyCanaryReplayTx(ctx context.Context, tx *sql.Tx, e model.ProbeExecution) error {
	stored, err := loadCanaryExecution(ctx, tx, e.ID)
	if err != nil {
		return err
	}
	if stored == nil && e.Canary == nil {
		return nil
	}
	if stored == nil || e.Canary == nil {
		return ErrIdempotencyConflict
	}
	hash, err := revisioncodec.NewCanaryEvidenceHash(*e.Canary)
	if err != nil || hash != e.Canary.EvidenceHash || hash != stored.EvidenceHash {
		return ErrIdempotencyConflict
	}
	return nil
}
