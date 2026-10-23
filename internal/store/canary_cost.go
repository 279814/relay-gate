package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"

	"github.com/279814/relay-gate/internal/model"
)

const canaryExecutionCols = `execution_id,source,policy_revision,expectation_version,nonce_sha256,expected_tool,verdict,nonce_matched,tool_matched,input_usage_present,output_usage_present,evidence_hash`

func loadCanaryExecution(ctx context.Context, tx interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, id string) (*model.CanaryExecution, error) {
	var c model.CanaryExecution
	err := tx.QueryRowContext(ctx, `SELECT `+canaryExecutionCols+` FROM canary_execution WHERE execution_id=?`, id).Scan(&c.ExecutionID, &c.Source, &c.PolicyRevision, &c.ExpectationVersion, &c.NonceSHA256, &c.ExpectedTool, &c.Verdict, &c.NonceMatched, &c.ToolMatched, &c.InputUsagePresent, &c.OutputUsagePresent, &c.EvidenceHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// The existing cost event remains the only idempotency gate. This hash binds
// Canary's separate source/verdict facts without changing historical V1 hashes.
func canaryCostHash(base string, c *model.CanaryExecution) string {
	digest := sha256.Sum256([]byte("relay-canary-cost-v1\x00" + base + "\x00" + string(c.Source) + "\x00" + c.EvidenceHash))
	return hex.EncodeToString(digest[:])
}

func rollupCanaryCostTx(ctx context.Context, tx *sql.Tx, e model.ProbeCostEvidenceV1, c *model.CanaryExecution) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO canary_cost_daily(day_utc,source,endpoint,route_id,upstream_id,executions,requests,passed,violated,incomplete,canceled,execution_failed,estimated_input_tokens,observed_output_tokens,unknown_input_rows,unknown_output_rows)
 VALUES(?,?,?,?,?,1,1,?,?,?,?,?,?,?,?,?) ON CONFLICT(day_utc,source,endpoint,route_id,upstream_id) DO UPDATE SET
 executions=executions+1,requests=requests+1,passed=passed+excluded.passed,violated=violated+excluded.violated,incomplete=incomplete+excluded.incomplete,
 canceled=canceled+excluded.canceled,execution_failed=execution_failed+excluded.execution_failed,
 estimated_input_tokens=estimated_input_tokens+excluded.estimated_input_tokens,observed_output_tokens=observed_output_tokens+excluded.observed_output_tokens,
 unknown_input_rows=unknown_input_rows+excluded.unknown_input_rows,unknown_output_rows=unknown_output_rows+excluded.unknown_output_rows`,
		e.DayUTC, c.Source, e.Endpoint, e.RouteID, e.UpstreamID, c.Verdict == "passed", c.Verdict == "violation", c.Verdict == "incomplete", c.Verdict == "canceled", c.Verdict == "execution_failed",
		e.EstimatedInputTokens, e.ObservedOutputTokens, e.EstimatedInputTokens == 0, !c.OutputUsagePresent)
	return err
}
