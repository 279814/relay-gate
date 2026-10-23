package revisioncodec

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

func NewCanaryEvidenceHash(c model.CanaryExecution) (string, error) {
	nonce, err := hex.DecodeString(c.NonceSHA256)
	if len(c.ExecutionID) == 0 || len(c.ExecutionID) > 64 || !c.Source.Valid() || c.ExpectationVersion != 1 || c.ExpectedTool != model.CanaryTool ||
		err != nil || len(nonce) != 32 || strings.ToLower(c.NonceSHA256) != c.NonceSHA256 ||
		c.Source == model.CanaryManual && c.PolicyRevision != 0 || c.Source == model.CanaryPeriodic && c.PolicyRevision < 1 ||
		!slices.Contains([]string{"passed", "violation", "incomplete", "canceled", "execution_failed", "not_sent"}, c.Verdict) {
		return "", model.WrapValidation("Canary 期待/来源/结论无效")
	}
	if c.Verdict == "passed" && (c.NonceMatched == nil || !*c.NonceMatched || c.ToolMatched == nil || !*c.ToolMatched) {
		return "", model.WrapValidation("Canary passed 缺少严格匹配事实")
	}
	encoder := newCanonicalEncoder("relay-gate/canary-execution/v1")
	encoder.string(c.ExecutionID)
	encoder.string(string(c.Source))
	encoder.int64(c.PolicyRevision)
	encoder.int64(int64(c.ExpectationVersion))
	encoder.string(c.NonceSHA256)
	encoder.string(c.ExpectedTool)
	encoder.string(c.Verdict)
	for _, flag := range []*bool{c.NonceMatched, c.ToolMatched} {
		encoder.boolean(flag != nil)
		if flag != nil {
			encoder.boolean(*flag)
		}
	}
	encoder.boolean(c.InputUsagePresent)
	encoder.boolean(c.OutputUsagePresent)
	// The side fact has an explicit expectation_version and stores raw SHA-256.
	digest := sha256.Sum256(encoder.content)
	return hex.EncodeToString(digest[:]), nil
}
