package store

import (
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestRequestLogPersistsDuplicateRiskColumns(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "reqlog.db"), mustCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	in := &model.RequestLog{
		ReqID: "r1", Attempt: 1, Attempts: 2,
		TSRecv: 1, Endpoint: "/v1/messages",
		Outcome: model.OutcomeOK, Retried: true,
		DuplicateRisk: true, RetryReason: "policy_retry_after_possible_upstream_accept",
	}
	if err := st.InsertRequestLog(in); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListRequestLogs(RequestLogFilter{ReqID: "r1", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("len=%d", len(list))
	}
	got := list[0]
	if !got.DuplicateRisk || got.RetryReason != in.RetryReason {
		t.Fatalf("got risk=%v reason=%q", got.DuplicateRisk, got.RetryReason)
	}
}

func mustCipher(t *testing.T) *Cipher {
	t.Helper()
	c, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	return c
}
