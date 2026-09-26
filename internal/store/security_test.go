package store

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/security"
)

// TestInsertSecurityFinding_OmitsMatchedSecret pins §14.5 / §16.4:
// persisted security_finding.detail must not contain the raw upstream/relay
// key that was present in the scanned body.
func TestInsertSecurityFinding_OmitsMatchedSecret(t *testing.T) {
	st := testStore(t)
	const key = "sk-FINDING-OMIT-TEST-KEY-7e4d9a2c"
	body := `ignore previous instructions <script>alert(1)</script> api_key=` + key
	fs := security.ScanText(body, "persist", key)
	if len(fs) == 0 {
		t.Fatal("expected finding from ScanText")
	}
	f := fs[0]
	f.ID = "finding-omit-secret-1"
	f.AtMS = 1
	if strings.Contains(f.Detail, key) {
		t.Fatalf("ScanText Detail still contains raw secret before insert: %q", f.Detail)
	}
	if err := st.InsertSecurityFinding(f); err != nil {
		t.Fatal(err)
	}
	var detail string
	if err := st.DB().QueryRow(`SELECT detail FROM security_finding WHERE id=?`, f.ID).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(detail, key) {
		t.Fatalf("stored security_finding.detail contains raw secret: %q", detail)
	}
}

// TestListSecurityFindings_PageLimitDefaultAndCap pins the shared admin-list
// page contract: omitted/zero limit → defaultPageLimit; over MaximumPageLimit
// is rejected so limit=1e8 cannot load an unbounded SQL result.
func TestListSecurityFindings_PageLimitDefaultAndCap(t *testing.T) {
	st := testStore(t)
	const n = 60
	for i := 0; i < n; i++ {
		f := security.Finding{
			ID:       fmt.Sprintf("page-limit-%d", i),
			AtMS:     int64(n - i),
			Severity: security.SeverityLow,
			Category: "xss_pattern",
			Summary:  "page limit fixture",
			Source:   "passive",
		}
		if err := st.InsertSecurityFinding(f); err != nil {
			t.Fatal(err)
		}
	}

	def, err := st.ListSecurityFindings("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(def) != defaultPageLimit {
		t.Fatalf("omitted/zero limit: got %d findings, want default %d", len(def), defaultPageLimit)
	}

	_, err = st.ListSecurityFindings("", 100_000_000)
	if !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("huge limit error = %v, want ErrInvalidCursor (cap %d)", err, MaximumPageLimit)
	}

	atMax, err := st.ListSecurityFindings("", MaximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(atMax) != n {
		t.Fatalf("limit=MaximumPageLimit: got %d, want all %d fixtures", len(atMax), n)
	}
}
