package api

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
	"github.com/279814/relay-gate/internal/store"
)

func TestDiagnosticHTTPDoesNotExposeHistoricalShortCredential(t *testing.T) {
	s, _ := newTestServer(t)
	up := metadataUpstream(t, s, "diagnostic-short", "diagnostic-long-fixture-credential")
	cipher, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	s.log = slog.New(slog.NewTextHandler(&logs, nil))
	server := httptest.NewServer(s.Routes(testAdminPW))
	defer server.Close()
	for _, length := range []int{model.MinRedactableKeyLen - 1, model.MinRedactableKeyLen} {
		secret := strings.Repeat("x", length)
		encrypted, err := cipher.Encrypt(secret)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.st.DB().Exec(`UPDATE upstream SET api_key_enc=? WHERE id=?`, encrypted, up.ID); err != nil {
			t.Fatal(err)
		}
		if err := s.st.InsertSecurityFinding(security.Finding{ID: "short-historical", AtMS: 1, Severity: security.SeverityHigh, Category: "xss_pattern", Detail: "opaque " + secret}); err != nil {
			t.Fatal(err)
		}
		request, _ := http.NewRequest("GET", server.URL+"/admin/api/security/findings", nil)
		request.Header.Set("Authorization", "Bearer "+testAdminPW)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		want := 200
		if length < model.MinRedactableKeyLen {
			want = 503
		}
		if response.StatusCode != want || strings.Contains(string(wire), secret) {
			t.Fatalf("diagnostic short-boundary privacy: length=%d status=%d", length, response.StatusCode)
		}
		s.writeErr(httptest.NewRecorder(), fmt.Errorf("opaque error %s", secret))
		if strings.Contains(logs.String(), secret) {
			t.Fatal("diagnostic log exposed historical credential")
		}
	}
}
