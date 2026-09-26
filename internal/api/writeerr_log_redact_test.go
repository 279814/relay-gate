package api

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// writeErr's default branch must not log raw err text that embeds a known
// upstream API key (docs/01 §2.4). Client body stays the fixed 500 message.
func TestWriteErr_DefaultLogRedactsKnownAPIKey(t *testing.T) {
	const fixtureSecret = "sk-WRITEERR-LOG-SECRET99"

	c, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "writeerr-log.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s := New(st, log)

	up := &model.Upstream{
		Name: "writeerr-log-up", BaseURL: "https://writeerr-log.example",
		APIKey: fixtureSecret, Enabled: true,
	}
	up.Defaults()
	if err := st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}

	wrapped := fmt.Errorf("upstream dial: authorization rejected for key %s", fixtureSecret)
	rec := httptest.NewRecorder()
	s.writeErr(rec, wrapped)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error":"internal error"`) {
		t.Fatalf("client body changed (len=%d)", rec.Body.Len())
	}
	if strings.Contains(logBuf.String(), fixtureSecret) {
		t.Fatal("writeErr default log leaked known upstream API key")
	}
	if !strings.Contains(logBuf.String(), "内部错误") {
		t.Fatal("expected writeErr default log line missing from buffer")
	}
}
