package api

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/transform"
)

type sqliteFailPersist struct{}

func (sqliteFailPersist) SaveTransformSnapshot([]transform.Set, []transform.Binding) error {
	return errors.New("constraint failed: FOREIGN KEY constraint failed: transform_binding (787)")
}

func (sqliteFailPersist) LoadTransformSnapshot() ([]transform.Set, []transform.Binding, error) {
	return nil, nil, nil
}

// A PersistSink failure carries raw SQLite text; the transform handlers must
// not echo it as a 400 validation message. Registry validation stays 400.
func TestTransformAPI_PersistErrorIsInternalNotValidation(t *testing.T) {
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	reg := transform.NewRegistry(4).WithPersist(sqliteFailPersist{})
	h := New(nil, log).WithTransformRegistry(reg).Routes(testAdminPW)

	rec := do(t, h, "POST", "/admin/api/transforms", `{"name":"leak"}`, true)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("persist failure status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"error":"internal error"`) {
		t.Fatalf("want fixed internal error, got %s", body)
	}
	for _, leak := range []string{"FOREIGN KEY", "constraint failed", "transform_binding", "persist transform snapshot"} {
		if strings.Contains(body, leak) {
			t.Fatalf("client body leaked %q: %s", leak, body)
		}
	}
	if !strings.Contains(logBuf.String(), "内部错误") {
		t.Fatal("expected writeErr default log line")
	}

	rec = do(t, h, "POST", "/admin/api/transforms", `{"name":"  "}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty name status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "name required") {
		t.Fatalf("validation message changed: %s", rec.Body.String())
	}
}
