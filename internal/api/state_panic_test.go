package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/runstate"
	"github.com/279814/relay-gate/internal/store"
)

// panicDrainSynth panics from CancelSynthetic with a value that must never
// appear in the /admin/api/state response (stand-in for secrets / request data).
type panicDrainSynth struct{}

func (panicDrainSynth) CancelSynthetic(context.Context, error) error {
	panic("sk-secret-must-not-reach-client")
}

func (panicDrainSynth) PrepareResume()   {}
func (panicDrainSynth) ResumeGradually() {}

func TestSetState_PauseDrainPanicOmitsPanicValue(t *testing.T) {
	c, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	runCtrl, err := runstate.NewController(st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runCtrl.Close)
	if err := runCtrl.BindSyntheticController(panicDrainSynth{}); err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New(st, log).WithRunState(runCtrl)
	h := s.Routes(testAdminPW)

	rev := runCtrl.Current().Revision
	body := `{"state":"paused","expected_revision":` + itoa(rev) + `}`
	rec := do(t, h, http.MethodPost, "/admin/api/state", body, true)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("pause drain pending want 503, got %d body=%s", rec.Code, rec.Body.String())
	}
	const panicSecret = "sk-secret-must-not-reach-client"
	if strings.Contains(rec.Body.String(), panicSecret) {
		t.Fatalf("response must not include panic value: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), runstate.PauseDrainPendingCode) {
		t.Fatalf("response should still report pause_drain_pending: %s", rec.Body.String())
	}
}
