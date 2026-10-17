package probe

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// Kill an actual process after a real HTTP exchange, while RoundTrip is held
// before returning to Executor. No recorder or Store.Close can run in that
// process: recovery must rely solely on the durable send_started intent.
func TestCalibration_SocketWriteCrashDoesNotReplay(t *testing.T) {
	const helperEnv = "RELAY_GATE_CALIBRATION_SOCKET_CRASH_HELPER"
	openStore := func(path string) *store.Store {
		t.Helper()
		cipher, err := store.NewCipher("calibration-test-passphrase-16")
		if err != nil {
			t.Fatal(err)
		}
		st, err := store.Open(path, cipher)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	if os.Getenv(helperEnv) == "1" {
		st := openStore(os.Getenv("RELAY_GATE_CALIBRATION_CRASH_DB"))
		defer st.Close()
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		svc, _ := newCalibrationHarness(t, st, nil, func(req *http.Request) (*http.Response, error) {
			response, err := transport.RoundTrip(req)
			if err != nil {
				return nil, err
			}
			defer response.Body.Close()
			if err := os.WriteFile(os.Getenv("RELAY_GATE_CALIBRATION_CRASH_READY"), []byte("response_headers_received"), 0600); err != nil {
				return nil, err
			}
			// The parent kills us here. Honour cancellation if it fails to do so,
			// so this test seam cannot leak the Executor's RoundTrip goroutine.
			<-req.Context().Done()
			return nil, req.Context().Err()
		})
		if err := svc.stepOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		t.Fatal("child escaped the socket-write crash barrier")
	}

	var sends atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		sends.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, anthropicSemanticBody())
	}))
	defer upstream.Close()
	directory := t.TempDir()
	path := filepath.Join(directory, "cal.db")
	ready := filepath.Join(directory, "response-received")
	st := openStore(path)
	defer func() { _ = st.Close() }()
	up := &model.Upstream{Name: "socket-crash", BaseURL: upstream.URL,
		APIKey: "synthetic-calibration-crash-key", AuthStyle: model.AuthAuto,
		Enabled: true, ProbeMode: model.ProbeModeActive}
	if err := st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	mn := &model.ModelName{Name: "socket-crash-model", Protocol: model.ProtoAnthropic,
		MatchMode: model.MatchExact, Enabled: true}
	mn.Defaults()
	if err := st.CreateModelName(mn); err != nil {
		t.Fatal(err)
	}
	route := &model.Route{UpstreamID: up.ID, ModelNameID: mn.ID, Enabled: true, Priority: 1, Weight: 1}
	if err := st.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	svc, _ := newCalibrationHarness(t, st, up, nil)
	run, err := svc.Plan(context.Background(), route.ID, model.EndpointMessages, CalibrationPlanOptions{Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(context.Background(), run.ID, run.Revision); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestCalibration_SocketWriteCrashDoesNotReplay$", "-test.count=1")
	child.Env = append(os.Environ(), helperEnv+"=1", "RELAY_GATE_CALIBRATION_CRASH_DB="+path,
		"RELAY_GATE_CALIBRATION_CRASH_READY="+ready)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill()
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	waiting := true
	for waiting {
		select {
		case err := <-done:
			t.Fatalf("child exited before the socket barrier: %v", err)
		case <-deadline.C:
			_ = child.Process.Kill()
			<-done
			t.Fatal("child did not reach the real HTTP response barrier")
		case <-poll.C:
			_, err := os.Stat(ready)
			if err == nil {
				waiting = false
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
		}
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("child must be killed rather than exit gracefully")
	}
	if got := sends.Load(); got != 1 {
		t.Fatalf("the killed process must have sent exactly one real request: %d", got)
	}

	st = openStore(path)
	fresh, err := st.GetCalibrationRun(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	candidate := fresh.Candidates[0]
	if fresh.State != model.CalibrationRunning || candidate.State != model.CalibrationCandidateSendStarted || candidate.ExecutionID == "" {
		t.Fatalf("crash did not preserve the in-flight intent: run=%s candidate=%s execution=%q", fresh.State, candidate.State, candidate.ExecutionID)
	}
	if _, err := st.GetProbeExecution(context.Background(), candidate.ExecutionID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("crash must precede execution insertion: %v", err)
	}
	recovered, counter := newCalibrationHarness(t, st, up, func(*http.Request) (*http.Response, error) {
		t.Error("recovery must not send or try another candidate")
		return nil, errors.New("forbidden replay")
	})
	if err := recovered.stepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	final, err := st.GetCalibrationRun(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.State != model.CalibrationInterrupted || final.Current != 0 || final.Candidates[0].State != model.CalibrationCandidateIndeterminate {
		t.Fatalf("ambiguous send must require an explicit new run: run=%s current=%d candidate=%s", final.State, final.Current, final.Candidates[0].State)
	}
	if _, err := recovered.Start(context.Background(), final.ID, final.Revision); err == nil {
		t.Fatal("interrupted run must not be restartable")
	}
	if err := recovered.advanceRun(context.Background(), final); err != nil {
		t.Fatal(err)
	}
	if err := recovered.stepOnce(context.Background()); !errors.Is(err, errNoCalibrationWork) {
		t.Fatalf("interrupted run must leave the automatic work queue: %v", err)
	}
	if counter.count() != 0 || sends.Load() != 1 {
		t.Fatal("recovery replayed an ambiguous request")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st = openStore(path)
	persisted, err := st.GetCalibrationRun(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.State != model.CalibrationInterrupted || persisted.Candidates[0].State != model.CalibrationCandidateIndeterminate || persisted.Candidates[0].ExecutionID != candidate.ExecutionID {
		t.Fatal("the interrupted decision must survive another cold reopen")
	}
}
