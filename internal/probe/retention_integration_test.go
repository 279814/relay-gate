package probe

import (
	"context"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

func TestRetentionDeletedExecutionDoesNotEraseCurrentNegativeOnColdRestart(t *testing.T) {
	st := calibrationTestStore(t)
	_, reservedThrough, err := st.ReserveObservationOrders(context.Background(), 4096)
	if err != nil {
		t.Fatal(err)
	}
	up, _, route := seedCalibrationRoute(t, st)
	commitRouteConfigError(t, st, up, route, model.EndpointMessages)
	// The execution's completion time is 2ms after epoch; no wall-clock or
	// private upstream is involved. The current negative has its own token row.
	n, err := st.PruneProbeExecutions(context.Background(), time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC), 500)
	if err != nil || n != 1 {
		t.Fatalf("prune=%d %v", n, err)
	}
	page, err := st.ListProbeExecutions(context.Background(), model.ProbeExecutionFilter{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("execution still present: %+v %v", page, err)
	}
	path := st.DatabasePath()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	cipher, err := store.NewCipher("calibration-test-passphrase-16")
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	caps := restartedRegistry(t, reopened)
	if got := caps.Effective(model.RecipeScopeRoute, route.ID, model.EndpointMessages, ""); got != model.CapabilityConfigError {
		t.Fatalf("negative lost without execution: %s", got)
	}
	start, _, err := reopened.ReserveObservationOrders(context.Background(), 4096)
	if err != nil || start <= reservedThrough {
		t.Fatalf("retention reused observation order: %d <= %d (%v)", start, reservedThrough, err)
	}
}
