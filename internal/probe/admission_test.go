package probe

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestAlwaysOpenAdmissionDoesNotCancelAndReleaseIsIdempotent(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, release, err := AlwaysOpenAdmission().AcquireSynthetic(parent, model.TriggerScheduled)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal("admission canceled a context it was supposed to leave open")
	}
	release()
	release()
	if ctx.Err() != nil {
		t.Fatal("release canceled the attempt context")
	}
}

func TestAlwaysOpenAdmissionRejectsRealTraffic(t *testing.T) {
	_, release, err := AlwaysOpenAdmission().AcquireSynthetic(context.Background(), model.TriggerRealTraffic)
	if !errors.Is(err, ErrRealTrafficNoLease) {
		t.Fatalf("err = %v", err)
	}
	if release != nil {
		t.Fatal("rejected admission returned a release func")
	}
}
