package configadmin_test

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/279814/relay-gate/internal/configadmin"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

func TestSettingsServiceClientRevisionNoopAndRunStateAreIndependent(t *testing.T) {
	cipher, err := store.NewCipher("settings-service-fixture-master")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "settings.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service := configadmin.NewSettings(st)
	ctx := context.Background()
	settings, revision, err := service.GetSettings(ctx)
	if err != nil || revision != 1 {
		t.Fatalf("initial revision=%d err=%v", revision, err)
	}
	_, stateRevision, err := st.GetRunStateWithRevision()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.UpdateSettings(ctx, settings, 0); !errors.Is(err, model.ErrValidation) {
		t.Fatalf("implicit revision accepted: %v", err)
	}
	same, sameRevision, err := service.UpdateSettings(ctx, settings, revision)
	if err != nil || sameRevision != revision || !reflect.DeepEqual(same, settings) {
		t.Fatalf("noop revision=%d err=%v", sameRevision, err)
	}
	settings.CountTokensConnectSec = 2
	settings.CountTokensTotalSec = 11
	stored, newRevision, err := service.UpdateSettings(ctx, settings, revision)
	if err != nil || newRevision != revision+1 {
		t.Fatalf("update revision=%d err=%v", newRevision, err)
	}
	if _, _, err := service.UpdateSettings(ctx, stored, revision); !errors.Is(err, store.ErrRevisionConflict) {
		t.Fatalf("stale equal-value write must conflict: %v", err)
	}
	if _, err := st.SetRunStateWithRevision(model.RunStatePaused, stateRevision); err != nil {
		t.Fatal(err)
	}
	_, unchangedRevision, err := service.GetSettings(ctx)
	if err != nil || unchangedRevision != newRevision {
		t.Fatal("RunState changed Settings revision")
	}
	_, currentStateRevision, err := st.GetRunStateWithRevision()
	if err != nil || currentStateRevision != stateRevision+1 {
		t.Fatal("Settings changed RunState revision")
	}
}
