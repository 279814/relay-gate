package keyring

import (
	"path/filepath"
	"testing"
)

func TestRotationHappyPath(t *testing.T) {
	f := Open(t.TempDir())
	if err := f.EnsureInitialized("mk_boot", "master-old-secret-value!!!!"); err != nil {
		t.Fatal(err)
	}
	rid, err := f.BeginRotation("master-new-secret-value!!!!")
	if err != nil {
		t.Fatal(err)
	}
	st, _ := f.Status()
	if st.Phase != PhasePrepared || !st.HasPending {
		t.Fatalf("%+v", st)
	}
	if err := f.MarkDBCommitted(rid); err != nil {
		t.Fatal(err)
	}
	newID, err := f.ActivatePending(rid)
	if err != nil {
		t.Fatal(err)
	}
	if newID == "" {
		t.Fatal("empty new id")
	}
	id, active, err := f.LoadActive()
	if err != nil || active != "master-new-secret-value!!!!" || id != newID {
		t.Fatalf("id=%s active=%q err=%v", id, active, err)
	}
	if err := f.MarkCleaned(rid); err != nil {
		t.Fatal(err)
	}
	st, _ = f.Status()
	if st.Phase != PhaseCleaned {
		t.Fatalf("phase=%s", st.Phase)
	}
}

func TestAbortPrepared(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	f := Open(dir)
	_ = f.EnsureInitialized("mk_a", "aaaaaaaaaaaaaaaa")
	rid, err := f.BeginRotation("bbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AbortPrepared(rid); err != nil {
		t.Fatal(err)
	}
	_, active, err := f.LoadActive()
	if err != nil || active != "aaaaaaaaaaaaaaaa" {
		t.Fatalf("active=%q err=%v", active, err)
	}
}
