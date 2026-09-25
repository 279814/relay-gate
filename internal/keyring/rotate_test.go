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

// §12.7：启动发现 phase=prepared（库未提交）须 AbortPrepared；旧 active 仍可用；
// 干净 keyring 不得要求 hold maintenance。
func TestRecoverUnfinished_PreparedAbortsWithoutMaintenance(t *testing.T) {
	const oldMaster = "aaaaaaaaaaaaaaaa"
	f := Open(t.TempDir())
	if err := f.EnsureInitialized("mk_a", oldMaster); err != nil {
		t.Fatal(err)
	}
	if _, err := f.BeginRotation("bbbbbbbbbbbbbbbb"); err != nil {
		t.Fatal(err)
	}

	hold, st, err := f.RecoverUnfinished()
	if err != nil {
		t.Fatal(err)
	}
	if hold {
		t.Fatal("prepared recovery must not hold maintenance")
	}
	if st.HasPending || st.Phase != PhaseIdle || st.RotationID != "" {
		t.Fatalf("pending not cleared: %+v", st)
	}
	_, active, err := f.LoadActive()
	if err != nil || active != oldMaster {
		t.Fatalf("old active must remain decryptable: active=%q err=%v", active, err)
	}

	// Clean keyring (idle / no rotation) starts without maintenance hold.
	f2 := Open(t.TempDir())
	if err := f2.EnsureInitialized("mk_b", "cccccccccccccccc"); err != nil {
		t.Fatal(err)
	}
	hold2, st2, err := f2.RecoverUnfinished()
	if err != nil {
		t.Fatal(err)
	}
	if hold2 {
		t.Fatalf("clean keyring must not force maintenance: %+v", st2)
	}
	if st2.HasPending {
		t.Fatalf("clean keyring has pending: %+v", st2)
	}
}

func TestRecoverUnfinished_DBCommittedHoldsMaintenance(t *testing.T) {
	f := Open(t.TempDir())
	if err := f.EnsureInitialized("mk_a", "aaaaaaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	rid, err := f.BeginRotation("bbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.MarkDBCommitted(rid); err != nil {
		t.Fatal(err)
	}
	hold, st, err := f.RecoverUnfinished()
	if err != nil {
		t.Fatal(err)
	}
	if !hold {
		t.Fatal("db_committed must hold maintenance for forward recovery")
	}
	if !st.HasPending || st.Phase != PhaseDBCommitted {
		t.Fatalf("must leave pending for forward recovery: %+v", st)
	}
}
