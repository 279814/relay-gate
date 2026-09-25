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

// §12.7：db_committed 必须前滚 ActivatePending；新 Key 成为 active，不得把
// pending 留成唯一未用密钥，也不得声称已提交数据库可回滚。
func TestRecoverUnfinished_DBCommittedActivatesForward(t *testing.T) {
	const oldMaster = "aaaaaaaaaaaaaaaa"
	const newMaster = "bbbbbbbbbbbbbbbb"
	f := Open(t.TempDir())
	if err := f.EnsureInitialized("mk_a", oldMaster); err != nil {
		t.Fatal(err)
	}
	rid, err := f.BeginRotation(newMaster)
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
	if hold {
		t.Fatal("db_committed forward activate finished; must not keep maintenance hold")
	}
	if st.HasPending {
		t.Fatalf("pending must not remain unused after activate: %+v", st)
	}
	if st.Phase != PhaseKeyActivated {
		t.Fatalf("phase=%s want key_activated", st.Phase)
	}
	id, active, err := f.LoadActive()
	if err != nil || active != newMaster {
		t.Fatalf("active must be new master: id=%s active=%q err=%v", id, active, err)
	}
	if id == "" {
		t.Fatal("empty new key id")
	}
	if active == oldMaster {
		t.Fatal("must not keep old master as sole decryptor after db_committed")
	}
}

// §12.7：key_activated 须 MarkCleaned（与在线轮换 activate 后相同）；新 active
// 不变；不得因未清理而永久 hold maintenance。
func TestRecoverUnfinished_KeyActivatedMarksCleaned(t *testing.T) {
	const newMaster = "bbbbbbbbbbbbbbbb"
	f := Open(t.TempDir())
	if err := f.EnsureInitialized("mk_a", "aaaaaaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	rid, err := f.BeginRotation(newMaster)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.MarkDBCommitted(rid); err != nil {
		t.Fatal(err)
	}
	newID, err := f.ActivatePending(rid)
	if err != nil {
		t.Fatal(err)
	}

	hold, st, err := f.RecoverUnfinished()
	if err != nil {
		t.Fatal(err)
	}
	if hold {
		t.Fatal("key_activated MarkCleaned finished; must not keep maintenance hold")
	}
	if st.Phase != PhaseCleaned {
		t.Fatalf("phase=%s want cleaned", st.Phase)
	}
	if st.RotationID != "" {
		t.Fatalf("rotation_id must clear after cleaned: %+v", st)
	}
	id, active, err := f.LoadActive()
	if err != nil || active != newMaster || id != newID {
		t.Fatalf("active key must stay new: id=%s want=%s active=%q err=%v", id, newID, active, err)
	}
}
