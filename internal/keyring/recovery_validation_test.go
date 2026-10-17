package keyring

import (
	"errors"
	"testing"
)

// A committed database cannot be activated or declared clean without proving
// that the matching master opens every protected value.
func TestRecoverUnfinished_RefusesCommittedRotationWithoutVerification(t *testing.T) {
	f := Open(t.TempDir())
	if err := f.EnsureInitialized("initial", "old-master-verification-aaaa"); err != nil {
		t.Fatal(err)
	}
	rid, err := f.BeginRotation("new-master-verification-bbbb")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.MarkDBCommitted(rid); err != nil {
		t.Fatal(err)
	}
	hold, _, err := f.RecoverUnfinishedAgainst(rid)
	if err == nil || !hold {
		t.Fatalf("unverified committed rotation must remain closed: hold=%v err=%v", hold, err)
	}
	st, err := f.Status()
	if err != nil || st.Phase != PhaseDBCommitted || !st.HasPending {
		t.Fatalf("unverified recovery changed the journal: %+v err=%v", st, err)
	}
}

func TestRecoverValidated_VerificationFailurePreservesRecoverablePhase(t *testing.T) {
	for _, phase := range []RotationPhase{PhasePrepared, PhaseDBCommitted, PhaseKeyActivated} {
		t.Run(string(phase), func(t *testing.T) {
			f := Open(t.TempDir())
			if err := f.EnsureInitialized("initial", "old-master-verification-aaaa"); err != nil {
				t.Fatal(err)
			}
			rid, err := f.BeginRotation("new-master-verification-bbbb")
			if err != nil {
				t.Fatal(err)
			}
			if phase != PhasePrepared {
				if err := f.MarkDBCommitted(rid); err != nil {
					t.Fatal(err)
				}
			}
			if phase == PhaseKeyActivated {
				if _, err := f.ActivatePending(rid); err != nil {
					t.Fatal(err)
				}
			}
			hold, _, err := f.RecoverUnfinishedValidated(rid, func(master string) error {
				if master != "new-master-verification-bbbb" {
					t.Fatal("recovery verified the wrong master")
				}
				return errors.New("ciphertext authentication failed")
			})
			if err == nil || !hold {
				t.Fatalf("failed verification admitted traffic: hold=%v err=%v", hold, err)
			}
			st, err := f.Status()
			if err != nil || st.Phase != phase || st.RotationID != rid {
				t.Fatalf("failed verification changed the recovery journal: %+v err=%v", st, err)
			}
		})
	}
}

func TestRecoverValidated_ActivationMustBeVerifiedBeforeCleanup(t *testing.T) {
	f := Open(t.TempDir())
	if err := f.EnsureInitialized("initial", "old-master-verification-aaaa"); err != nil {
		t.Fatal(err)
	}
	rid, err := f.BeginRotation("new-master-verification-bbbb")
	if err != nil {
		t.Fatal(err)
	}
	var phases []RotationPhase
	hold, _, err := f.RecoverUnfinishedValidated(rid, func(master string) error {
		st, err := f.Status() // The verifier must not run with the keyring mutex held.
		if err != nil {
			return err
		}
		phases = append(phases, st.Phase)
		if st.Phase == PhaseKeyActivated {
			return errors.New("injected post-activation verification failure")
		}
		return nil
	})
	if err == nil || !hold || len(phases) != 2 || phases[0] != PhasePrepared || phases[1] != PhaseKeyActivated {
		t.Fatalf("activation verification order=%v hold=%v err=%v", phases, hold, err)
	}
	st, err := f.Status()
	if err != nil || st.Phase != PhaseKeyActivated || st.RotationID != rid {
		t.Fatalf("failed final verification was marked clean: %+v err=%v", st, err)
	}
	hold, st, err = f.RecoverUnfinishedValidated(rid, func(master string) error {
		if master != "new-master-verification-bbbb" {
			t.Fatal("retry did not use the activated master")
		}
		return nil
	})
	if err != nil || hold || st.Phase != PhaseCleaned || st.RotationID != "" {
		t.Fatalf("verified recovery did not finish: %+v hold=%v err=%v", st, hold, err)
	}
}

func TestRecoverValidated_MismatchedCommittedDatabaseCannotActivate(t *testing.T) {
	f := Open(t.TempDir())
	if err := f.EnsureInitialized("initial", "old-master-verification-aaaa"); err != nil {
		t.Fatal(err)
	}
	rid, err := f.BeginRotation("new-master-verification-bbbb")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.MarkDBCommitted(rid); err != nil {
		t.Fatal(err)
	}
	hold, _, err := f.RecoverUnfinishedValidated("another-database-rotation", func(string) error {
		t.Fatal("mismatched database must be rejected before verification")
		return nil
	})
	if err == nil || !hold {
		t.Fatalf("mismatched journal admitted traffic: hold=%v err=%v", hold, err)
	}
	st, err := f.Status()
	if err != nil || st.Phase != PhaseDBCommitted || !st.HasPending {
		t.Fatalf("mismatched recovery consumed the pending master: %+v err=%v", st, err)
	}
}
