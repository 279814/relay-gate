package probe

import (
	"testing"
	"time"
)

func TestManualClockFiresOnlyWhenAdvancedToDeadline(t *testing.T) {
	start := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	clock := NewManualClock(start)
	timer := clock.NewTimer(5 * time.Minute)

	clock.Advance(5*time.Minute - time.Millisecond)
	select {
	case <-timer.C():
		t.Fatal("timer fired before its deadline")
	default:
	}

	clock.Advance(time.Millisecond)
	select {
	case got := <-timer.C():
		if !got.Equal(start.Add(5 * time.Minute)) {
			t.Fatalf("fired at %s", got)
		}
	default:
		t.Fatal("timer did not fire at the deadline")
	}

	clock.Advance(time.Hour)
	select {
	case <-timer.C():
		t.Fatal("timer fired a second time")
	default:
	}
}

func TestManualClockStopPreventsFireAndResetRearms(t *testing.T) {
	clock := NewManualClock(time.Unix(0, 0).UTC())
	timer := clock.NewTimer(time.Second)
	if !timer.Stop() {
		t.Fatal("Stop on an active timer returned false")
	}
	clock.Advance(time.Minute)
	select {
	case <-timer.C():
		t.Fatal("stopped timer fired")
	default:
	}
	if timer.Stop() {
		t.Fatal("Stop on an already stopped timer returned true")
	}

	if timer.Reset(2 * time.Second) {
		t.Fatal("Reset of a stopped timer reported it was still active")
	}
	clock.Advance(time.Second)
	select {
	case <-timer.C():
		t.Fatal("timer fired before the reset deadline")
	default:
	}
	clock.Advance(time.Second)
	select {
	case <-timer.C():
	default:
		t.Fatal("timer did not fire at the reset deadline")
	}
}

func TestManualClockDoesNotRefireWhenMovedBackward(t *testing.T) {
	clock := NewManualClock(time.Unix(100, 0).UTC())
	timer := clock.NewTimer(10 * time.Second)
	clock.Advance(-time.Hour)
	clock.Advance(9 * time.Second)
	select {
	case <-timer.C():
		t.Fatal("moving the clock backward then partially forward fired the timer")
	default:
	}
}

func TestWallClockTimerZeroDurationIsPending(t *testing.T) {
	timer := WallClock().NewTimer(0)
	defer timer.Stop()
	select {
	case <-timer.C():
	case <-time.After(time.Second):
		t.Fatal("zero-duration wall timer did not fire")
	}
}
