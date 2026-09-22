package observationseq

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

type scriptedReserve struct {
	mu    sync.Mutex
	next  int64
	calls atomic.Int32
	hold  chan struct{}
	fail  error
}

func (r *scriptedReserve) ReserveObservationOrders(ctx context.Context, blockSize int64) (int64, int64, error) {
	call := r.calls.Add(1)
	if call > 1 && r.hold != nil {
		select {
		case <-ctx.Done():
			return 0, 0, ctx.Err()
		case <-r.hold:
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return 0, 0, r.fail
	}
	if r.next == 0 {
		r.next = 1
	}
	start := r.next
	end := start + blockSize - 1
	r.next = end + 1
	return start, end, nil
}

func TestSequencerOrdersAreUniqueAcrossBlockBoundary(t *testing.T) {
	seq, err := Open(context.Background(), &scriptedReserve{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(seq.Close)

	const n = int(BlockSize + 10)
	got := make(chan int64, n)
	var wait sync.WaitGroup
	for range n {
		wait.Add(1)
		go func() {
			defer wait.Done()
			order, err := seq.Next(context.Background(), model.TriggerScheduled)
			if err != nil {
				t.Errorf("next: %v", err)
				return
			}
			got <- order
		}()
	}
	wait.Wait()
	close(got)

	seen := map[int64]struct{}{}
	var max int64
	for order := range got {
		if order <= 0 {
			t.Fatalf("non-positive order %d", order)
		}
		if _, ok := seen[order]; ok {
			t.Fatalf("order %d issued twice", order)
		}
		seen[order] = struct{}{}
		if order > max {
			max = order
		}
	}
	if len(seen) != n {
		t.Fatalf("issued %d orders, want %d", len(seen), n)
	}
	if max < BlockSize+1 {
		t.Fatalf("max order %d never crossed the first block", max)
	}
}

func TestRestartLeavesAGapInsteadOfReusingUnusedOrders(t *testing.T) {
	reserve := &scriptedReserve{}
	first, err := Open(context.Background(), reserve)
	if err != nil {
		t.Fatal(err)
	}
	order, err := first.Next(context.Background(), model.TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	if order != 1 {
		t.Fatalf("first order = %d", order)
	}
	first.Close()

	second, err := Open(context.Background(), reserve)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	order, err = second.Next(context.Background(), model.TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	if order != BlockSize+1 {
		t.Fatalf("restart continued at %d, want %d; unused orders from the first block were reused", order, BlockSize+1)
	}
}

func TestRealTrafficDoesNotWaitWhenTheNextBlockIsStillReserved(t *testing.T) {
	reserve := &scriptedReserve{hold: make(chan struct{})}
	seq, err := Open(context.Background(), reserve)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(seq.Close)

	for range BlockSize {
		if _, err := seq.Next(context.Background(), model.TriggerScheduled); err != nil {
			t.Fatal(err)
		}
	}

	started := time.Now()
	_, err = seq.Next(context.Background(), model.TriggerRealTraffic)
	elapsed := time.Since(started)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("real traffic waited %s for a reservation", elapsed)
	}

	close(reserve.hold)
	deadline := time.Now().Add(2 * time.Second)
	var order int64
	for {
		order, err = seq.Next(context.Background(), model.TriggerRealTraffic)
		if err == nil {
			break
		}
		if !errors.Is(err, ErrUnavailable) || time.Now().After(deadline) {
			t.Fatalf("order after reservation: %d, %v", order, err)
		}
		time.Sleep(time.Millisecond)
	}
	if order != BlockSize+1 {
		t.Fatalf("order = %d, want %d", order, BlockSize+1)
	}
}

func TestSyntheticWaitsForThePrefetchedBlockUntilCanceled(t *testing.T) {
	reserve := &scriptedReserve{hold: make(chan struct{})}
	seq, err := Open(context.Background(), reserve)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(seq.Close)
	for range BlockSize {
		if _, err := seq.Next(context.Background(), model.TriggerScheduled); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := seq.Next(ctx, model.TriggerScheduled)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled synthetic next did not return")
	}

	close(reserve.hold)
	order, err := seq.Next(context.Background(), model.TriggerCalibration)
	if err != nil {
		t.Fatal(err)
	}
	if order != BlockSize+1 {
		t.Fatalf("canceled wait consumed or skipped to %d", order)
	}
}

func TestOpenRefusesAFailedReservation(t *testing.T) {
	reserve := &scriptedReserve{fail: errors.New("disk full")}
	seq, err := Open(context.Background(), reserve)
	if err == nil {
		seq.Close()
		t.Fatal("Open succeeded without a reserved block")
	}
}
