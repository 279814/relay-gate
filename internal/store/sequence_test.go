package store

import (
	"context"
	"math"
	"sort"
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observationseq"
)

func TestReserveObservationOrdersIsConcurrentAndPersistent(t *testing.T) {
	store := testStore(t)

	type block struct{ start, end int64 }
	blocks := make([]block, 32)
	var wait sync.WaitGroup
	errorsByIndex := make([]error, len(blocks))
	for index := range blocks {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			blocks[index].start, blocks[index].end, errorsByIndex[index] = store.ReserveObservationOrders(context.Background(), 17)
		}(index)
	}
	wait.Wait()
	for _, err := range errorsByIndex {
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Slice(blocks, func(left, right int) bool { return blocks[left].start < blocks[right].start })
	for index, got := range blocks {
		wantStart := int64(index*17 + 1)
		if got.start != wantStart || got.end != wantStart+16 {
			t.Fatalf("block %d = %+v, want %d..%d", index, got, wantStart, wantStart+16)
		}
	}

	start, end, err := store.ReserveObservationOrders(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if start != 32*17+1 || end != start {
		t.Fatalf("persistent next block = %d..%d", start, end)
	}
}

func TestSequencerPersistsAcrossReopenWithoutReusingOrders(t *testing.T) {
	store := testStore(t)
	first, err := observationseq.Open(context.Background(), store)
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

	second, err := observationseq.Open(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	order, err = second.Next(context.Background(), model.TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	if order != observationseq.BlockSize+1 {
		t.Fatalf("reopened sequencer issued %d, want %d", order, observationseq.BlockSize+1)
	}
}

func TestReserveObservationOrdersRejectsInvalidOrOverflowingBlocks(t *testing.T) {
	store := testStore(t)
	for _, size := range []int64{0, -1, 1_000_001} {
		if _, _, err := store.ReserveObservationOrders(context.Background(), size); err == nil {
			t.Errorf("block size %d accepted", size)
		}
	}
	if _, err := store.DB().Exec(`UPDATE observation_sequence SET high_watermark=? WHERE singleton=1`, int64(math.MaxInt64-2)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReserveObservationOrders(context.Background(), 3); err == nil {
		t.Fatal("overflowing reservation accepted")
	}
	var watermark int64
	if err := store.DB().QueryRow(`SELECT high_watermark FROM observation_sequence WHERE singleton=1`).Scan(&watermark); err != nil {
		t.Fatal(err)
	}
	if watermark != math.MaxInt64-2 {
		t.Fatalf("failed reservation changed watermark to %d", watermark)
	}
}
