package livecfg

import (
	"context"
	"testing"
	"time"
)

func TestSource_CachedProbeSnapshotNeverWaitsForDatabase(t *testing.T) {
	st := testStore(t)
	seed(t, st)
	s, now := newSource(t, st)
	pub, err := s.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(DefaultTTL + time.Second)
	// SQLite has one connection: keeping it leased blocks any config reload.
	conn, err := st.DB().Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		snap, err := s.CachedProbeSnapshot()
		if err == nil && snap != pub.Probe {
			t.Error("cached snapshot changed")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		conn.Close()
		<-done
		t.Fatal("cached observation waited for SQLite")
	}
}

func TestSource_CachedProbeSnapshotSkipsRefreshWriter(t *testing.T) {
	st := testStore(t)
	s, _ := newSource(t, st)
	if _, err := s.Bundle(); err != nil {
		t.Fatal(err)
	}
	// Refresh holds this lock while loading SQLite; readers must skip it.
	s.mu.Lock()
	done := make(chan error, 1)
	go func() { _, err := s.CachedProbeSnapshot(); done <- err }()
	select {
	case err := <-done:
		s.mu.Unlock()
		if err != ErrProbeSnapshotUnavailable {
			t.Fatalf("busy snapshot error=%v", err)
		}
	case <-time.After(time.Second):
		s.mu.Unlock()
		<-done
		t.Fatal("cached observation waited for refresh writer")
	}
	s.Invalidate()
	if _, err := s.CachedProbeSnapshot(); err != ErrProbeSnapshotUnavailable {
		t.Fatalf("invalidated snapshot error=%v", err)
	}
}
