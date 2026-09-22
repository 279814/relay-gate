package transform_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/store"
	"github.com/279814/relay-gate/internal/transform"
)

func TestPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.db")
	cipher, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	reg := transform.NewRegistry(20).WithPersist(st)
	set, err := reg.CreateSet("demo")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Demo", Value: "1"}}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, "n1"); err != nil {
		t.Fatal(err)
	}
	b, ver, err := reg.PublishSnapshot(set.ID, 9, 3)
	if err != nil {
		t.Fatal(err)
	}
	if b.PublishedID != ver.ID || ver.ID == 0 {
		t.Fatalf("binding=%+v ver=%+v", b, ver)
	}

	reg2 := transform.NewRegistry(20).WithPersist(st)
	if err := reg2.LoadFromPersist(); err != nil {
		t.Fatal(err)
	}
	c, id, err := reg2.PublishedCompiled(9, 3)
	if err != nil {
		t.Fatal(err)
	}
	if c == nil || id != ver.ID {
		t.Fatalf("reloaded compiled=%v id=%d want %d", c != nil, id, ver.ID)
	}
	c2, _, err := reg2.PublishedCompiled(9, 99)
	if err != nil || c2 != nil {
		t.Fatalf("unbound endpoint should skip: c=%v err=%v", c2, err)
	}
}

type failPersist struct{}

func (failPersist) SaveTransformSnapshot([]transform.Set, []transform.Binding) error {
	return errors.New("persist boom")
}
func (failPersist) LoadTransformSnapshot() ([]transform.Set, []transform.Binding, error) {
	return nil, nil, nil
}

func TestCreateSetSurfacesPersistError(t *testing.T) {
	reg := transform.NewRegistry(4).WithPersist(failPersist{})
	if _, err := reg.CreateSet("x"); err == nil {
		t.Fatal("expected persist error")
	}
	if len(reg.ListSets()) != 0 {
		t.Fatal("failed CreateSet must not leave set in memory")
	}
}
