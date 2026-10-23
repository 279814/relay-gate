package transform_test

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

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

type togglePersist struct{ fail bool }

func (p *togglePersist) SaveTransformSnapshot([]transform.Set, []transform.Binding) error {
	if p.fail {
		return errors.New("persist boom")
	}
	return nil
}
func (p *togglePersist) LoadTransformSnapshot() ([]transform.Set, []transform.Binding, error) {
	return nil, nil, nil
}

// A failed save must leave published/shadow pointers on the previous version
// (an error means the binding did not change); a later successful save switches.
func TestPointerSwitchRestoredOnPersistError(t *testing.T) {
	sink := &togglePersist{}
	reg := transform.NewRegistry(4).WithPersist(sink)
	set, err := reg.CreateSet("x")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Demo", Value: "1"}}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	const route, ep = 7, 2

	// First publish/shadow fails on a fresh binding: nothing may remain.
	sink.fail = true
	if _, _, err := reg.PublishSnapshot(set.ID, route, ep); err == nil {
		t.Fatal("expected publish persist error")
	}
	if _, _, err := reg.ShadowSnapshot(set.ID, route, ep); err == nil {
		t.Fatal("expected shadow persist error")
	}
	if _, ok := reg.GetBinding(route, ep); ok {
		t.Fatal("failed first publish/shadow must not leave a binding")
	}
	if got, _ := reg.GetSet(set.ID); len(got.History) != 0 {
		t.Fatalf("failed snapshots must not stay in history: %d", len(got.History))
	}

	sink.fail = false
	_, v1, err := reg.PublishSnapshot(set.ID, route, ep)
	if err != nil {
		t.Fatal(err)
	}
	_, s1, err := reg.ShadowSnapshot(set.ID, route, ep)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := reg.GetBinding(route, ep)

	sink.fail = true
	if _, _, err := reg.PublishSnapshot(set.ID, route, ep); err == nil {
		t.Fatal("expected publish persist error")
	}
	if _, id, _ := reg.PublishedCompiled(route, ep); id != v1.ID {
		t.Fatalf("failed publish moved published pointer: got %d want %d", id, v1.ID)
	}
	if _, _, err := reg.ShadowSnapshot(set.ID, route, ep); err == nil {
		t.Fatal("expected shadow persist error")
	}
	if _, id, _ := reg.ShadowCompiled(route, ep); id != s1.ID {
		t.Fatalf("failed shadow moved shadow pointer: got %d want %d", id, s1.ID)
	}
	if after, _ := reg.GetBinding(route, ep); *after != *before {
		t.Fatalf("failed saves changed binding: before=%+v after=%+v", before, after)
	}

	sink.fail = false
	_, v2, err := reg.PublishSnapshot(set.ID, route, ep)
	if err != nil {
		t.Fatal(err)
	}
	if _, id, _ := reg.PublishedCompiled(route, ep); id != v2.ID {
		t.Fatalf("successful publish must switch: got %d want %d", id, v2.ID)
	}

	sink.fail = true
	if _, err := reg.Rollback(route, ep, v1.ID); err == nil {
		t.Fatal("expected rollback persist error")
	}
	if _, id, _ := reg.PublishedCompiled(route, ep); id != v2.ID {
		t.Fatalf("failed rollback moved published pointer: got %d want %d", id, v2.ID)
	}
	if _, id, _ := reg.ShadowCompiled(route, ep); id != s1.ID {
		t.Fatalf("failed rollback touched shadow: got %d want %d", id, s1.ID)
	}

	sink.fail = false
	if _, err := reg.Rollback(route, ep, v1.ID); err != nil {
		t.Fatal(err)
	}
	if _, id, _ := reg.PublishedCompiled(route, ep); id != v1.ID {
		t.Fatalf("successful rollback must switch: got %d want %d", id, v1.ID)
	}
}

// A failed ClearPublished save must leave the published pointer and revision
// untouched (and shadow unchanged); a later successful clear sets it to 0.
func TestClearPublishedRestoredOnPersistError(t *testing.T) {
	sink := &togglePersist{}
	reg := transform.NewRegistry(4).WithPersist(sink)
	set, err := reg.CreateSet("x")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Demo", Value: "1"}}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	const route, ep = 7, 2
	_, v1, err := reg.PublishSnapshot(set.ID, route, ep)
	if err != nil {
		t.Fatal(err)
	}
	_, s1, err := reg.ShadowSnapshot(set.ID, route, ep)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := reg.GetBinding(route, ep)

	sink.fail = true
	if _, err := reg.ClearPublished(route, ep); err == nil {
		t.Fatal("expected clear persist error")
	}
	after, _ := reg.GetBinding(route, ep)
	if *after != *before {
		t.Fatalf("failed clear changed binding: before=%+v after=%+v", before, after)
	}
	if _, id, _ := reg.PublishedCompiled(route, ep); id != v1.ID {
		t.Fatalf("failed clear moved published pointer: got %d want %d", id, v1.ID)
	}
	if _, id, _ := reg.ShadowCompiled(route, ep); id != s1.ID {
		t.Fatalf("failed clear touched shadow: got %d want %d", id, s1.ID)
	}

	sink.fail = false
	b, err := reg.ClearPublished(route, ep)
	if err != nil {
		t.Fatal(err)
	}
	if b.PublishedID != 0 || b.Revision != before.Revision+1 || b.ShadowID != s1.ID {
		t.Fatalf("successful clear: got %+v (before %+v)", b, before)
	}
	if c, id, _ := reg.PublishedCompiled(route, ep); c != nil || id != 0 {
		t.Fatalf("successful clear must disable published: id=%d", id)
	}
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

func TestDraftRestoredOnPersistError(t *testing.T) {
	sink := &togglePersist{}
	registry := transform.NewRegistry(4).WithPersist(sink)
	set, err := registry.CreateSet("draft atomicity")
	if err != nil {
		t.Fatal(err)
	}
	before, err := registry.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Before", Value: "saved"}}, transform.FailClosed, transform.FailOpen, "saved note")
	if err != nil {
		t.Fatal(err)
	}
	sink.fail = true
	if _, err := registry.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-After", Value: "rejected"}}, transform.FailOpen, transform.FailClosed, "rejected note"); !errors.Is(err, transform.ErrPersist) {
		t.Fatalf("expected persistence failure: %v", err)
	}
	after, err := registry.GetSet(set.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatal("failed persistence replaced the in-memory draft")
	}
	sink.fail = false
	if _, err := registry.CreateSet("later successful mutation"); err != nil {
		t.Fatal(err)
	}
	after, err = registry.GetSet(set.ID)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("failed draft leaked through a later save")
	}
}

func TestBindingConflictDoesNotAppendUnpublishedHistory(t *testing.T) {
	registry := transform.NewRegistry(4)
	first, err := registry.CreateSet("existing owner")
	if err != nil {
		t.Fatal(err)
	}
	second, err := registry.CreateSet("rejected owner")
	if err != nil {
		t.Fatal(err)
	}
	for _, set := range []*transform.Set{first, second} {
		if _, err := registry.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Test", Value: "saved"}}, transform.FailClosed, transform.FailOpen, ""); err != nil {
			t.Fatal(err)
		}
	}
	const route, endpoint = 31, 7
	if _, _, err := registry.PublishSnapshot(first.ID, route, endpoint); err != nil {
		t.Fatal(err)
	}
	binding, _ := registry.GetBinding(route, endpoint)
	for _, action := range []func(int64, int64, int64) (*transform.Binding, *transform.Version, error){registry.PublishSnapshot, registry.ShadowSnapshot} {
		if _, _, err := action(second.ID, route, endpoint); err == nil {
			t.Fatal("occupied binding accepted another set")
		}
		rejected, err := registry.GetSet(second.ID)
		if err != nil || len(rejected.History) != 0 {
			t.Fatal("rejected bind appended an immutable history version")
		}
		after, _ := registry.GetBinding(route, endpoint)
		if !reflect.DeepEqual(after, binding) {
			t.Fatal("rejected bind changed the existing owner")
		}
	}
}

func TestRejectedDraftNeverLeaksIntoLaterSQLiteSnapshot(t *testing.T) {
	cipher, err := store.NewCipher("transform-draft-rollback-fixture-master")
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "relay.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	registry := transform.NewRegistry(4).WithPersist(db)
	set, err := registry.CreateSet("saved draft")
	if err != nil {
		t.Fatal(err)
	}
	before, err := registry.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Saved", Value: "original"}}, transform.FailClosed, transform.FailOpen, "saved")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().Exec(`CREATE TRIGGER reject_transform_snapshot BEFORE INSERT ON transform_set BEGIN SELECT RAISE(ABORT,'fixture SQL rejection'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Rejected", Value: "failed"}}, transform.FailOpen, transform.FailClosed, "rejected"); !errors.Is(err, transform.ErrPersist) {
		t.Fatalf("SQL rejection not reported: %v", err)
	}
	if _, err := db.DB().Exec(`DROP TRIGGER reject_transform_snapshot`); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.CreateSet("later save"); err != nil {
		t.Fatal(err)
	}
	restarted := transform.NewRegistry(4).WithPersist(db)
	if err := restarted.LoadFromPersist(); err != nil {
		t.Fatal(err)
	}
	got, err := restarted.GetSet(set.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != before.ID || got.Name != before.Name || !reflect.DeepEqual(got.Draft, before.Draft) {
		t.Fatal("a rejected draft entered the database during a later successful mutation")
	}
}

type waitingPersist struct {
	block            bool
	entered, release chan struct{}
}

func (p *waitingPersist) SaveTransformSnapshot([]transform.Set, []transform.Binding) error {
	if p.block {
		close(p.entered)
		<-p.release
	}
	return nil
}
func (*waitingPersist) LoadTransformSnapshot() ([]transform.Set, []transform.Binding, error) {
	return nil, nil, nil
}

func TestRequestSnapshotUsesPublishedStateWithoutWaitingForDraftSQL(t *testing.T) {
	sink := &waitingPersist{entered: make(chan struct{}), release: make(chan struct{})}
	registry := transform.NewRegistry(4).WithPersist(sink)
	set, err := registry.CreateSet("nonblocking publication")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Version", Value: "old"}}
	if _, err := registry.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	_, published, err := registry.PublishSnapshot(set.ID, 3, 7)
	if err != nil {
		t.Fatal(err)
	}
	sink.block = true
	written := make(chan error, 1)
	go func() {
		_, err := registry.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Version", Value: "new"}}, transform.FailClosed, transform.FailOpen, "")
		written <- err
	}()
	<-sink.entered
	snapshots := make(chan *transform.RequestView, 1)
	go func() { snapshots <- registry.CaptureRoutes([]int64{3}) }()
	select {
	case view := <-snapshots:
		_, id, err := view.PublishedCompiled(3, 7)
		if err != nil || id != published.ID {
			close(sink.release)
			<-written
			t.Fatal("read observed an uncommitted publication")
		}
		current, err := registry.GetSet(set.ID)
		if err != nil || current.Draft.Rules[0].Value != "old" {
			close(sink.release)
			<-written
			t.Fatal("read observed a draft whose SQL had not committed")
		}
	case <-time.After(time.Second):
		close(sink.release)
		<-written
		t.Fatal("request-start transform snapshot waited for draft SQL")
	}
	close(sink.release)
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	current, err := registry.GetSet(set.ID)
	if err != nil || current.Draft.Rules[0].Value != "new" {
		t.Fatal("committed draft was not published")
	}
}
