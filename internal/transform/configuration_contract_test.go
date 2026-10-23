package transform_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
	"github.com/279814/relay-gate/internal/transform"
)

func TestPublicationCopiesCannotRewriteImmutableHistory(t *testing.T) {
	for _, which := range []string{"publication", "compiled"} {
		t.Run(which, func(t *testing.T) {
			registry := transform.NewRegistry(8)
			set, err := registry.CreateSet("immutable result")
			if err != nil {
				t.Fatal(err)
			}
			set, err = registry.UpdateDraftAtRevision(set.ID, set.Revision, []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Immutable", Value: "original"}}, transform.FailClosed, transform.FailOpen, "")
			if err != nil {
				t.Fatal(err)
			}
			published, err := registry.PublishAtRevision(set.ID, 3, 7, false, transform.PublishPreconditions{SetRevision: set.Revision, BindingRevision: 0})
			if err != nil {
				t.Fatal(err)
			}
			if which == "publication" {
				published.Version.Rules[0].Value = "caller rewrite"
			} else {
				compiled, _, err := registry.PublishedCompiled(3, 7)
				if err != nil {
					t.Fatal(err)
				}
				compiled.Version.Rules[0].Value = "caller rewrite"
			}
			stored, err := registry.GetSet(set.ID)
			if err != nil || stored.History[0].Rules[0].Value != "original" {
				t.Fatal("an exported result rewrote immutable history")
			}
		})
	}
}

func TestPublishCASPersistsOneWinnerAndLifecycleKeepsFrozenRequest(t *testing.T) {
	cipher, err := store.NewCipher("registry-cas-fixture-master-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "registry.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Strict administrative publications require real owned targets, even when
	// the test is focused on CAS and in-flight lifecycle behavior.
	up := &model.Upstream{Name: "cas-target", BaseURL: "https://fixture.invalid", APIKey: "fixture-cas-only", Enabled: true}
	if err := db.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	name := &model.ModelName{Name: "cas-model", Protocol: model.ProtoAnthropic}
	if err := db.CreateModelName(name); err != nil {
		t.Fatal(err)
	}
	route := &model.Route{UpstreamID: up.ID, ModelNameID: name.ID, Enabled: true}
	if err := db.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	endpoints, err := db.ListEndpointsPage(context.Background(), model.EndpointFilter{UpstreamID: up.ID})
	if err != nil || len(endpoints.Items) == 0 {
		t.Fatalf("targets: %+v %v", endpoints, err)
	}
	endpoint := endpoints.Items[0]
	registry := transform.NewRegistry(8).WithPersist(db)
	set, err := registry.CreateSet("concurrent publish")
	if err != nil {
		t.Fatal(err)
	}
	set, err = registry.UpdateDraftAtRevision(set.ID, set.Revision, []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Original", Value: "original"}}, transform.FailClosed, transform.FailOpen, "")
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := registry.PublishAtRevision(set.ID, route.ID, endpoint.ID, false, transform.PublishPreconditions{SetRevision: set.Revision, BindingRevision: 0})
			results <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)
	wins, conflicts := 0, 0
	for err := range results {
		if err == nil {
			wins++
		} else if errors.Is(err, transform.ErrRevisionConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("publish wins/conflicts=%d/%d", wins, conflicts)
	}
	persisted := transform.NewRegistry(8).WithPersist(db)
	if err := persisted.LoadFromPersist(); err != nil {
		t.Fatal(err)
	}
	current, err := persisted.GetSet(set.ID)
	if err != nil || current.Revision != 3 || len(current.History) != 1 {
		t.Fatal("restart did not retain the unique publish")
	}
	binding, _ := registry.GetBinding(route.ID, endpoint.ID)
	frozen := registry.CaptureRoutes([]int64{route.ID})
	disabled, err := registry.SetLifecycleAtRevision(set.ID, current.Revision, transform.LifecycleDisabled)
	if err != nil {
		t.Fatal(err)
	}
	if compiled, _, err := registry.CaptureRoutes([]int64{route.ID}).PublishedCompiled(route.ID, endpoint.ID); err != nil || compiled != nil {
		t.Fatal("new request used a disabled transform")
	}
	if compiled, id, err := frozen.PublishedCompiled(route.ID, endpoint.ID); err != nil || compiled == nil || id != binding.PublishedID {
		t.Fatal("disable changed an in-flight request")
	}
	enabled, err := registry.SetLifecycleAtRevision(set.ID, disabled.Revision, transform.LifecycleActive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RollbackAtRevision(route.ID, endpoint.ID, binding.PublishedID, binding.Revision); !errors.Is(err, transform.ErrRevisionConflict) {
		t.Fatalf("old binding revision survived lifecycle: %v", err)
	}
	if _, err := registry.SetLifecycleAtRevision(set.ID, enabled.Revision, transform.LifecycleArchived); err != nil {
		t.Fatal(err)
	}
	latest, _ := registry.GetSet(set.ID)
	if _, err := registry.PublishAtRevision(set.ID, route.ID, endpoint.ID, false, transform.PublishPreconditions{SetRevision: latest.Revision, BindingRevision: 3}); err == nil {
		t.Fatal("archived set was republished")
	}
	after, _ := registry.GetSet(set.ID)
	if len(after.History) != 1 || after.History[0].Rules[0].Value != "original" {
		t.Fatal("lifecycle changed history")
	}
}
