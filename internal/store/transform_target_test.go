package store

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/transform"
)

type deletingTransformTargetSink struct {
	*Store
	beforeTargetSave func()
}

func (s deletingTransformTargetSink) SaveTransformSnapshotForTarget(sets []transform.Set, bindings []transform.Binding, routeID, endpointID int64) error {
	s.beforeTargetSave()
	return s.Store.SaveTransformSnapshotForTarget(sets, bindings, routeID, endpointID)
}

func TestTransformTargetDeletedAfterReadCannotCommitOrphan(t *testing.T) {
	st := testStore(t)
	route := mkRoute(t, st)
	page, err := st.ListEndpointsPage(context.Background(), model.EndpointFilter{UpstreamID: route.UpstreamID})
	if err != nil || len(page.Items) == 0 {
		t.Fatalf("endpoints: %+v %v", page, err)
	}
	endpoint := page.Items[0]
	registry := transform.NewRegistry(8).WithPersist(deletingTransformTargetSink{Store: st, beforeTargetSave: func() {
		if err := st.DeleteRouteWithRevision(context.Background(), route.ID, route.Revision); err != nil {
			t.Fatal(err)
		}
	}})
	set, err := registry.CreateSet("target deleted after read")
	if err != nil {
		t.Fatal(err)
	}
	set, err = registry.UpdateDraftAtRevision(set.ID, set.Revision, []transform.Rule{{Kind: transform.KindReplaceBytes, From: "a", To: "b"}}, transform.FailClosed, transform.FailOpen, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.GetRoute(route.ID); err != nil {
		t.Fatal(err)
	} // The API pre-read succeeds.
	_, err = registry.PublishAtRevision(set.ID, route.ID, endpoint.ID, false, transform.PublishPreconditions{SetRevision: set.Revision, BindingRevision: 0})
	if !errors.Is(err, transform.ErrRevisionConflict) {
		t.Fatalf("missing target must conflict: %v", err)
	}
	current, err := registry.GetSet(set.ID)
	if err != nil || current.Revision != set.Revision || len(current.History) != 0 || len(registry.ListBindings()) != 0 {
		t.Fatalf("failed commit changed registry: %+v %v", current, err)
	}
	_, bindings, err := st.LoadTransformSnapshot()
	if err != nil || len(bindings) != 0 {
		t.Fatalf("orphan binding: %+v %v", bindings, err)
	}
}

func TestTransformStrictPublicationRejectsMissingTargetAtCommit(t *testing.T) {
	st := testStore(t)
	registry := transform.NewRegistry(8).WithPersist(st)
	set, err := registry.CreateSet("missing target")
	if err != nil {
		t.Fatal(err)
	}
	set, err = registry.UpdateDraftAtRevision(set.ID, set.Revision, []transform.Rule{{Kind: transform.KindReplaceBytes, From: "a", To: "b"}}, transform.FailClosed, transform.FailOpen, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = registry.PublishAtRevision(set.ID, 999, 888, false, transform.PublishPreconditions{SetRevision: set.Revision, BindingRevision: 0}); err == nil {
		t.Fatal("published to missing target at SQL commit")
	}
	current, err := registry.GetSet(set.ID)
	if err != nil || current.Revision != set.Revision || len(current.History) != 0 || len(registry.ListBindings()) != 0 {
		t.Fatalf("failed target mutated registry: %+v %v", current, err)
	}
	sets, bindings, err := st.LoadTransformSnapshot()
	if err != nil || len(sets) != 1 || len(sets[0].History) != 0 || len(bindings) != 0 {
		t.Fatalf("failed target mutated SQL: sets=%+v bindings=%+v err=%v", sets, bindings, err)
	}
}
