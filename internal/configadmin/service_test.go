package configadmin_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/configadmin"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

type publisher struct{ calls int }

func (p *publisher) Publish() { p.calls++ }

func TestServiceDeletionHonorsClientRevisionBeforePublishing(t *testing.T) {
	for _, kind := range []string{"upstream", "model_name", "route"} {
		t.Run(kind, func(t *testing.T) {
			cipher, err := store.NewCipher("config-admin-fixture-master")
			if err != nil {
				t.Fatal(err)
			}
			st, err := store.Open(filepath.Join(t.TempDir(), "fixture.db"), cipher)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			pub := &publisher{}
			svc := configadmin.New(st, pub)
			ctx := context.Background()
			initial := []configadmin.EndpointMutation{}
			for _, kind := range []model.EndpointKind{model.EndpointModels, model.EndpointMessages, model.EndpointResponses, model.EndpointChatCompletions, model.EndpointCountTokens} {
				initial = append(initial, configadmin.EndpointMutation{Endpoint: kind, AuthProfile: model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "upstream_api_key"}})
			}
			up, err := svc.CreateUpstream(ctx, model.Upstream{Name: "fixture", BaseURL: "https://example.test", APIKey: "fixture-upstream-credential", Enabled: true}, initial)
			if err != nil {
				t.Fatal(err)
			}
			mn, err := svc.CreateModelName(ctx, model.ModelName{Name: "fixture-model", Protocol: model.ProtoAnthropic, Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			route, err := svc.CreateRoute(ctx, model.Route{UpstreamID: up.ID, ModelNameID: mn.ID, Priority: 1, Weight: 100, Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			var remove func(int64) error
			var revision int64
			switch kind {
			case "upstream":
				revision = up.Revision
				remove = func(rev int64) error { return svc.DeleteUpstream(ctx, up.ID, rev) }
			case "model_name":
				revision = mn.Revision
				remove = func(rev int64) error { return svc.DeleteModelName(ctx, mn.ID, rev) }
			case "route":
				revision = route.Revision
				remove = func(rev int64) error { return svc.DeleteRoute(ctx, route.ID, rev) }
			}
			if err := remove(revision + 1); !errors.Is(err, store.ErrRevisionConflict) {
				t.Fatalf("service ignored caller revision: %v", err)
			}
			if pub.calls != 3 {
				t.Fatalf("rejected write was published: %d", pub.calls)
			}
			if _, err := st.GetRoute(route.ID); err != nil {
				t.Fatalf("stale delete changed child route: %v", err)
			}
			wantCalls := 4
			if kind != "route" {
				if err := remove(revision); !errors.Is(err, store.ErrDependencyConflict) || pub.calls != 3 {
					t.Fatalf("referenced parent changed or published: %v calls=%d", err, pub.calls)
				}
				if err := svc.DeleteRoute(ctx, route.ID, route.Revision); err != nil {
					t.Fatal(err)
				}
				wantCalls++
			}
			if err := remove(revision); err != nil {
				t.Fatal(err)
			}
			if pub.calls != wantCalls {
				t.Fatalf("committed delete was not published once: %d", pub.calls)
			}
		})
	}
}
