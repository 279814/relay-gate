package probe

import (
	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"testing"
)

func TestLocalAuthConfigFailureCommitsOnlyCapturedRouteEndpoint(t *testing.T) {
	h := newCountTrafficHarness(t)
	h.seedEndpoint(t, model.EndpointMessages, model.CapabilitySupported)
	observer := h.beginEndpoint(model.EndpointMessages)
	observer.Finish(health.AttemptFinish{ConfigError: true})
	h.commitQueued(t)
	row := h.caps.Snapshot(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages)
	if row == nil || row.State != model.CapabilityConfigError || row.ErrorClass != model.ErrorConfig || row.ExpiresAt != 0 || row.ObservationToken == "" {
		t.Fatalf("local config_error not ordered/persisted: %+v", row)
	}
	for _, target := range []struct {
		id       int64
		endpoint model.EndpointKind
	}{{h.route.ID, model.EndpointChatCompletions}, {h.route.ID + 1, model.EndpointMessages}} {
		if got := h.caps.Effective(model.RecipeScopeRoute, target.id, target.endpoint, ""); got != model.CapabilityUnknown {
			t.Fatalf("unrelated endpoint leaked: %s", got)
		}
	}
	h.caps.InvalidateScope(model.RecipeScopeRoute, h.route.ID)
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("invalidated state=%s", got)
	}
}
