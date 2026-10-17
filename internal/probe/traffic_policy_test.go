package probe

import (
	"context"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestTrafficPolicy_SameConfigurationCannotClearProbeConfigError(t *testing.T) {
	h := newCountTrafficHarness(t)
	h.seedEndpoint(t, model.EndpointMessages, model.CapabilityConfigError)
	h.finish(t, h.beginEndpoint(model.EndpointMessages), 200, `{"type":"message","content":[{"type":"text","text":"ok"}]}`)
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages, ""); got != model.CapabilityConfigError {
		t.Fatalf("real-purpose token cleared same-configuration config_error: %s", got)
	}
	rows, err := h.store.ListEndpointCapabilitiesByState(context.Background(), model.CapabilityConfigError)
	if err != nil || len(rows) != 1 {
		t.Fatalf("sticky error lost in database: %v rows=%d", err, len(rows))
	}
	if rows[0].LastRealOKAt != 0 {
		t.Fatal("sticky configuration error gained piggyback evidence")
	}
	h.seedEndpoint(t, model.EndpointMessages, model.CapabilitySupported)
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages, ""); got != model.CapabilitySupported {
		t.Fatalf("manual retest failed to clear error: %s", got)
	}
}
