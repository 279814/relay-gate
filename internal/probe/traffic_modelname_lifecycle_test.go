package probe

import (
	"context"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestCapabilityTraffic_ModelNameReEnableRejectsLateResult(t *testing.T) {
	for _, endpoint := range []model.EndpointKind{model.EndpointMessages, model.EndpointCountTokens} {
		t.Run(string(endpoint), func(t *testing.T) {
			h := newCountTrafficHarness(t)
			h.seedEndpoint(t, endpoint, model.CapabilitySupported)
			late := h.beginEndpoint(endpoint)
			mn, err := h.store.GetModelName(h.route.ModelNameID)
			if err != nil {
				t.Fatal(err)
			}
			for _, enabled := range []bool{false, true} {
				mn.Enabled = enabled
				if err := h.store.UpdateModelNameWithRevision(context.Background(), mn, mn.Revision); err != nil {
					t.Fatal(err)
				}
			}
			h.caps.InvalidateScope(model.RecipeScopeRoute, h.route.ID)
			status, body := 404, liveMissingModel
			if endpoint == model.EndpointCountTokens {
				status, body = 401, `{"error":{"type":"authentication_error"}}`
			}
			h.finish(t, late, status, body)
			if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, endpoint, ""); got != model.CapabilityUnknown {
				t.Fatalf("pre-reenable response revived model capability: %s", got)
			}
			if got := restartedRegistry(t, h.store).Effective(model.RecipeScopeRoute, h.route.ID, endpoint, ""); got != model.CapabilityUnknown {
				t.Fatalf("stale model error revived after restart: %s", got)
			}
		})
	}
}
