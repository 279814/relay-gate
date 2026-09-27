package probe

import (
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/proxy"
)

var _ proxy.RouteConfigErrorMarker = (*CapabilityRegistry)(nil)

// §6.5 / §7.2: a route-local Auth Secret failure on real traffic marks only that
// Route's endpoint config_error, with no TTL, and leaves other endpoints alone.
func TestCapabilityRegistry_MarkRouteConfigError(t *testing.T) {
	settings := model.DefaultSettings()
	reg := NewCapabilityRegistry(capSettings{settings})
	now := time.UnixMilli(1_700_000_000_000)
	reg.now = func() time.Time { return now }

	reg.MarkRouteConfigError(7, 0, model.EndpointMessages)
	if got := reg.Effective(model.RecipeScopeRoute, 7, model.EndpointMessages, ""); got != model.CapabilityConfigError {
		t.Fatalf("messages effective=%s, want config_error", got)
	}
	row := reg.Snapshot(model.RecipeScopeRoute, 7, model.EndpointMessages)
	if row == nil || row.ErrorClass != model.ErrorConfig || row.ExpiresAt != 0 {
		t.Fatalf("snapshot=%+v", row)
	}
	if got := reg.Effective(model.RecipeScopeRoute, 7, model.EndpointChatCompletions, ""); got != model.CapabilityUnknown {
		t.Fatalf("other endpoint leaked: %s", got)
	}
	if got := reg.Effective(model.RecipeScopeRoute, 8, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("other route leaked: %s", got)
	}

	reg.InvalidateScope(model.RecipeScopeRoute, 7)
	if got := reg.Effective(model.RecipeScopeRoute, 7, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("after invalidate effective=%s, want unknown", got)
	}
}
