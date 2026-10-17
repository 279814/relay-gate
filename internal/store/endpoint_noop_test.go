package store

import (
	"errors"
	"reflect"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestEndpointNoOpPreservesIdentityAndCapturedSecretBindings(t *testing.T) {
	st, endpoint, secret := boundEndpointFixture(t)
	before, err := st.GetEndpoint(endpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	input := *before
	input.AuthProfile.ManualHeaders = []model.HeaderTemplate{}
	if err := st.UpdateEndpoint(&input, before.Revision); err != nil {
		t.Fatal(err)
	}
	if input.Revision != before.Revision || input.AuthProfile.Revision != before.AuthProfile.Revision || input.UpdatedAt != before.UpdatedAt {
		t.Fatalf("no-op changed semantic identity: before=%+v after=%+v", before, input)
	}
	if !reflect.DeepEqual(input.BoundSecrets, before.BoundSecrets) {
		t.Fatal("no-op lost captured secret identity")
	}
	rotated, err := st.UpdateProbeSecret(secret.ID, secret.Revision, []byte("fixture-rotated-noop-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateEndpoint(&input, input.Revision); err != nil {
		t.Fatal(err)
	}
	if input.Revision != before.Revision {
		t.Fatal("secret telemetry forced an Endpoint revision")
	}
	requireEndpointBinding(t, &input, secret.ID, rotated.Revision)
	changed := input
	// Use the upstream's existing origin; this test changes only a path.
	up, err := st.GetUpstream(changed.UpstreamID)
	if err != nil {
		t.Fatal(err)
	}
	changed.URLOverride = up.BaseURL + "/custom"
	if err := st.UpdateEndpoint(&changed, input.Revision); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateEndpoint(&input, before.Revision); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("same-value stale write=%v", err)
	}
}

func TestEndpointNoOpDoesNotRepairMissingSecretIdentity(t *testing.T) {
	st, endpoint, _ := boundEndpointFixture(t)
	if _, err := st.db.Exec(`DELETE FROM endpoint_active_secret_ref WHERE endpoint_id=?`, endpoint.ID); err != nil {
		t.Fatal(err)
	}
	current, err := st.GetEndpoint(endpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateEndpoint(current, current.Revision); err != nil {
		t.Fatal(err)
	}
	var refs int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM endpoint_active_secret_ref WHERE endpoint_id=?`, endpoint.ID).Scan(&refs); err != nil || refs != 0 {
		t.Fatalf("no-op rebound an unproven Secret identity: refs=%d err=%v", refs, err)
	}
}
