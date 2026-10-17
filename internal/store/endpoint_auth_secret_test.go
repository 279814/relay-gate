package store

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestEndpointAuthSecretBindingProtectsIdentityAndDeduplicates(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "auth-probe-reference")
	secret, err := st.CreateProbeSecret("auth-credential", []byte("fixture-probe-credential"))
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.LegacyCompatRealOnly = false
	endpoint.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "probe:auth-credential"}
	if err := st.UpdateEndpoint(endpoint, endpoint.Revision); err != nil {
		t.Fatal(err)
	}
	bundle, err := st.LoadConfigBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	refs := bundle.EndpointSecretRefs[endpoint.ID]
	if len(refs) != 1 || refs[0].BoundSecretID != secret.ID || refs[0].Name != secret.Name {
		t.Fatalf("Auth Secret was absent from same-generation metadata: %+v", refs)
	}
	if err := st.DeleteProbeSecret(secret.ID, secret.Revision); !errors.Is(err, ErrDependencyConflict) {
		t.Fatalf("active Auth Secret was deletable: %v", err)
	}
	endpoint.FixedQueryTemplate = "auth={{SECRET:auth-credential}}"
	if err := st.UpdateEndpoint(endpoint, endpoint.Revision); err != nil {
		t.Fatalf("same secret in two fields was not deduplicated: %v", err)
	}
}

func TestEndpointMissingOrInvalidAuthSecretRollsBack(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "missing-auth-probe")
	for _, reference := range []string{"probe:missing", "probe:", "probe:bad name", "credential-literal"} {
		before, err := st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
		if err != nil {
			t.Fatal(err)
		}
		changed := *before
		changed.LegacyCompatRealOnly = false
		changed.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: reference}
		if err := st.UpdateEndpoint(&changed, before.Revision); !errors.Is(err, model.ErrValidation) {
			t.Fatalf("unsafe auth reference was saved: %v", err)
		}
		after, err := st.GetEndpoint(before.ID)
		if err != nil || after.Revision != before.Revision || after.AuthProfile.SecretRef != before.AuthProfile.SecretRef {
			t.Fatal("rejected Auth Secret changed the endpoint")
		}
	}
}
