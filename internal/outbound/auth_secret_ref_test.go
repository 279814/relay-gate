package outbound

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestAuthSecretRefSelectsDeclaredCredential(t *testing.T) {
	for _, mode := range []model.AuthMode{model.AuthModeBearer, model.AuthModeXAPIKey, model.AuthModeAPIKey, model.AuthModeAutoCalibrated} {
		t.Run(string(mode), func(t *testing.T) {
			profile := model.EndpointAuthProfile{Mode: mode, SecretRef: "probe:separate-auth", Revision: 1}
			if mode == model.AuthModeAutoCalibrated {
				profile.CalibratedMode = model.AuthModeBearer
			}
			header := inboundHeaders()
			values := staticValues{"UPSTREAM_API_KEY": {Plain: []byte("fixture-upstream-credential")}, "SECRET:separate-auth": {Plain: []byte("fixture-declared-probe-credential")}}
			if err := ApplyAuth(context.Background(), header, AuthInput{Profile: profile, Values: values}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join([]string{header.Get("Authorization"), header.Get("X-Api-Key"), header.Get("Api-Key")}, ";"), "fixture-declared-probe-credential") || strings.Contains(header.Get("Authorization")+header.Get("X-Api-Key")+header.Get("Api-Key"), "fixture-upstream-credential") {
				t.Fatal("authentication ignored the selected Probe Secret")
			}
		})
	}
}

func TestAuthSecretRefNeverFallsBackOrEchoesResolverErrors(t *testing.T) {
	for _, reference := range []string{"probe:missing", "literal-credential", "probe:", "probe:bad name", "UPSTREAM_API_KEY"} {
		t.Run(reference, func(t *testing.T) {
			header := inboundHeaders()
			err := ApplyAuth(context.Background(), header, AuthInput{Profile: model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: reference}, Values: authValues("fixture-upstream-credential")})
			if !errors.Is(err, ErrAuthConfig) || header.Get("Authorization") != "" || header.Get("X-Api-Key") != "" || header.Get("Api-Key") != "" {
				t.Fatalf("unsafe or missing reference fell back: %v", err)
			}
		})
	}
	const private = "PRIVATE_PROBE_CREDENTIAL_SHOULD_NOT_APPEAR"
	err := ApplyAuth(context.Background(), http.Header{}, AuthInput{Profile: model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "probe:separate-auth"}, Values: leakyValues{plain: private}})
	if err == nil || strings.Contains(err.Error(), private) {
		t.Fatal("credential resolver error was echoed")
	}
}
