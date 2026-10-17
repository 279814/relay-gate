package probe

import (
	"context"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestPreparedProbe_CostUsesRenderedOutputUpperBound(t *testing.T) {
	for _, field := range []string{"max_tokens", "max_output_tokens", "max_completion_tokens"} {
		t.Run(field, func(t *testing.T) {
			binding := messagesBinding()
			binding.Version.Body = []byte(`{"model":"{{UPSTREAM_MODEL}}","` + field + `":1025,"messages":[{"role":"user","content":"{{PROBE_PROMPT}}"}]}`)
			mn := modelNameFor(model.ProtoAnthropic)
			mn.ProbeMaxTokens = 1
			prepared, _, err := proberWithRecipes(&fakeRecipeSource{routeBinding: binding}, nil).prepare(context.Background(), upstreamFor("http://localhost"), mn, &model.Route{ID: 2}, model.EndpointMessages)
			if err != nil {
				t.Fatal(err)
			}
			if got := prepared.estimatedTokens(mn); got < 1025 {
				t.Fatalf("rendered 1025-token output was estimated as %d", got)
			}
		})
	}
}

func TestRecipeProfile_StreamExpectationMatchesSafeTemplate(t *testing.T) {
	profile := &model.ClientProbeProfile{ID: 9, Revision: 1, Status: model.ProfileTested}
	resolved, err := testResolver(&fakeRecipeSource{profile: profile}).Resolve(context.Background(), RecipeQuery{UpstreamID: 1, RouteID: 2, Endpoint: model.EndpointMessages})
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.StreamExpected {
		t.Fatal("streaming learned template was treated as non-streaming")
	}
}
