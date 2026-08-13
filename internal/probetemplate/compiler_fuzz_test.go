package probetemplate

import (
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func FuzzCompileTemplateNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"model":"{{UPSTREAM_MODEL}}"}`),
		[]byte(`{{SECRET:tenant}}`),
		[]byte(`{{{{literal`),
		{0, 0xff, '{', '{', 'X', '}', '}'},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		compiled, err := Compile(model.EndpointMessages, model.ProbeRecipeVersion{
			Method:         "POST",
			Body:           body,
			TimeoutProfile: model.TimeoutL2Standard,
		})
		if err != nil {
			return
		}
		for _, name := range compiled.RequiredSecrets() {
			if !validSecretName(name) {
				t.Fatalf("compiler returned invalid secret name %q", name)
			}
		}
	})
}
