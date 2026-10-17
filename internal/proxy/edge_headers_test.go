package proxy

import (
	"net/http"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/transform"
)

func TestPrepareOutboundHeaders_StripsAllForwardingMetadata(t *testing.T) {
	headers := http.Header{
		"Forwarded":               {`for=203.0.113.7;proto=https;host=private.example`},
		"X-Forwarded-Host":        {"private.example"},
		"X-Forwarded-Port":        {"443"},
		"X-Forwarded-Client-Cert": {"private-edge-certificate"},
		"X-Real-IP":               {"203.0.113.7"},
		"User-Agent":              {"fixture-native-client"},
	}
	out := PrepareOutboundHeaders(headers, model.ProtoAnthropic)
	for _, name := range []string{"Forwarded", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Client-Cert", "X-Real-IP"} {
		if out.Get(name) != "" {
			t.Errorf("internal forwarding metadata reached upstream: %s", name)
		}
	}
	if out.Get("User-Agent") != "fixture-native-client" {
		t.Fatal("metadata cleanup changed an ordinary end-to-end header")
	}
}

func TestHandler_StripsForwardedMetadataAtActualUpstreamBoundary(t *testing.T) {
	for _, transformed := range []bool{false, true} {
		t.Run(map[bool]string{false: "external headers", true: "transform reintroduction"}[transformed], func(t *testing.T) {
			hs := newHarness(t, nil)
			if transformed {
				registry := transform.NewRegistry(4)
				set, err := registry.CreateSet("edge-metadata-boundary")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := registry.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSetHeader, Name: "Forwarded", Value: "for=private-client;proto=http"}, {Kind: transform.KindSetHeader, Name: "X-Forwarded-Host", Value: "private.example"}}, transform.FailClosed, transform.FailClosed, ""); err != nil {
					t.Fatal(err)
				}
				if _, _, err := registry.PublishSnapshot(set.ID, 100, 1); err != nil {
					t.Fatal(err)
				}
				hs.h.WithTransforms(registry)
			}
			request := hs.anthropicRequest(`{"model":"claude-opus-5","max_tokens":1}`)
			request.Header.Set("Forwarded", "for=203.0.113.7;proto=https")
			request.Header.Set("X-Forwarded-Host", "private.example")
			request.Header.Set("X-Forwarded-Port", "443")
			response := hs.serve(request)
			if response.Code != http.StatusOK {
				t.Fatalf("proxy failed: %d %s", response.Code, response.Body.String())
			}
			for name := range hs.gotReq.headers {
				if name == "Forwarded" || name == "X-Forwarded-Host" || name == "X-Forwarded-Port" {
					t.Fatalf("forwarding metadata reached real upstream: %s", name)
				}
			}
			if hs.gotReq.headers.Get("User-Agent") != request.Header.Get("User-Agent") {
				t.Fatal("native client header changed")
			}
		})
	}
}
