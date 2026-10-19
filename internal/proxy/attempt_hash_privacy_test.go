package proxy

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/sample"
	"github.com/279814/relay-gate/internal/transform"
)

func encodedMetadataSecrets(secret string) map[string]string {
	var jsonEscaped, jsonUpper strings.Builder
	for _, r := range secret {
		fmt.Fprintf(&jsonEscaped, `\u%04x`, r)
		fmt.Fprintf(&jsonUpper, `\u%04X`, r)
	}
	return map[string]string{"url_upper": url.QueryEscape(secret), "url_lower": strings.NewReplacer("%2F", "%2f", "%2B", "%2b", "%3F", "%3f", "%3D", "%3d").Replace(url.QueryEscape(secret)), "json_lower": jsonEscaped.String(), "json_upper": jsonUpper.String()}
}

func TestAttemptHashesUseExistingBodyKeyRulesForEncodedCredentials(t *testing.T) {
	const secret = "fixture-meta-Secret/+Value?=9"
	for name, encoded := range encodedMetadataSecrets(secret) {
		t.Run(name, func(t *testing.T) {
			body := []byte(`{"token":"` + encoded + `"}`)
			keys := []string{secret}
			if bytes.Equal(sample.RedactBodyKeys(body, keys), body) {
				t.Fatal("fixture not recognized by existing sample BodyKeys rules")
			}
			input, output, reason := safeAttemptBodyHashes(body, body, keys, false)
			if input != "" || output != "" || reason != "secret_taint" || safeAttemptBodyHash(body, keys) != "" {
				t.Fatalf("encoded credential was hashed: input=%q output=%q reason=%s", input, output, reason)
			}
		})
	}
	clean := []byte(`{"token":"public-value"}`)
	input, output, reason := safeAttemptBodyHashes(clean, clean, []string{secret}, false)
	if reason != "recorded" || input != transform.HashBytes(clean) || output != transform.HashBytes(clean) {
		t.Fatal("clean hash semantics changed")
	}
}

func TestHTTPAttemptOmitsEncodedCredentialHashesBeforeAndAfterTransform(t *testing.T) {
	const secret = "fixture-meta-Secret/+Value?=9"
	for name, encoded := range encodedMetadataSecrets(secret) {
		t.Run(name, func(t *testing.T) {
			body := `{"note":"before","token":"` + encoded + `"}`
			hs := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(body))
			})
			hs.cfg.snap.Upstreams[10].APIKey = secret
			reg := transform.NewRegistry(8)
			set, _ := reg.CreateSet("encoded-metadata")
			if _, err := reg.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindReplaceBytes, From: "before", To: "after"}}, transform.FailClosed, transform.FailClosed, ""); err != nil {
				t.Fatal(err)
			}
			if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
				t.Fatal(err)
			}
			hs.h.WithTransforms(reg)
			rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","note":"before","token":"` + encoded + `"}`))
			if rec.Code != 200 {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			m := hs.sink.one(t).Metadata
			if m.RequestDiffReason != "secret_taint" || m.ResponseDiffReason != "secret_taint" || m.RequestInputHash != "" || m.RequestOutputHash != "" || m.ResponseInputHash != "" || m.ResponseOutputHash != "" || m.RequestBodyChanged || m.ResponseBodyChanged {
				t.Fatalf("HTTP encoded credential produced a hash/diff: %+v", m)
			}
			for _, record := range reg.ListExecutions(0) {
				if record.InputHash != "" || record.OutputHash != "" {
					t.Fatalf("published diagnostic hashed encoded credential: %+v", record)
				}
			}
		})
	}
}
