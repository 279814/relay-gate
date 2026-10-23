package probe

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
	"github.com/279814/relay-gate/internal/transform"
	"github.com/andybalholm/brotli"
)

func originalSampleWire(t *testing.T, encoding string, plain []byte) []byte {
	t.Helper()
	if encoding == "identity" {
		return plain
	}
	var dst bytes.Buffer
	var w io.WriteCloser
	if encoding == "gzip" {
		w = gzip.NewWriter(&dst)
	} else {
		w = brotli.NewWriter(&dst)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return dst.Bytes()
}

func TestOriginalSampleHTTPAndSQLiteKeepRawFactsWhileLogKeepsClientFacts(t *testing.T) {
	const original = `{"type":"message","content":[{"type":"text","text":"before"}]}`
	for _, encoding := range []string{"identity", "gzip", "br"} {
		t.Run(encoding, func(t *testing.T) {
			wire := originalSampleWire(t, encoding, []byte(original))
			h := newTrafficPrivacyHarness(t, func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Sample-View", "original")
				if encoding != "identity" {
					w.Header().Set("Content-Encoding", encoding)
				}
				w.WriteHeader(202)
				w.Write(wire)
			})
			ep, err := h.store.Endpoint(context.Background(), h.up.ID, model.EndpointMessages)
			if err != nil {
				t.Fatal(err)
			}
			reg := transform.NewRegistry(8)
			set, _ := reg.CreateSet("raw-client-split")
			if _, err := reg.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindReplaceBytes, From: "before", To: "after"}, {Kind: transform.KindSetHeader, Name: "X-Sample-View", Value: "client"}, {Kind: transform.KindSetStatus, Value: "201"}}, transform.FailClosed, transform.FailClosed, ""); err != nil {
				t.Fatal(err)
			}
			if _, _, err := reg.PublishSnapshot(set.ID, h.route.ID, ep.ID); err != nil {
				t.Fatal(err)
			}
			h.handler.WithTransforms(reg)
			status, client := h.requestProtocol(t, model.ProtoAnthropic)
			if status != 201 || !bytes.Contains(client, []byte("after")) {
				t.Fatalf("client transform=%d %s", status, client)
			}
			h.flush(t)
			groups, err := h.store.ListSamples(store.SampleFilter{})
			if err != nil || len(groups) != 1 {
				t.Fatalf("groups=%v %v", groups, err)
			}
			full, err := h.store.GetSample(groups[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			wantEncoding := encoding
			if encoding == "identity" {
				wantEncoding = ""
			}
			if full.RespStatus != 202 || full.RespHeaders.Get("X-Sample-View") != "original" || full.RespHeaders.Get("Content-Encoding") != wantEncoding || !bytes.Equal(full.RespBody, wire) || full.Metadata.ResponseView != "upstream_response" {
				t.Fatalf("not persisted raw facts: status=%d header=%v bytes=%d marker=%s", full.RespStatus, full.RespHeaders, len(full.RespBody), full.Metadata.ResponseView)
			}
			metadata, err := h.store.GetSampleMetadata(context.Background(), full.ID)
			if err != nil || metadata.Attempts[0].Metadata.ResponseView != "upstream_response" {
				t.Fatalf("metadata lost raw marker: %v %v", metadata, err)
			}
			logs, err := h.store.ListRequestLogs(store.RequestLogFilter{ReqID: full.ReqID})
			if err != nil || len(logs) != 1 {
				t.Fatalf("logs=%v %v", logs, err)
			}
			if logs[0].RespStatus != 201 || logs[0].BytesWritten != int64(len(client)) || logs[0].Metadata.ResponseView != "client_response" {
				t.Fatalf("raw sample changed client log facts: %+v", logs[0])
			}
			execution := h.execution(t)
			if execution.StatusCode != 202 || execution.ID != logs[0].Metadata.ExecutionID {
				t.Fatalf("raw sample changed original Observer/correlation: %+v", execution)
			}
		})
	}
}

func TestOriginalCompressedSecretEchoIsOmittedByExistingBackgroundWriter(t *testing.T) {
	for _, encoding := range []string{"gzip", "br"} {
		t.Run(encoding, func(t *testing.T) {
			var wire []byte
			h := newTrafficPrivacyHarness(t, func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", encoding)
				w.Write(wire)
			})
			plain := `{"type":"message","content":[{"type":"text","text":"` + h.up.APIKey + `"}]}`
			wire = originalSampleWire(t, encoding, []byte(plain))
			ep, err := h.store.Endpoint(context.Background(), h.up.ID, model.EndpointMessages)
			if err != nil {
				t.Fatal(err)
			}
			reg := transform.NewRegistry(8)
			set, _ := reg.CreateSet("remove client echo")
			if _, err := reg.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindReplaceBytes, From: h.up.APIKey, To: "safe-client-text"}}, transform.FailClosed, transform.FailClosed, ""); err != nil {
				t.Fatal(err)
			}
			if _, _, err := reg.PublishSnapshot(set.ID, h.route.ID, ep.ID); err != nil {
				t.Fatal(err)
			}
			h.handler.WithTransforms(reg)
			if output := h.request(t); bytes.Contains(output, []byte(h.up.APIKey)) || !bytes.Contains(output, []byte("safe-client-text")) {
				t.Fatal("client fixture transform failed")
			}
			h.flush(t)
			groups, err := h.store.ListSamples(store.SampleFilter{})
			if err != nil || len(groups) != 1 {
				t.Fatalf("groups=%v %v", groups, err)
			}
			full, err := h.store.GetSample(groups[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(full.RespBody) != 0 || full.Metadata.ResponseView != "omitted_secret" || !full.Truncated.Has(model.TruncRespBody) {
				t.Fatalf("compressed original secret persisted: bytes=%d marker=%s flags=%d", len(full.RespBody), full.Metadata.ResponseView, full.Truncated)
			}
			assertPrivateValuesAbsent(t, "raw sample/metadata", full, h.up.APIKey)
		})
	}
}

func TestOriginalSampleQuotaCountsOriginalBytesBeforeShrink(t *testing.T) {
	padding := strings.Repeat("p", 4096)
	h := newTrafficPrivacyHarness(t, func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"text":"`+padding+`"}`)
	})
	settings, revision, err := h.store.GetSettingsWithRevision()
	if err != nil {
		t.Fatal(err)
	}
	settings.SampleDiskQuotaBytes = 1024
	settings.SampleRespHeadBytes = 0
	settings.SampleRespTailBytes = 0
	if _, err := h.store.SaveSettingsWithRevision(settings, revision); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.cfg.(interface{ Refresh() error }).Refresh(); err != nil {
		t.Fatal(err)
	}
	ep, err := h.store.Endpoint(context.Background(), h.up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	reg := transform.NewRegistry(8)
	set, _ := reg.CreateSet("shrink client")
	if _, err := reg.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindReplaceBytes, From: padding, To: "small"}}, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, h.route.ID, ep.ID); err != nil {
		t.Fatal(err)
	}
	h.handler.WithTransforms(reg)
	if body := h.request(t); !bytes.Contains(body, []byte("small")) {
		t.Fatal("client response not shrunk")
	}
	h.flush(t)
	groups, err := h.store.ListSamples(store.SampleFilter{})
	if err != nil || len(groups) != 1 {
		t.Fatalf("groups=%v %v", groups, err)
	}
	full, err := h.store.GetSample(groups[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !full.Truncated.Has(model.TruncRespBody) || len(full.RespBody) > 1024 || bytes.Contains(full.RespBody, []byte("small")) || full.Metadata.ResponseView != "upstream_response" {
		t.Fatalf("quota used shrunk client bytes instead of original: body=%d flags=%d marker=%s", len(full.RespBody), full.Truncated, full.Metadata.ResponseView)
	}
}
