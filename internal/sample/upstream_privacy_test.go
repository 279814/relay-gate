package sample

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/andybalholm/brotli"
)

func encodedRawSample(t *testing.T, encoding string, body []byte) []byte {
	t.Helper()
	var dst bytes.Buffer
	if encoding == "gzip" {
		w := gzip.NewWriter(&dst)
		w.Write(body)
		w.Close()
	} else {
		w := brotli.NewWriter(&dst)
		w.Write(body)
		w.Close()
	}
	return dst.Bytes()
}

func TestRecorderValidatesEncodedOriginalResponseBeforePersistence(t *testing.T) {
	const secret = "fixture-original-response-secret"
	for _, encoding := range []string{"gzip", "br"} {
		for _, kind := range []string{"clean", "secret", "truncated", "malformed", "unknown"} {
			t.Run(encoding+"/"+kind, func(t *testing.T) {
				body := []byte(`{"text":"public text"}`)
				if kind == "secret" {
					body = []byte(`{"text":"` + secret + `"}`)
				}
				wire := encodedRawSample(t, encoding, body)
				if kind == "malformed" {
					wire = []byte("invalid codec")
				}
				headerEncoding := encoding
				if kind == "unknown" {
					headerEncoding = "unreviewed"
				}
				a := &model.SampleAttempt{RespStatus: 200, RespHeaders: http.Header{"Content-Encoding": {headerEncoding}}, RespBody: wire, ResponseCaptureView: "upstream_response", Metadata: model.AttemptMetadata{Version: 1, ResponseView: "upstream_response"}}
				if kind == "truncated" {
					a.Truncated |= model.TruncRespBody
					a.ResponseCaptureView = "upstream_attempt_prefix"
				}
				smp := &model.Sample{ResponsePrivacyKeys: []string{secret}, RespBody: wire, Attempts: []*model.SampleAttempt{a}}
				w := &fakeWriter{}
				r := newTestRecorder(w, testSettings())
				r.Record(smp)
				r.Close()
				if w.count() != 1 {
					t.Fatal("guard dropped the whole metadata group")
				}
				got := w.got[0].Attempts[0]
				if kind == "clean" {
					if !bytes.Equal(got.RespBody, wire) || got.ResponseCaptureView != "upstream_response" {
						t.Fatalf("clean raw bytes rewritten/omitted: %+v", got)
					}
				} else {
					want := "omitted_unverified"
					if kind == "secret" {
						want = "omitted_secret"
					}
					if len(got.RespBody) != 0 || got.RespBodyFile != "" || !got.Truncated.Has(model.TruncRespBody) || got.ResponseCaptureView != want || got.Metadata.ResponseView != want {
						t.Fatalf("unsafe compressed body reached writer: len=%d marker=%s metadata=%s", len(got.RespBody), got.ResponseCaptureView, got.Metadata.ResponseView)
					}
				}
				if len(w.got[0].ResponsePrivacyKeys) != 0 {
					t.Fatal("sample writer retained credential values")
				}
				encoded, _ := json.Marshal(w.got[0])
				if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), "response_privacy_keys") {
					t.Fatal("transient credentials serialized")
				}
			})
		}
	}
}

func TestRecorderOmissionReleasesEncodedSpill(t *testing.T) {
	const secret = "fixture-spill-response-secret"
	tee := NewHeadTail(0, 0)
	tee.Write(encodedRawSample(t, "gzip", []byte(`{"text":"`+secret+`"}`)))
	// Produce an actual owned spill through the same HeadTail used in production.
	if !tee.openSpill() {
		t.Fatal("could not open owned spill")
	}
	_, path := tee.DetachBody()
	if path == "" {
		t.Fatal("spill fixture did not spill")
	}
	a := &model.SampleAttempt{RespStatus: 200, RespHeaders: http.Header{"Content-Encoding": {"gzip"}}, RespBodyFile: path, ResponseCaptureView: "upstream_response", Metadata: model.AttemptMetadata{Version: 1}}
	w := &fakeWriter{}
	r := newTestRecorder(w, testSettings())
	r.Record(&model.Sample{ResponsePrivacyKeys: []string{secret}, Attempts: []*model.SampleAttempt{a}})
	r.Close()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("omitted secret spill retained: %v", err)
	}
	if a.ResponseCaptureView != "omitted_secret" || a.RespBodyFile != "" {
		t.Fatalf("spill omission not recorded: %+v", a)
	}
}

func TestEncodedOriginalGuardFindsEscapedSecretAcrossReadWindows(t *testing.T) {
	const secret = "fixture-window-Secret/+Value?=9"
	escaped := url.QueryEscape(secret)
	decoded := append(bytes.Repeat([]byte("x"), SpillMemLimit()-len(escaped)/2), []byte(escaped)...)
	a := &model.SampleAttempt{RespStatus: 200, RespHeaders: http.Header{"Content-Encoding": {"gzip"}}, RespBody: encodedRawSample(t, "gzip", decoded), ResponseCaptureView: "upstream_response", Metadata: model.AttemptMetadata{Version: 1}}
	w := &fakeWriter{}
	r := newTestRecorder(w, testSettings())
	r.Record(&model.Sample{ResponsePrivacyKeys: []string{secret}, Attempts: []*model.SampleAttempt{a}})
	r.Close()
	if a.ResponseCaptureView != "omitted_secret" || len(a.RespBody) != 0 {
		t.Fatal("escaped secret across decoder windows reached the writer")
	}
}

func TestEncodedOriginalGuardHasFiniteDecodedWork(t *testing.T) {
	var wire bytes.Buffer
	encoded := gzip.NewWriter(&wire)
	chunk := bytes.Repeat([]byte("p"), 1<<20)
	for i := 0; i <= maxRawSampleDecoded/len(chunk); i++ {
		encoded.Write(chunk)
	}
	encoded.Close()
	a := &model.SampleAttempt{RespStatus: 200, RespHeaders: http.Header{"Content-Encoding": {"gzip"}}, RespBody: wire.Bytes(), ResponseCaptureView: "upstream_response", Metadata: model.AttemptMetadata{Version: 1}}
	w := &fakeWriter{}
	r := newTestRecorder(w, testSettings())
	r.Record(&model.Sample{ResponsePrivacyKeys: []string{"fixture-budget-secret"}, Attempts: []*model.SampleAttempt{a}})
	r.Close()
	if a.ResponseCaptureView != "omitted_unverified" || len(a.RespBody) != 0 {
		t.Fatal("decoded validation overrun retained an unverified raw body")
	}
}

func TestRawPrivacyKeysAreReleasedForQueueAndWriterRejections(t *testing.T) {
	w := &mixedDropWriter{fakeWriter: &fakeWriter{}, started: make(chan struct{}), release: make(chan struct{})}
	settings := testSettings()
	settings.SampleQueueSize = 1
	r := newTestRecorder(w, settings)
	first := &model.Sample{ReqID: "write-error", ResponsePrivacyKeys: []string{"fixture-key-first"}}
	queued := &model.Sample{ReqID: "quota-skip", ResponsePrivacyKeys: []string{"fixture-key-queued"}}
	dropped := &model.Sample{ReqID: "queue-drop", ResponsePrivacyKeys: []string{"fixture-key-dropped"}}
	r.Record(first)
	select {
	case <-w.started:
	case <-time.After(time.Second):
		t.Fatal("writer did not start")
	}
	r.Record(queued)
	r.Record(dropped)
	if len(dropped.ResponsePrivacyKeys) != 0 {
		t.Fatal("queue rejection retained private key references")
	}
	close(w.release)
	r.Close()
	if len(first.ResponsePrivacyKeys) != 0 || len(queued.ResponsePrivacyKeys) != 0 {
		t.Fatal("writer/quota rejection retained private key references")
	}
}
