package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func settingsHTTPPut(t *testing.T, target, body string) (int, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPut, target+"/admin/api/settings", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testAdminPW)
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 3 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	output, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, output
}

func TestSettingsHTTP_StageBudgetsPersistAndPublishWithoutLosingUnspecifiedFields(t *testing.T) {
	server, handler, source, publisher := newLivecfgServer(t)
	seed := model.DefaultSettings()
	seed.RealResponseHeaderSec = 620
	seed.RealFirstByteSec = 650
	seed.RealFirstSemanticSec = 700
	seed.RealFirstTokenSec = 700
	seed.L2ResponseHeaderSec = 21
	seed.L2FirstByteSec = 23
	seed.L2FirstEventSec = 25
	seed.L2FirstSemanticSec = 27
	seed.L2FirstTokenSec = 27
	seed.CountTokensConnectSec = 8
	seed.CountTokensTotalSec = 19
	seed.CountTokensSec = 19
	seed.RequestLogKeepCount = 321
	seed.SampleKeepCount = 123
	_, revision, err := server.st.GetSettingsWithRevision()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.st.SaveSettingsWithRevision(seed, revision); err != nil {
		t.Fatal(err)
	}
	warm, err := source.Settings()
	if err != nil {
		t.Fatal(err)
	}
	remote := httptest.NewServer(handler)
	t.Cleanup(remote.Close)
	beforeInv, beforeRef := publisher.counts()
	status, body := settingsHTTPPut(t, remote.URL, `{"count_tokens_connect_sec":2,"count_tokens_total_sec":11,"sample_enabled":false}`)
	if status != 200 {
		t.Fatalf("PUT status=%d body=%s", status, body)
	}
	stored, err := server.st.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	want := warm
	want.CountTokensConnectSec = 2
	want.CountTokensTotalSec = 11
	want.CountTokensSec = 11
	want.SampleEnabled = false
	if !reflect.DeepEqual(stored, want) {
		t.Fatalf("partial PUT lost independent stage budgets or unspecified settings:\nstored=%+v\nwant=%+v", stored, want)
	}
	published, err := source.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(published, want) {
		t.Fatal("successful PUT returned before publishing its exact persisted settings")
	}
	var response model.Settings
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(response, want) {
		t.Fatal("PUT response must remain the canonical Settings object")
	}
	assertPublished(t, publisher, beforeInv, beforeRef)
}

func TestSettingsHTTP_ExplicitLegacyAliasesOnlyFillUnspecifiedStages(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		check      func(model.Settings) bool
	}{
		{"legacy count", `{"count_tokens_sec":13}`, func(s model.Settings) bool { return s.CountTokensConnectSec == 13 && s.CountTokensTotalSec == 13 }},
		{"explicit count connect wins", `{"count_tokens_sec":13,"count_tokens_connect_sec":2}`, func(s model.Settings) bool { return s.CountTokensConnectSec == 2 && s.CountTokensTotalSec == 13 }},
		{"explicit count stages win", `{"count_tokens_sec":13,"count_tokens_connect_sec":2,"count_tokens_total_sec":17}`, func(s model.Settings) bool { return s.CountTokensConnectSec == 2 && s.CountTokensTotalSec == 17 }},
		{"case insensitive aliases", `{"COUNT_TOKENS_SEC":13,"COUNT_TOKENS_CONNECT_SEC":2}`, func(s model.Settings) bool { return s.CountTokensConnectSec == 2 && s.CountTokensTotalSec == 13 }},
		{"null legacy is no change", `{"count_tokens_sec":null,"count_tokens_connect_sec":2,"count_tokens_total_sec":17}`, func(s model.Settings) bool { return s.CountTokensConnectSec == 2 && s.CountTokensTotalSec == 17 }},
		{"legacy real", `{"real_first_token_sec":600}`, func(s model.Settings) bool {
			return s.RealResponseHeaderSec == 600 && s.RealFirstByteSec == 600 && s.RealFirstSemanticSec == 600
		}},
		{"explicit real semantic wins", `{"real_first_token_sec":600,"real_first_semantic_sec":900}`, func(s model.Settings) bool {
			return s.RealResponseHeaderSec == 600 && s.RealFirstByteSec == 600 && s.RealFirstSemanticSec == 900
		}},
		{"legacy L2", `{"l2_first_token_sec":17}`, func(s model.Settings) bool {
			return s.L2ResponseHeaderSec == 17 && s.L2FirstByteSec == 17 && s.L2FirstEventSec == 17 && s.L2FirstSemanticSec == 17
		}},
		{"explicit L2 stage wins", `{"l2_first_token_sec":17,"l2_first_semantic_sec":29}`, func(s model.Settings) bool {
			return s.L2ResponseHeaderSec == 17 && s.L2FirstByteSec == 17 && s.L2FirstEventSec == 17 && s.L2FirstSemanticSec == 29
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, handler, source, _ := newLivecfgServer(t)
			if _, err := source.Settings(); err != nil {
				t.Fatal(err)
			}
			remote := httptest.NewServer(handler)
			t.Cleanup(remote.Close)
			status, body := settingsHTTPPut(t, remote.URL, tc.body)
			if status != 200 {
				t.Fatalf("PUT status=%d body=%s", status, body)
			}
			stored, err := server.st.GetSettings()
			if err != nil {
				t.Fatal(err)
			}
			published, err := source.Settings()
			if err != nil {
				t.Fatal(err)
			}
			var result model.Settings
			if err := json.Unmarshal(body, &result); err != nil {
				t.Fatal(err)
			}
			if !tc.check(stored) || !reflect.DeepEqual(stored, published) || !reflect.DeepEqual(stored, result) {
				t.Fatalf("legacy/new precedence or canonical response wrong: stored=%+v response=%+v", stored, result)
			}
		})
	}
}

func TestSettingsHTTP_InvalidPartialUpdateDoesNotWriteOrPublish(t *testing.T) {
	for _, body := range []string{
		`{"unknown-private-fixture-field":5}`,
		`{"count_tokens_connect_sec":"private-fixture-value"}`,
		`{"count_tokens_connect_sec":0}`,
		`{"count_tokens_connect_sec":10,"count_tokens_total_sec":2}`,
		`{"sample_enabled":false}{"sample_enabled":true}`,
	} {
		t.Run(body, func(t *testing.T) {
			server, handler, source, publisher := newLivecfgServer(t)
			before, revision, err := server.st.GetSettingsWithRevision()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := source.Settings(); err != nil {
				t.Fatal(err)
			}
			remote := httptest.NewServer(handler)
			t.Cleanup(remote.Close)
			beforeInv, beforeRef := publisher.counts()
			status, response := settingsHTTPPut(t, remote.URL, body)
			if status != 400 {
				t.Fatalf("invalid PUT status=%d body=%s", status, response)
			}
			if strings.Contains(string(response), "private-fixture") {
				t.Fatal("decoder echoed arbitrary request data")
			}
			after, newRevision, err := server.st.GetSettingsWithRevision()
			if err != nil {
				t.Fatal(err)
			}
			if newRevision != revision || !reflect.DeepEqual(after, before) {
				t.Fatal("rejected settings mutated the persisted revision or values")
			}
			afterInv, afterRef := publisher.counts()
			if afterInv != beforeInv || afterRef != beforeRef {
				t.Fatal("rejected settings invalidated or published configuration")
			}
		})
	}
}

type settingsBodyGate struct {
	io.ReadCloser
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (b *settingsBodyGate) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered); <-b.release })
	return b.ReadCloser.Read(p)
}

func TestSettingsHTTP_ConcurrentPartialUpdateRejectsCapturedStaleRevision(t *testing.T) {
	server, handler, source, publisher := newLivecfgServer(t)
	if _, err := source.Settings(); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	resume := sync.OnceFunc(func() { close(release) })
	defer resume()
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Fixture-Block") == "1" {
			r.Body = &settingsBodyGate{ReadCloser: r.Body, entered: entered, release: release}
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(remote.Close)
	request, err := http.NewRequest(http.MethodPut, remote.URL+"/admin/api/settings", strings.NewReader(`{"retry_policy":"aggressive"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testAdminPW)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Fixture-Block", "1")
	type result struct {
		status int
		err    error
	}
	done := make(chan result, 1)
	go func() {
		response, err := (&http.Client{Timeout: 3 * time.Second}).Do(request)
		if err != nil {
			done <- result{err: err}
			return
		}
		_, err = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		done <- result{status: response.StatusCode, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler never decoded after capturing its current settings revision")
	}
	status, body := settingsHTTPPut(t, remote.URL, `{"sample_enabled":false}`)
	if status != 200 {
		t.Fatalf("winning PUT status=%d body=%s", status, body)
	}
	beforeInv, beforeRef := publisher.counts()
	resume()
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.status != 409 {
			t.Fatalf("stale same-generation PUT status=%d want 409", result.status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stale update failed to terminate")
	}
	stored, err := server.st.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	if stored.SampleEnabled || stored.RetryPolicy != model.RetryPolicyBalanced {
		t.Fatalf("stale writer overwrote winning partial settings: %+v", stored)
	}
	afterInv, afterRef := publisher.counts()
	if afterInv != beforeInv || afterRef != beforeRef {
		t.Fatal("conflicting PUT must not invalidate/publish")
	}
	published, err := source.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(published, stored) {
		t.Fatal("live source diverged from the winning settings")
	}
}
