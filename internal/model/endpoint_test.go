package model

import "testing"

func TestEndpointKindContractAndProtocolMapping(t *testing.T) {
	tests := []struct {
		kind   EndpointKind
		method string
		path   string
	}{
		{EndpointModels, "GET", "/v1/models"},
		{EndpointMessages, "POST", "/v1/messages"},
		{EndpointResponses, "POST", "/v1/responses"},
		{EndpointChatCompletions, "POST", "/v1/chat/completions"},
		{EndpointCountTokens, "POST", "/v1/messages/count_tokens"},
	}
	for _, tc := range tests {
		if !tc.kind.Valid() {
			t.Errorf("%q must be valid", tc.kind)
		}
		if got := tc.kind.Method(); got != tc.method {
			t.Errorf("%q method = %q, want %q", tc.kind, got, tc.method)
		}
		if got := tc.kind.CanonicalPath(); got != tc.path {
			t.Errorf("%q path = %q, want %q", tc.kind, got, tc.path)
		}
	}
	if EndpointKind("unknown").Valid() || EndpointKind("unknown").Method() != "" || EndpointKind("unknown").CanonicalPath() != "" {
		t.Fatal("unknown endpoint must fail closed")
	}

	protocols := []struct {
		protocol Protocol
		want     EndpointKind
	}{
		{ProtoAnthropic, EndpointMessages},
		{ProtoOpenAIResponses, EndpointResponses},
		{ProtoOpenAIChat, EndpointChatCompletions},
	}
	for _, tc := range protocols {
		got, ok := tc.protocol.Endpoint()
		if !ok || got != tc.want {
			t.Errorf("protocol %q endpoint = %q,%v want %q,true", tc.protocol, got, ok, tc.want)
		}
	}
	if got, ok := Protocol("unknown").Endpoint(); ok || got != "" {
		t.Fatalf("unknown protocol endpoint = %q,%v", got, ok)
	}
}

func TestP0ConfigurationEnumsFailClosed(t *testing.T) {
	for _, mode := range []ProbeMode{ProbeModeActive, ProbeModeLazy} {
		if !mode.Valid() {
			t.Errorf("probe mode %q must be valid", mode)
		}
	}
	for _, mode := range []EndpointURLMode{EndpointURLCanonical, EndpointURLLegacyExact} {
		if !mode.Valid() {
			t.Errorf("URL mode %q must be valid", mode)
		}
	}
	for _, mode := range []AuthMode{
		AuthModeBearer,
		AuthModeXAPIKey,
		AuthModeAPIKey,
		AuthModeFixedQuery,
		AuthModeManualHeaders,
		AuthModeAutoCalibrated,
		AuthModeLegacyAutoRealOnly,
	} {
		if !mode.Valid() {
			t.Errorf("auth mode %q must be valid", mode)
		}
	}
	if ProbeMode("bogus").Valid() || EndpointURLMode("bogus").Valid() || AuthMode("bogus").Valid() {
		t.Fatal("unknown P0 configuration enum must fail closed")
	}
}

func TestUpstreamDefaultsToActiveProbeMode(t *testing.T) {
	upstream := Upstream{}
	upstream.Defaults()
	if upstream.ProbeMode != ProbeModeActive {
		t.Fatalf("probe mode = %q, want active", upstream.ProbeMode)
	}
}

func TestRunStateValidity(t *testing.T) {
	if !RunStateRunning.Valid() || !RunStatePaused.Valid() {
		t.Fatal("running and paused must be valid run states")
	}
	if RunState("bogus").Valid() {
		t.Fatal("unknown run state must fail closed")
	}
}
