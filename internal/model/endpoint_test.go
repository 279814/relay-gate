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

// full_url_mode 下 base_url 已是完整端点；L1 必须接到 origin，不能叠路径，
// 也不能回落 canonical 让 Resolver 再拼 /v1/models（docs/01 §5.1 / §7.1，
// docs/03「不再拼路径」）。
func TestEndpointURLOverride_FullURLModeDoesNotDoubleAppendL1Path(t *testing.T) {
	up := &Upstream{
		BaseURL:     "https://a.com/custom/entry",
		FullURLMode: true,
		L1Path:      "/status",
	}
	if got, want := up.EndpointURLOverride(EndpointMessages), "https://a.com/custom/entry"; got != want {
		t.Errorf("messages override = %q, want %q", got, want)
	}
	if got, want := up.EndpointURLOverride(EndpointModels), "https://a.com/status"; got != want {
		t.Errorf("custom l1_path override = %q, want %q（不得变成 /custom/entry/status）", got, want)
	}

	up.L1Path = "/v1/models"
	if got, want := up.EndpointURLOverride(EndpointModels), "https://a.com/v1/models"; got != want {
		t.Errorf("default l1_path override = %q, want %q（不得回落 canonical）", got, want)
	}

	// 非 full_url_mode：base + L1 路径（docs/01 §7.1）
	plain := &Upstream{BaseURL: "https://a.com", L1Path: "/status"}
	if got, want := plain.EndpointURLOverride(EndpointModels), "https://a.com/status"; got != want {
		t.Errorf("non-full L1 join = %q, want %q", got, want)
	}
	plain.L1Path = "/v1/models"
	if got := plain.EndpointURLOverride(EndpointModels); got != "" {
		t.Errorf("canonical models 应返回空 override，得到 %q", got)
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
