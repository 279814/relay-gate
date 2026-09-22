package probe

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
)

func TestSingleAuthProfile_WritesExactlyOneForm(t *testing.T) {
	cases := []struct {
		mode      model.AuthMode
		wantOnly  string
		wantValue string
	}{
		{model.AuthModeBearer, "Authorization", "Bearer sk-up"},
		{model.AuthModeXAPIKey, "X-Api-Key", "sk-up"},
		{model.AuthModeAPIKey, "Api-Key", "sk-up"},
	}
	for _, tc := range cases {
		t.Run(string(tc.mode), func(t *testing.T) {
			profile, err := SingleAuthProfile(tc.mode, "upstream_api_key")
			if err != nil {
				t.Fatal(err)
			}
			header := http.Header{}
			header.Set("Authorization", "Bearer rk-relay")
			header.Set("X-Api-Key", "rk-relay")
			header.Set("Api-Key", "rk-relay")
			if err := ApplyCandidateAuth(context.Background(), header, profile, outbound.Values{
				UpstreamAPIKey: []byte("sk-up"), CredentialRevision: 1,
			}); err != nil {
				t.Fatal(err)
			}
			for _, name := range model.AuthHeaders {
				got := header.Get(name)
				if name == tc.wantOnly {
					if got != tc.wantValue {
						t.Fatalf("%s = %q, want %q", name, got, tc.wantValue)
					}
					continue
				}
				if got != "" {
					t.Fatalf("%s 应为空，得到 %q（写了两种认证）", name, got)
				}
			}
		})
	}
}

func TestAutoCalibrated_DoesNotSendBothBearerAndXAPIKey(t *testing.T) {
	profile := model.EndpointAuthProfile{
		Mode: model.AuthModeAutoCalibrated, CalibratedMode: model.AuthModeBearer,
		SecretRef: "upstream_api_key", Revision: 1,
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer rk")
	header.Set("X-Api-Key", "rk")
	if err := ApplyCandidateAuth(context.Background(), header, profile, outbound.Values{
		UpstreamAPIKey: []byte("sk-up"), CredentialRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if header.Get("Authorization") != "Bearer sk-up" {
		t.Fatalf("Authorization = %q", header.Get("Authorization"))
	}
	if header.Get("X-Api-Key") != "" {
		t.Fatal("auto_calibrated 不能同时写 x-api-key")
	}
}

func TestLegacyAuto_SyntheticConfigErrorPointsAtCalibration(t *testing.T) {
	profile := model.EndpointAuthProfile{
		Mode: model.AuthModeLegacyAutoRealOnly, SecretRef: "upstream_api_key", Revision: 1,
	}
	err := ApplyCandidateAuth(context.Background(), http.Header{}, profile, outbound.Values{
		UpstreamAPIKey: []byte("sk-up"), CredentialRevision: 1,
	})
	if err == nil {
		t.Fatal("synthetic 必须 config_error")
	}
	if !errors.Is(err, outbound.ErrAuthConfig) {
		t.Fatalf("want ErrAuthConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), "校准") {
		t.Fatalf("错误应引导校准，得到 %v", err)
	}
}

func TestStripInboundAliasesBeforeWritingProfile(t *testing.T) {
	profile, err := SingleAuthProfile(model.AuthModeXAPIKey, "upstream_api_key")
	if err != nil {
		t.Fatal(err)
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer relay-secret-plaintext")
	header.Add("Authorization", "Bearer another")
	header.Set("X-Api-Key", "relay-secret-plaintext")
	header.Set("Api-Key", "relay-secret-plaintext")
	if err := ApplyCandidateAuth(context.Background(), header, profile, outbound.Values{
		UpstreamAPIKey: []byte("sk-up"), CredentialRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if header.Get("Authorization") != "" || header.Get("Api-Key") != "" {
		t.Fatal("入站认证别名必须先删干净")
	}
	if header.Get("X-Api-Key") != "sk-up" {
		t.Fatalf("X-Api-Key = %q", header.Get("X-Api-Key"))
	}
}

func TestManualHeaders_SecretsOnlyFromAllowedSources(t *testing.T) {
	_, err := ManualAuthProfile([]model.HeaderTemplate{
		{Name: "X-Custom-Auth", Values: []string{"tok {{UPSTREAM_API_KEY}}"}},
	}, "upstream_api_key")
	if err != nil {
		t.Fatalf("允许的占位符应通过: %v", err)
	}
	_, err = ManualAuthProfile([]model.HeaderTemplate{
		{Name: "X-Custom-Auth", Values: []string{"tok {{SECRET:tenant}}"}},
	}, "upstream_api_key")
	if err != nil {
		t.Fatalf("Probe Secret 占位符应通过: %v", err)
	}
	_, err = ManualAuthProfile([]model.HeaderTemplate{
		{Name: "Authorization", Values: []string{"Bearer {{UPSTREAM_API_KEY}}"}},
	}, "upstream_api_key")
	if err == nil {
		t.Fatal("manual 不能写标准认证别名")
	}
}

func TestValidateAuthSecretRef(t *testing.T) {
	if err := ValidateAuthSecretRef("upstream_api_key"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAuthSecretRef("probe:tenant"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAuthSecretRef("env:FOO"); err == nil {
		t.Fatal("非法 secret_ref 必须拒绝")
	}
}

func TestDefaultAuthCalibrationModes_AtMostThree(t *testing.T) {
	modes := DefaultAuthCalibrationModes()
	if len(modes) == 0 || len(modes) > MaxCalibrationCandidates {
		t.Fatalf("候选数 = %d, want 1..%d", len(modes), MaxCalibrationCandidates)
	}
}

func TestCalibratedSuccessProfile(t *testing.T) {
	got, err := CalibratedSuccessProfile(model.AuthModeBearer, model.EndpointAuthProfile{
		Mode: model.AuthModeLegacyAutoRealOnly, SecretRef: "upstream_api_key", Revision: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != model.AuthModeAutoCalibrated || got.CalibratedMode != model.AuthModeBearer {
		t.Fatalf("got %+v", got)
	}
}

func TestNeedsAuthCalibration(t *testing.T) {
	if !NeedsAuthCalibration(model.EndpointAuthProfile{Mode: model.AuthModeLegacyAutoRealOnly}) {
		t.Fatal("legacy auto 需要校准")
	}
	if !NeedsAuthCalibration(model.EndpointAuthProfile{Mode: model.AuthModeAutoCalibrated}) {
		t.Fatal("未填 CalibratedMode 需要校准")
	}
	if NeedsAuthCalibration(model.EndpointAuthProfile{
		Mode: model.AuthModeAutoCalibrated, CalibratedMode: model.AuthModeBearer,
	}) {
		t.Fatal("已校准不应再需要")
	}
	if NeedsAuthCalibration(model.EndpointAuthProfile{Mode: model.AuthModeBearer}) {
		t.Fatal("单一模式不需要校准")
	}
}
