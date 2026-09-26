package probe

// Auth Profile 校准侧的帮助函数（§7.2、§P0-11）。
//
// outbound.ApplyAuth 仍是唯一的出站认证改写器；本文件只负责：
//   - 为校准候选构造「恰好一种」AuthMode 的 profile；
//   - 校验 manual headers 的 Secret 只能来自 UPSTREAM_API_KEY / Probe Secret；
//   - 给出默认鉴权候选顺序（最多 3 个）。
// 周期探活不得在这里偷偷换头重试。

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/probetemplate"
)

// MaxCalibrationCandidates 是一次 CalibrationRun 允许的候选上限（§8.7）。
const MaxCalibrationCandidates = 3

// DefaultAuthCalibrationModes 是无证据时的默认鉴权候选顺序。
//
// 只列三种标准头模式：fixed_query / manual_headers 需要端点侧显式模板，
// 不能无依据地猜；auto / legacy_auto 本身不是可发送的单一形式。
func DefaultAuthCalibrationModes() []model.AuthMode {
	return []model.AuthMode{
		model.AuthModeBearer,
		model.AuthModeXAPIKey,
		model.AuthModeAPIKey,
	}
}

// SingleAuthProfile 构造只写一种认证形式的 profile。
//
// 校准成功后 Mode=auto_calibrated、CalibratedMode=选中模式；候选试探阶段
// 直接把 Mode 设成待测模式，避免走「尚未校准」分支。
func SingleAuthProfile(mode model.AuthMode, secretRef string) (model.EndpointAuthProfile, error) {
	if secretRef == "" {
		secretRef = "upstream_api_key"
	}
	if err := ValidateAuthSecretRef(secretRef); err != nil {
		return model.EndpointAuthProfile{}, err
	}
	switch mode {
	case model.AuthModeBearer, model.AuthModeXAPIKey, model.AuthModeAPIKey:
		return model.EndpointAuthProfile{
			Mode: mode, SecretRef: secretRef, Revision: 1,
		}, nil
	case model.AuthModeFixedQuery:
		return model.EndpointAuthProfile{}, fmt.Errorf("%w: fixed_query 候选必须显式给出 query 参数名", outbound.ErrAuthConfig)
	case model.AuthModeManualHeaders:
		return model.EndpointAuthProfile{}, fmt.Errorf("%w: manual_headers 候选必须给出 ManualHeaders", outbound.ErrAuthConfig)
	case model.AuthModeAutoCalibrated, model.AuthModeLegacyAutoRealOnly:
		return model.EndpointAuthProfile{}, fmt.Errorf("%w: 校准候选不能直接使用 %s", outbound.ErrAuthConfig, mode)
	default:
		return model.EndpointAuthProfile{}, fmt.Errorf("%w: auth mode 无效 %q", outbound.ErrAuthConfig, mode)
	}
}

// FixedQueryAuthProfile 构造带显式 query 名的 fixed_query profile。
func FixedQueryAuthProfile(queryName, secretRef string) (model.EndpointAuthProfile, error) {
	queryName = strings.TrimSpace(queryName)
	if queryName == "" {
		return model.EndpointAuthProfile{}, fmt.Errorf("%w: fixed_query 认证必须显式给出 query 参数名", outbound.ErrAuthConfig)
	}
	if secretRef == "" {
		secretRef = "upstream_api_key"
	}
	if err := ValidateAuthSecretRef(secretRef); err != nil {
		return model.EndpointAuthProfile{}, err
	}
	return model.EndpointAuthProfile{
		Mode: model.AuthModeFixedQuery, QueryName: queryName, SecretRef: secretRef, Revision: 1,
	}, nil
}

// ManualAuthProfile 构造 manual_headers profile；值只能引用允许的 Secret。
func ManualAuthProfile(headers []model.HeaderTemplate, secretRef string) (model.EndpointAuthProfile, error) {
	if len(headers) == 0 {
		return model.EndpointAuthProfile{}, fmt.Errorf("%w: manual_headers 认证未配置任何头", outbound.ErrAuthConfig)
	}
	if secretRef == "" {
		secretRef = "upstream_api_key"
	}
	if err := ValidateAuthSecretRef(secretRef); err != nil {
		return model.EndpointAuthProfile{}, err
	}
	for _, header := range headers {
		if err := ValidateManualAuthHeaderSecrets(header); err != nil {
			return model.EndpointAuthProfile{}, err
		}
	}
	return model.EndpointAuthProfile{
		Mode: model.AuthModeManualHeaders, ManualHeaders: headers, SecretRef: secretRef, Revision: 1,
	}, nil
}

// CalibratedSuccessProfile 把校准选中的单一 AuthMode 固化为 auto_calibrated。
func CalibratedSuccessProfile(selected model.AuthMode, base model.EndpointAuthProfile) (model.EndpointAuthProfile, error) {
	switch selected {
	case model.AuthModeBearer, model.AuthModeXAPIKey, model.AuthModeAPIKey,
		model.AuthModeFixedQuery, model.AuthModeManualHeaders:
		// ok
	default:
		return model.EndpointAuthProfile{}, fmt.Errorf("%w: 校准结果不能是 %s", outbound.ErrAuthConfig, selected)
	}
	out := base
	out.Mode = model.AuthModeAutoCalibrated
	out.CalibratedMode = selected
	if out.SecretRef == "" {
		out.SecretRef = "upstream_api_key"
	}
	if err := ValidateAuthSecretRef(out.SecretRef); err != nil {
		return model.EndpointAuthProfile{}, err
	}
	return out, nil
}

// ValidateAuthSecretRef 只接受 upstream_api_key 或 probe:<name>（§4.2）。
func ValidateAuthSecretRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "upstream_api_key" {
		return nil
	}
	if strings.HasPrefix(ref, "probe:") {
		name := strings.TrimSpace(strings.TrimPrefix(ref, "probe:"))
		if name != "" && !strings.ContainsAny(name, " \t\r\n") {
			return nil
		}
	}
	return fmt.Errorf("%w: auth secret_ref 只接受 upstream_api_key 或 probe:<name>", outbound.ErrAuthConfig)
}

// ValidateManualAuthHeaderSecrets 确保 manual header 值里的占位符只引用允许的 Secret。
func ValidateManualAuthHeaderSecrets(header model.HeaderTemplate) error {
	name := strings.TrimSpace(header.Name)
	if name == "" {
		return fmt.Errorf("%w: manual auth header 缺少名字", outbound.ErrAuthConfig)
	}
	if model.IsAuthHeader(name) {
		return fmt.Errorf("%w: manual_headers 不能写标准认证头 %q", outbound.ErrAuthConfig, name)
	}
	for _, raw := range header.Values {
		if err := probetemplate.RejectLiteralAuthFieldValue(raw); err != nil {
			return fmt.Errorf("%w: manual headers 认证值必须来自 UPSTREAM_API_KEY 或 Probe Secret", outbound.ErrAuthConfig)
		}
		required, err := probetemplate.ScanRequiredSecrets(model.EndpointMessages, probetemplate.TemplateContent{
			Method:  http.MethodPost,
			Headers: []model.HeaderTemplate{{Name: name, Values: []string{raw}}},
		})
		if err != nil {
			return fmt.Errorf("%w: manual auth header %q 模板无效", outbound.ErrAuthConfig, name)
		}
		for _, secretName := range required {
			if secretName == "" {
				continue
			}
			// ScanRequiredSecrets 返回的是 SECRET 名（不含 probe: 前缀）；
			// UPSTREAM_API_KEY 走另一通道，不出现在 required 列表。
			if strings.ContainsAny(secretName, " \t\r\n") {
				return fmt.Errorf("%w: manual auth header 引用了非法 Secret 名", outbound.ErrAuthConfig)
			}
		}
		if strings.Contains(raw, "{{") && !strings.Contains(raw, "{{UPSTREAM_API_KEY}}") &&
			!strings.Contains(raw, "{{SECRET:") {
			// 有占位符却不是允许的两类 —— 拒绝明文塞 key。
			if looksLikeCredentialPlaceholder(raw) {
				return fmt.Errorf("%w: manual headers 认证值必须来自 UPSTREAM_API_KEY 或 Probe Secret", outbound.ErrAuthConfig)
			}
		}
	}
	return nil
}

func looksLikeCredentialPlaceholder(raw string) bool {
	upper := strings.ToUpper(raw)
	return strings.Contains(upper, "{{") && (strings.Contains(upper, "KEY") ||
		strings.Contains(upper, "TOKEN") || strings.Contains(upper, "SECRET") ||
		strings.Contains(upper, "AUTH"))
}

// ApplyCandidateAuth 对校准候选写出站认证：先删入站别名，再只写这一种 profile。
//
// 直接委托 outbound.ApplyAuth，避免第二套认证实现。
func ApplyCandidateAuth(ctx context.Context, header http.Header, profile model.EndpointAuthProfile,
	values outbound.ValueResolver) error {

	return outbound.ApplyAuth(ctx, header, outbound.AuthInput{
		Profile: profile,
		Values:  values,
		Use:     outbound.ResolveSyntheticProbe,
	})
}

// NeedsAuthCalibration 判断该 Endpoint 是否仍需显式校准后才能跑合成探活。
func NeedsAuthCalibration(profile model.EndpointAuthProfile) bool {
	switch profile.Mode {
	case model.AuthModeLegacyAutoRealOnly:
		return true
	case model.AuthModeAutoCalibrated:
		return !profile.CalibratedMode.Valid() ||
			profile.CalibratedMode == model.AuthModeAutoCalibrated ||
			profile.CalibratedMode == model.AuthModeLegacyAutoRealOnly
	default:
		return false
	}
}
