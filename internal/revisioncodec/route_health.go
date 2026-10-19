package revisioncodec

import "github.com/279814/relay-gate/internal/model"

// RouteHealthSettingsFingerprint covers the state machine's policy. Stage and
// parser policies remain in the captured observation expectations.
func RouteHealthSettingsFingerprint(settings model.Settings) string {
	encoder := newCanonicalEncoder("relay-gate/route-health-policy/v1")
	encoder.int64(int64(settings.FailThreshold))
	encoder.int64(int64(settings.OKThreshold))
	encoder.int64(int64(settings.CooldownSec))
	return encoder.digest()
}
