package probe

import "github.com/279814/relay-gate/internal/model"

// errDisabledProbeTarget rejects admin calibration / manual probe of a disabled
// Route or Upstream before any RoundTrip. This is config rejection, not
// reachability or probe cost.
func errDisabledProbeTarget(rt *model.Route, up *model.Upstream) error {
	if rt != nil && !rt.Enabled {
		return model.WrapValidation("Route 已停用，不能探活或校准")
	}
	if up != nil && !up.Enabled {
		return model.WrapValidation("Upstream 已停用，不能探活或校准")
	}
	return nil
}
