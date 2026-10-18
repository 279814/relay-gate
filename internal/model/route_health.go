package model

// RouteHealthIdentity carries the pre-send observation expectations plus the
// reducer policy actually used by Report. It contains no keys or payload text
// and is never reconstructed when a snapshot is flushed.
type RouteHealthIdentity struct {
	Version            int
	ModelNameID        int64
	ModelNameCreatedAt int64
	Route              SemanticExpectation
	// L1 keeps a model configuration anchor, but its model-stage budgets did
	// not classify the actual models request. Evidence/Reachability did.
	RouteContextOnly          bool
	Evidence                  *SemanticExpectation
	Reachability              *ReachabilityExpectation
	HealthSettingsFingerprint string
}

func CloneRouteHealthIdentity(in *RouteHealthIdentity) *RouteHealthIdentity {
	if in == nil {
		return nil
	}
	out := *in
	out.Route.Revision.ProbeSecrets = cloneHealthSecrets(in.Route.Revision.ProbeSecrets)
	if in.Evidence != nil {
		value := *in.Evidence
		value.Revision.ProbeSecrets = cloneHealthSecrets(in.Evidence.Revision.ProbeSecrets)
		out.Evidence = &value
	}
	if in.Reachability != nil {
		value := *in.Reachability
		out.Reachability = &value
	}
	return &out
}

func cloneHealthSecrets(in []SecretRevision) []SecretRevision {
	if in == nil {
		return nil
	}
	out := make([]SecretRevision, len(in))
	copy(out, in)
	return out
}
