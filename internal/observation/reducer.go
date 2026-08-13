package observation

import "github.com/279814/relay-gate/internal/model"

// StateReducer is deliberately pure: Store owns the transaction and the
// health layer owns state-machine semantics.
type StateReducer interface {
	ReduceReachability(current *model.UpstreamReachability, execution model.ProbeExecution, policy model.ReachabilityReductionPolicy) (*model.UpstreamReachability, error)
	ReduceCapability(current *model.EndpointCapability, execution model.ProbeExecution, policy model.CapabilityReductionPolicy) (*model.EndpointCapability, error)
}
