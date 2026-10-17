package livecfg

import "github.com/279814/relay-gate/internal/model"

// CurrentReachabilityRevision uses a ready immutable published snapshot. A
// missing target returns a zero revision with ready=true; refresh contention or
// an unpublished configuration returns ready=false without waiting for SQLite.
func (source *Source) CurrentReachabilityRevision(upstreamID int64, selector model.EvidencePolicySelector) (revision model.ReachabilityRevision, ready bool) {
	snapshot, err := source.CachedProbeSnapshot()
	if err != nil {
		return revision, false
	}
	expectation, err := snapshot.ReachabilityExpectation(upstreamID, selector)
	if err != nil {
		return revision, true
	}
	return expectation.Revision, true
}
