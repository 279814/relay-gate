package model

// RouteMetadata is a management read projection. It contains only route
// configuration and the labels/revisions needed for a bounded health page;
// upstream credentials, proxy URLs and legacy header contents are absent.
type RouteMetadata struct {
	Route                   Route
	ModelName               string
	ModelEnabled            bool
	ModelExists             bool
	UpstreamName            string
	UpstreamEnabled         bool
	UpstreamExists          bool
	UpstreamNetworkRevision int64
}
