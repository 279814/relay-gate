package health

// UpstreamStatus is the administration view of current Reachability evidence.
type UpstreamStatus struct {
	UpstreamID int64  `json:"upstream_id"`
	OK         bool   `json:"ok"`
	Probed     bool   `json:"probed"`
	LastError  string `json:"last_error"`
	LastAt     int64  `json:"last_at"`
}
