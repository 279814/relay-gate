package proxy

import (
	"net/http"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/transform"
)

// shadowRequest runs the bound shadow version on a side copy of the attempt's
// pre-published request (§15.2) and records a redacted diff. It never returns
// bytes to the caller: the live request stays whatever published/passthrough
// produced, shadow errors never fail the attempt, and no upstream call is made.
func (h *Handler) shadowRequest(cand *router.Candidate, endpointID int64,
	header http.Header, body []byte) {
	if h.transforms == nil || endpointID == 0 {
		return
	}
	c, verID, err := h.transforms.ShadowCompiled(cand.Route.ID, endpointID)
	if err != nil {
		h.log.Warn("加载 shadow transform 失败", "err", err, "route", cand.Route.ID)
		return
	}
	if c == nil {
		return
	}
	var secrets transform.SecretMap
	if key := cand.Upstream.APIKey; key != "" && !model.APIKeyTooShortForOutbound(key) {
		secrets = transform.SecretMap{"upstream_api_key": []byte(key)}
	}
	summary := c.ShadowDiffSecrets("request",
		transform.RequestInput{Header: header, Body: body}, transform.ResponseInput{}, secrets)
	h.transforms.RecordExecution(transform.ExecutionRecord{
		RouteID: cand.Route.ID, EndpointID: endpointID, VersionID: verID,
		Mode: "shadow", Phase: "request",
		OK:          strings.HasSuffix(summary, " err="),
		DiffSummary: summary,
		InputHash:   transform.HashBytes(body),
	})
}
