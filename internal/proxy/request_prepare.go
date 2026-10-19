package proxy

import (
	"fmt"
	"net/http"
	"reflect"

	"github.com/279814/relay-gate/internal/edge"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/sample"
	"github.com/279814/relay-gate/internal/transform"
)

type preparedRequest struct {
	metadata model.AttemptMetadata
	tainted  bool
	body     []byte
	header   http.Header
	compiled *transform.Compiled
	version  int64
	keys     []string
}

// prepareOutboundRequest is shared by model forwarding and count_tokens. Every
// Attempt starts from the inbound bytes, the resolved Endpoint and its own key.
// It never sends a request or writes a client response.
func (h *Handler) prepareOutboundRequest(r *http.Request, pre *preambleResult,
	cand *router.Candidate, target outbound.ResolvedTarget, header http.Header) (preparedRequest, dispatchStatus) {

	out := preparedRequest{header: header, keys: append(h.credentialsOf(r, cand), target.ResolvedSecrets()...)}
	if pre.encoding != "" {
		out.tainted = containsAttemptSecret(pre.decoded, out.keys)
	}
	if target.EndpointID != 0 {
		var err error
		out.compiled, out.version, err = pre.transforms.PublishedCompiled(cand.Route.ID, target.EndpointID)
		if err != nil {
			h.log.Error("加载 transform 失败", "err", err, "route", cand.Route.ID)
			return out, dispatchRouteLocal
		}
	}
	c := out.compiled
	reencode := pre.encoding != "" && c.AllowsRequestReencoding()
	if pre.encoding != "" && !reencode {
		if cand.Route.UpstreamModel != "" {
			return out, dispatchRouteCompressedMapping
		}
		if c.HasRequestBodyRules() {
			return out, dispatchRouteCompressedTransform
		}
	}
	body := pre.body
	if reencode {
		if len(pre.decoded) > transform.MaxBodyBuffer {
			return out, dispatchRouteLocal
		}
		body = pre.decoded
	}
	var err error
	out.body, err = ReplaceModel(body, cand.Route.UpstreamModel)
	if err != nil {
		h.log.Error("替换 model 失败", "route", cand.Route.ID)
		return out, dispatchRouteLocal
	}
	shadowHeader, shadowBody := out.header, out.body
	if reencode {
		shadowHeader = out.header.Clone()
		shadowHeader.Del("Content-Encoding") // shadowBody is already decoded
	}
	if c != nil {
		var secrets transform.SecretMap
		if key := cand.Upstream.APIKey; key != "" && !model.APIKeyTooShortForOutbound(key) {
			secrets = transform.SecretMap{"upstream_api_key": []byte(key)}
		}
		beforeBody := out.body
		beforeHeader := out.header
		tr := c.ApplyRequestSecrets(transform.RequestInput{Header: out.header, Body: beforeBody}, secrets)
		// §15.3: rules cannot finally select a different model. Do not insert a
		// removed field or repair duplicate/non-string model keys: those use the
		// version's failure policy, just like any other invalid transformation.
		if tr.Err == nil && (reencode || pre.encoding == "") {
			protectedModel := pre.inModel
			if cand.Route.UpstreamModel != "" {
				protectedModel = cand.Route.UpstreamModel
			}
			currentModel, validationErr := ExtractModel(tr.Body)
			if validationErr == nil && currentModel != protectedModel {
				tr.Body, validationErr = ReplaceModel(tr.Body, protectedModel)
			}
			if validationErr != nil {
				tr.Err = fmt.Errorf("转换后的 model 必须是已存在的唯一字符串")
				tr.Header, tr.Body = out.header, beforeBody
				tr.Changed, tr.HitRules = false, nil
			}
		}
		if tr.Taint != nil {
			secrets := tr.Taint.Secrets()
			out.keys = append(out.keys, secrets...)
			out.tainted = out.tainted || len(secrets) > 0
		}
		out.metadata.RequestHeadersChanged = !reflect.DeepEqual(beforeHeader, tr.Header)
		if tr.Changed || tr.Err != nil {
			errText := ""
			if tr.Err != nil {
				errText = tr.Err.Error()
			}
			inputHash, outputHash, _ := safeAttemptBodyHashes(beforeBody, tr.Body, out.keys, out.tainted)
			h.transforms.RecordExecution(transform.ExecutionRecord{
				RouteID: cand.Route.ID, EndpointID: target.EndpointID, VersionID: out.version,
				Mode: "published", Phase: "request", OK: tr.Err == nil,
				HitRules: tr.HitRules, FailPolicyUsed: tr.PolicyUsed,
				InputHash: inputHash, OutputHash: outputHash, Error: sample.RedactDiagnosticText(errText, out.keys),
			})
		}
		if tr.Err != nil && tr.PolicyUsed == transform.FailClosed {
			return out, dispatchRouteLocal
		}
		out.header, out.body = tr.Header, tr.Body

	}
	edge.StripForwardingHeaders(out.header)
	h.shadowRequest(pre.transforms, cand, target.EndpointID, shadowHeader, shadowBody, out.keys, out.tainted)
	if reencode {
		out.body, err = encodeRequestBody(pre.encoding, out.body, transform.MaxBodyBuffer)
		if err != nil {
			h.log.Warn("压缩请求重编码超过上限", "route", cand.Route.ID)
			return out, dispatchRouteLocal
		}
	}
	if pre.encoding != "" {
		// A header rule cannot describe different bytes from the actual encoder.
		out.header.Set("Content-Encoding", pre.encoding)
	}
	if h.samples != nil && pre.settings.SampleEnabled {
		if pre.encoding != "" && containsAttemptSecret(pre.decoded, out.keys) {
			out.tainted = true
		}
		inHash, outHash, reason := safeAttemptBodyHashes(pre.body, out.body, out.keys, out.tainted)
		out.metadata.RequestInputHash, out.metadata.RequestOutputHash, out.metadata.RequestDiffReason = inHash, outHash, reason
		if reason == "recorded" {
			out.metadata.RequestBodyChanged = inHash != outHash
		} else {
			out.metadata.RequestHeadersChanged = false
		}
	} else {
		out.metadata.RequestHeadersChanged = false
		out.metadata.RequestDiffReason = "sample_disabled"
	}
	return out, dispatchSent
}
