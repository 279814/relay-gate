package probe

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

// sanitizeLearnedShape also protects callers supplying a typed DTO or an old
// database row. A type graph becomes a request of harmless dummy values, then
// passes through the same protocol vocabulary as the real wire request. Neither
// the supplied body template nor query metadata is trusted or replayed.
func sanitizeLearnedShape(endpoint model.EndpointKind, shape model.ClientRequestShape) (model.ClientRequestShape, error) {
	invalid := func() (model.ClientRequestShape, error) {
		return model.ClientRequestShape{}, model.WrapValidation("profile shape 含有未获准的协议字段或值")
	}
	if len(shape.BodyShapeJSON) > requestShapeBodyLimit {
		return invalid()
	}
	view := health.AttemptRequestView{Header: http.Header{}, RawQuery: shape.FixedRawQuery}
	for _, header := range shape.SafeHeaders {
		for _, value := range header.Values {
			view.Header.Add(header.Name, value)
		}
	}
	var canonicalGraph []byte
	if len(shape.BodyShapeJSON) == 0 {
		// Header-only legacy profiles never supply business fields.
		view.Body = materializeLearnedBodyTemplate(endpoint)
	} else {
		var graph map[string]any
		if json.Unmarshal(shape.BodyShapeJSON, &graph) != nil || graph == nil || len(graph) > 64 {
			return invalid()
		}
		canonicalGraph, _ = json.Marshal(graph)
		request := make(map[string]any, len(graph))
		for name, value := range graph {
			switch name {
			case "thinking", "reasoning":
				configuration, ok := value.(map[string]any)
				if !ok {
					return invalid()
				}
				copy := make(map[string]any, len(configuration))
				for key, value := range configuration {
					if key == "budget_tokens" && value == "number" {
						value = 1024
					}
					copy[key] = value
				}
				request[name] = copy
			case "service_tier", "stream", "store", "parallel_tool_calls", "include_obfuscation":
				request[name] = value
			default:
				marker, ok := value.(string)
				if !ok {
					return invalid()
				}
				switch marker {
				case "string":
					request[name] = "probe"
				case "array":
					request[name] = []any{}
				case "object":
					request[name] = map[string]any{}
				case "number":
					request[name] = 1
				case "bool":
					request[name] = false
				case "null":
					request[name] = nil
				default:
					return invalid()
				}
			}
		}
		if endpoint != model.EndpointModels {
			view.Body, _ = json.Marshal(request)
		} else if len(request) != 0 {
			return invalid()
		}
	}
	safe, reason := SanitizeRequestShape(endpoint, view)
	if reason != "" {
		return invalid()
	}
	if canonicalGraph != nil && !bytes.Equal(canonicalGraph, safe.BodyShapeJSON) {
		return invalid()
	}
	// Preserve the validated graph's identity. Nil is the legacy header-only form.
	safe.BodyShapeJSON = canonicalGraph
	safe.BodyTemplate = materializeApprovedShapeBody(endpoint, canonicalGraph)
	return safe, nil
}
