package main

import (
	"bytes"
	"encoding/json"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
)

func validControlHeader(header model.HeaderTemplate, bodyBytes int) bool {
	if len(header.Values) == 0 {
		return false
	}
	for _, value := range header.Values {
		if len(value) > 4096 || strings.ContainsAny(value, "\r\n") || strings.Contains(value, "{{") {
			return false
		}
		switch strings.ToLower(header.Name) {
		case "host":
			host, port, err := net.SplitHostPort(value)
			portNumber, portErr := strconv.Atoi(port)
			if err != nil || portErr != nil || (host != "127.0.0.1" && host != "::1") || portNumber < 1 || portNumber > 65535 {
				return false
			}
		case "content-length":
			if value != strconv.Itoa(bodyBytes) {
				return false
			}
		case "connection":
			if value != "close" && value != "keep-alive" {
				return false
			}
		case "accept-encoding":
			for _, coding := range strings.Split(value, ",") {
				switch strings.TrimSpace(coding) {
				case "gzip", "br", "deflate", "identity":
				default:
					return false
				}
			}
		case "content-type":
			media, params, err := mime.ParseMediaType(value)
			if err != nil || media != "application/json" || len(params) > 1 || (len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) {
				return false
			}
		default:
			// Reuse the maintained native SDK/OS/version/beta vocabulary. Only
			// validate it here: the original header order and values are retained.
			shape, reason := probe.SanitizeRequestShape(model.EndpointMessages, health.AttemptRequestView{
				Header: http.Header{header.Name: {value}}, Body: []byte(`{"model":"control"}`),
			})
			if reason != "" || len(shape.SafeHeaders) != 1 || len(shape.SafeHeaders[0].Values) != 1 {
				return false
			}
		}
	}
	return true
}

func controlJSONContainsSecret(data []byte, secrets ...string) bool {
	for _, secret := range secrets {
		if secret != "" && bytes.Contains(data, []byte(secret)) {
			return true
		}
	}
	var value any
	if json.Unmarshal(data, &value) != nil {
		return true
	}
	var contains func(any) bool
	contains = func(value any) bool {
		switch value := value.(type) {
		case string:
			for _, secret := range secrets {
				if secret != "" && strings.Contains(value, secret) {
					return true
				}
			}
		case []any:
			for _, item := range value {
				if contains(item) {
					return true
				}
			}
		case map[string]any:
			for key, item := range value {
				if contains(key) || contains(item) {
					return true
				}
			}
		}
		return false
	}
	return contains(value)
}
