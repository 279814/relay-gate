package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/279814/relay-gate/internal/probe"
)

func (runner *probeCLIRunner) warnOnlineCost(output io.Writer) error {
	builtins, err := probe.LoadBuiltinTemplates()
	if err != nil {
		return err
	}
	sites, protocols := map[int64]bool{}, map[string]bool{}
	var bodyBytes, estimatedTokens int64
	requests := len(runner.candidates) + len(runner.controls)
	for _, candidate := range runner.candidates {
		sites[candidate.up.ID] = true
		if candidate.mn != nil {
			protocols[string(candidate.mn.Protocol)] = true
		}
		template, err := builtins.Compact(candidate.endpoint)
		if err != nil {
			return err
		}
		modelBytes := 0
		if candidate.route != nil {
			encoded, err := json.Marshal(candidate.route.UpstreamModel)
			if err != nil {
				return err
			}
			modelBytes = len(encoded)
		}
		// Include rendered model/session expansion rather than reporting just
		// the fixture's static template byte length as the actual request size.
		bodyBytes += int64(len(template.Body) + modelBytes + 256)
		estimatedTokens += template.EstimatedCost()
		if control, ok := runner.controls[candidateControlKey(candidate)]; ok {
			bodyBytes += int64(len(control.fixture.body) + modelBytes)
			estimatedTokens += int64(len(control.fixture.body) + 64 + probe.ProbeRequestOutputTokenLimit(control.fixture.body))
		}
	}
	fmt.Fprintf(output, "隐私警告：内容将发送给多个第三方站点。sites=%d protocols=%d max_requests=%d body_bytes_upper=%d estimated_tokens=%d\n", len(sites), len(protocols), requests, bodyBytes, estimatedTokens)
	return nil
}
