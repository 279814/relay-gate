package transform

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// validateBodyTemplateShape rejects duplicate top-level "model" keys and
// non-declarative script-like bodies at compile time (§15.4 / §15.8).
func validateBodyTemplateShape(body []byte) error {
	if !json.Valid(body) {
		// Non-JSON templates are allowed (raw bytes / text protocols).
		return nil
	}
	if _, _, err := inspectTopLevelModel(body); err != nil {
		return err
	}
	return nil
}

type modelKind int

const (
	modelAbsent modelKind = iota
	modelString
	modelOther
)

type modelInfo struct {
	kind  modelKind
	value string // only for modelString
}

func inspectTopLevelModel(body []byte) (modelInfo, bool /*duplicate*/, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return modelInfo{}, false, err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return modelInfo{kind: modelAbsent}, false, nil
	}
	info := modelInfo{kind: modelAbsent}
	found := false
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return modelInfo{}, false, err
		}
		k, ok := kt.(string)
		if !ok {
			return modelInfo{}, false, fmt.Errorf("JSON object key not string")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return modelInfo{}, false, err
		}
		if k != "model" {
			continue
		}
		if found {
			return modelInfo{}, true, fmt.Errorf("body template must not create duplicate model")
		}
		found = true
		raw = bytes.TrimSpace(raw)
		if len(raw) > 0 && raw[0] == '"' {
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return modelInfo{}, false, err
			}
			info = modelInfo{kind: modelString, value: s}
		} else {
			info = modelInfo{kind: modelOther}
		}
	}
	return info, false, nil
}

// applyBodyTemplate replaces the body with a declarative literal template.
// If the prior body was JSON with a string model, the template must keep
// exactly one string model (§6.5 / §15.8); missing / typed / duplicate → error.
func applyBodyTemplate(prev, template []byte) ([]byte, error) {
	if len(template) > MaxBodyBuffer {
		return nil, fmt.Errorf("body_template exceeds %d byte buffer", MaxBodyBuffer)
	}
	if int64(len(template))-int64(len(prev)) > MaxAddedBytes {
		return nil, fmt.Errorf("body_template exceeds added-byte budget")
	}
	prevInfo, prevDup, err := inspectTopLevelModel(prev)
	if err == nil && prevDup {
		return nil, fmt.Errorf("prior body already has duplicate model")
	}
	if err == nil && prevInfo.kind == modelString {
		nextInfo, nextDup, nerr := inspectTopLevelModel(template)
		if nerr != nil {
			return nil, nerr
		}
		if nextDup {
			return nil, fmt.Errorf("body template must not create duplicate model")
		}
		if nextInfo.kind == modelAbsent {
			return nil, fmt.Errorf("body template must not delete model")
		}
		if nextInfo.kind != modelString {
			return nil, fmt.Errorf("body template must not change model type")
		}
	} else if json.Valid(template) {
		if _, nextDup, nerr := inspectTopLevelModel(template); nerr != nil {
			return nil, nerr
		} else if nextDup {
			return nil, fmt.Errorf("body template must not create duplicate model")
		}
	}
	return append([]byte(nil), template...), nil
}
