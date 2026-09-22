package transform

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// applyJSONPatch runs one declarative RFC 6902 op (add / remove / copy).
// These ops remarshal the document; untouched fields are not byte-identical (§15.4).
func applyJSONPatch(body []byte, rule Rule) ([]byte, error) {
	if !json.Valid(body) {
		return nil, fmt.Errorf("body is not JSON")
	}
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, err
	}
	var err error
	switch rule.Kind {
	case KindJSONPatchAdd:
		var val any
		val, err = parsePatchValue(rule.Value)
		if err != nil {
			return nil, err
		}
		root, err = patchAdd(root, rule.Name, val)
	case KindJSONPatchRemove:
		root, err = patchRemove(root, rule.Name)
	case KindJSONPatchCopy:
		var src any
		src, err = patchGet(root, rule.From)
		if err != nil {
			return nil, fmt.Errorf("copy from %q: %w", rule.From, err)
		}
		root, err = patchAdd(root, rule.To, deepCopyJSON(src))
		if err != nil {
			return nil, fmt.Errorf("copy to %q: %w", rule.To, err)
		}
	default:
		return nil, fmt.Errorf("not a json_patch kind: %s", rule.Kind)
	}
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	if int64(len(out))-int64(len(body)) > MaxAddedBytes {
		return nil, fmt.Errorf("json patch exceeds added-byte budget")
	}
	return out, nil
}

func parsePatchValue(raw string) (any, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty patch value")
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw, nil
	}
	return v, nil
}

func pointerParts(pointer string) ([]string, error) {
	pointer = strings.TrimSpace(pointer)
	if pointer == "" || pointer == "/" {
		return nil, fmt.Errorf("empty or root-only json pointer not supported")
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("json pointer must start with /")
	}
	raw := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	parts := make([]string, len(raw))
	for i, p := range raw {
		parts[i] = unescapePointer(p)
	}
	return parts, nil
}

func patchGet(root any, pointer string) (any, error) {
	parts, err := pointerParts(pointer)
	if err != nil {
		return nil, err
	}
	cur := root
	for _, key := range parts {
		next, err := stepInto(cur, key)
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}

func stepInto(cur any, key string) (any, error) {
	switch node := cur.(type) {
	case map[string]any:
		next, ok := node[key]
		if !ok {
			return nil, fmt.Errorf("missing %q", key)
		}
		return next, nil
	case []any:
		idx, err := strconv.Atoi(key)
		if err != nil || idx < 0 || idx >= len(node) {
			return nil, fmt.Errorf("invalid array index %q", key)
		}
		return node[idx], nil
	default:
		return nil, fmt.Errorf("cannot traverse %q", key)
	}
}

func patchRemove(root any, pointer string) (any, error) {
	parts, err := pointerParts(pointer)
	if err != nil {
		return nil, err
	}
	return patchRemoveAt(root, parts)
}

func patchRemoveAt(cur any, parts []string) (any, error) {
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty path")
	}
	key := parts[0]
	if len(parts) == 1 {
		switch node := cur.(type) {
		case map[string]any:
			if _, ok := node[key]; !ok {
				return nil, fmt.Errorf("missing %q", key)
			}
			delete(node, key)
			return node, nil
		case []any:
			idx, err := strconv.Atoi(key)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, fmt.Errorf("invalid array index %q", key)
			}
			return append(node[:idx], node[idx+1:]...), nil
		default:
			return nil, fmt.Errorf("cannot remove at %q", key)
		}
	}
	switch node := cur.(type) {
	case map[string]any:
		child, ok := node[key]
		if !ok {
			return nil, fmt.Errorf("missing %q", key)
		}
		next, err := patchRemoveAt(child, parts[1:])
		if err != nil {
			return nil, err
		}
		node[key] = next
		return node, nil
	case []any:
		idx, err := strconv.Atoi(key)
		if err != nil || idx < 0 || idx >= len(node) {
			return nil, fmt.Errorf("invalid array index %q", key)
		}
		next, err := patchRemoveAt(node[idx], parts[1:])
		if err != nil {
			return nil, err
		}
		node[idx] = next
		return node, nil
	default:
		return nil, fmt.Errorf("cannot traverse %q", key)
	}
}

func patchAdd(root any, pointer string, value any) (any, error) {
	parts, err := pointerParts(pointer)
	if err != nil {
		return nil, err
	}
	return patchAddAt(root, parts, value)
}

func patchAddAt(cur any, parts []string, value any) (any, error) {
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty path")
	}
	key := parts[0]
	if len(parts) == 1 {
		switch node := cur.(type) {
		case map[string]any:
			node[key] = value
			return node, nil
		case []any:
			if key == "-" {
				return append(node, value), nil
			}
			idx, err := strconv.Atoi(key)
			if err != nil || idx < 0 || idx > len(node) {
				return nil, fmt.Errorf("invalid array index %q", key)
			}
			if idx == len(node) {
				return append(node, value), nil
			}
			out := make([]any, 0, len(node)+1)
			out = append(out, node[:idx]...)
			out = append(out, value)
			out = append(out, node[idx:]...)
			return out, nil
		default:
			return nil, fmt.Errorf("cannot add at %q", key)
		}
	}
	switch node := cur.(type) {
	case map[string]any:
		child, ok := node[key]
		if !ok {
			return nil, fmt.Errorf("missing %q", key)
		}
		next, err := patchAddAt(child, parts[1:], value)
		if err != nil {
			return nil, err
		}
		node[key] = next
		return node, nil
	case []any:
		idx, err := strconv.Atoi(key)
		if err != nil || idx < 0 || idx >= len(node) {
			return nil, fmt.Errorf("invalid array index %q", key)
		}
		next, err := patchAddAt(node[idx], parts[1:], value)
		if err != nil {
			return nil, err
		}
		node[idx] = next
		return node, nil
	default:
		return nil, fmt.Errorf("cannot traverse %q", key)
	}
}

func deepCopyJSON(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return v
	}
	return out
}
