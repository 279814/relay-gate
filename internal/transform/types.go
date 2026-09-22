// Package transform implements P4 declarative traffic transforms (§15).
//
// Default is off: unbound Route+Endpoint pairs never enter JSON parse or
// event rewrite paths. No arbitrary script execution.
package transform

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Lifecycle of an immutable Version via Binding pointers.
const (
	StatusDraft     = "draft"
	StatusShadow    = "shadow"
	StatusPublished = "published"
	StatusDisabled  = "disabled"
	StatusArchived  = "archived"
)

// Rule kinds (declarative only).
const (
	KindSetHeader      = "set_header"
	KindDeleteHeader   = "delete_header"
	KindRenameHeader   = "rename_header"
	KindReplaceBytes   = "replace_bytes"
	KindSetJSONPointer = "set_json_pointer"
	KindSetStatus      = "set_status"
	KindSSEMatch       = "sse_match"
	KindSSEAppendEnd   = "sse_append_end" // synthetic completion
)

// FailPolicy for apply failures.
const (
	FailClosed = "fail_closed"
	FailOpen   = "fail_open"
)

// Limits (§15.3 defaults; may be lowered, not raised without audit).
const (
	MaxRulesPerVersion = 100
	MaxRegexBytes      = 4 * 1024
	MaxSSEEventBytes   = 1 << 20
	MaxAddedBytes      = 1 << 20
	MaxBodyBuffer      = 8 << 20
)

// Protected hop-by-hop / auth / transport headers rules must not finally control.
var protectedHeaders = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"set-cookie":          {},
	"content-length":      {},
	"transfer-encoding":   {},
	"connection":          {},
	"host":                {},
	"te":                  {},
	"trailer":             {},
	"upgrade":             {},
	"x-api-key":           {},
	"api-key":             {},
}

// Rule is one declarative transform step.
type Rule struct {
	Kind      string `json:"kind"`
	Name      string `json:"name,omitempty"`      // header name / JSON pointer / event type
	Value     string `json:"value,omitempty"`     // new value / replacement / status text
	From      string `json:"from,omitempty"`      // rename source / find bytes
	To        string `json:"to,omitempty"`        // rename target
	Match     string `json:"match,omitempty"`     // SSE event type filter
	Regex     string `json:"regex,omitempty"`     // RE2 only; compile-time bound
	FailOpen  bool   `json:"fail_open,omitempty"` // per-rule override (response default)
	Synthetic bool   `json:"synthetic,omitempty"` // mark synthetic_completion
}

// Version is an immutable compiled snapshot once published/shadowed.
type Version struct {
	ID            int64     `json:"id"`
	SetID         int64     `json:"set_id"`
	Revision      int64     `json:"revision"`
	CreatedAt     time.Time `json:"created_at"`
	Rules         []Rule    `json:"rules"`
	ReqFailPolicy string    `json:"req_fail_policy"` // default fail_closed
	ResFailPolicy string    `json:"res_fail_policy"` // default fail_open
	Note          string    `json:"note,omitempty"`
}

// Set is a named transform configuration container.
type Set struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Draft     *Version  `json:"draft,omitempty"`
	History   []Version `json:"history,omitempty"` // immutable published/shadow snapshots
}

// Binding attaches at most one published and one shadow version to Route+Endpoint.
type Binding struct {
	RouteID     int64 `json:"route_id"`
	EndpointID  int64 `json:"endpoint_id"`
	SetID       int64 `json:"set_id"`
	PublishedID int64 `json:"published_id,omitempty"`
	ShadowID    int64 `json:"shadow_id,omitempty"`
	Revision    int64 `json:"revision"`
}

// ExecutionRecord is a redacted apply/shadow diagnostic (§15.7 / §16.3).
type ExecutionRecord struct {
	ID             string    `json:"id"`
	At             time.Time `json:"at"`
	RouteID        int64     `json:"route_id"`
	EndpointID     int64     `json:"endpoint_id"`
	VersionID      int64     `json:"version_id"`
	Mode           string    `json:"mode"`  // published | shadow | preview
	Phase          string    `json:"phase"` // request | response | sse
	OK             bool      `json:"ok"`
	Synthetic      bool      `json:"synthetic_completion"`
	InputHash      string    `json:"input_hash"`
	OutputHash     string    `json:"output_hash"`
	DiffSummary    string    `json:"diff_summary"` // plain text, no secrets
	HitRules       []string  `json:"hit_rules"`
	Error          string    `json:"error,omitempty"`
	FailPolicyUsed string    `json:"fail_policy_used,omitempty"`
}

// Compiled is a validated, ready-to-apply Version.
type Compiled struct {
	Version Version
	regex   map[int]*regexp.Regexp // rule index → compiled RE2
}

// Registry holds in-process sets, bindings, and execution records.
// Optional PersistSink mirrors mutations into SQLite.
type Registry struct {
	mu       sync.RWMutex
	sets     map[int64]*Set
	bindings map[string]*Binding // key route:endpoint
	execs    []ExecutionRecord
	nextSet  atomic.Int64
	nextVer  atomic.Int64
	execSeq  atomic.Uint64
	execCap  int
	persist  PersistSink
}

// NewRegistry constructs an empty transform registry.
func NewRegistry(execCap int) *Registry {
	if execCap < 1 {
		execCap = 200
	}
	r := &Registry{
		sets:     make(map[int64]*Set),
		bindings: make(map[string]*Binding),
		execCap:  execCap,
	}
	r.nextSet.Store(1)
	r.nextVer.Store(1)
	return r
}

func bindKey(routeID, endpointID int64) string {
	return fmt.Sprintf("%d:%d", routeID, endpointID)
}

// HashBytes returns a stable hex SHA-256 for passthrough identity checks.
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// HeaderFingerprint hashes canonical header pairs (name lowercased, values joined).
func HeaderFingerprint(h http.Header) string {
	if h == nil {
		return HashBytes(nil)
	}
	var b strings.Builder
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, strings.ToLower(k))
	}
	// insertion order unstable; sort for stability
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strings.Join(h.Values(k), "\n"))
		b.WriteByte('\n')
	}
	return HashBytes([]byte(b.String()))
}

func isProtectedHeader(name string) bool {
	_, ok := protectedHeaders[strings.ToLower(strings.TrimSpace(name))]
	return ok
}
