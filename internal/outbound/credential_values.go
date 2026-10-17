package outbound

import (
	"context"
	"sort"
	"strings"
	"sync"
)

// This trace lives for one Attempt only. URL/auth rendering shares resolved
// values so redaction can use the original credentials without another read.
// Its mutex protects bookkeeping; it is never held across SecretSource I/O.
type credentialValueTrace struct {
	source ValueResolver
	mu     sync.Mutex
	values map[string]*credentialValueEntry
}

type credentialValueEntry struct {
	ready chan struct{}
	value ResolvedValue
	err   error
}

func newCredentialValueTrace(source ValueResolver) *credentialValueTrace {
	return &credentialValueTrace{source: source, values: map[string]*credentialValueEntry{}}
}

func copyResolvedValue(value ResolvedValue) ResolvedValue {
	value.Plain = append([]byte(nil), value.Plain...)
	return value
}

func (trace *credentialValueTrace) ResolveValue(ctx context.Context, name string) (ResolvedValue, error) {
	trace.mu.Lock()
	entry, exists := trace.values[name]
	if !exists {
		entry = &credentialValueEntry{ready: make(chan struct{})}
		trace.values[name] = entry
	}
	trace.mu.Unlock()
	if exists {
		select {
		case <-entry.ready:
			return copyResolvedValue(entry.value), entry.err
		case <-ctx.Done():
			return ResolvedValue{}, &secretSourceReadError{cause: ctx.Err()}
		}
	}
	var value ResolvedValue
	var err error
	if trace.source == nil {
		err = ErrUpstreamAPIKeyEmpty
	} else {
		value, err = trace.source.ResolveValue(ctx, name)
	}
	trace.mu.Lock()
	entry.value, entry.err = copyResolvedValue(value), err
	close(entry.ready)
	trace.mu.Unlock()
	return copyResolvedValue(value), err
}

func (trace *credentialValueTrace) resolvedSecrets() []string {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	seen := map[string]bool{}
	for name, entry := range trace.values {
		if entry.err == nil && (name == "UPSTREAM_API_KEY" || strings.HasPrefix(name, "SECRET:")) && len(entry.value.Plain) > 0 {
			seen[string(entry.value.Plain)] = true
		}
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}
