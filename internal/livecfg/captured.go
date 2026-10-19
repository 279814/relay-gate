package livecfg

import "context"

type capturedProbeKey struct{}

// WithCapturedProbeSnapshot carries the immutable request root to the existing
// Observer. It creates no cache and never substitutes a newer configuration.
func WithCapturedProbeSnapshot(ctx context.Context, snapshot *ProbeSnapshot) context.Context {
	if snapshot == nil {
		return ctx
	}
	return context.WithValue(ctx, capturedProbeKey{}, snapshot)
}

func CapturedProbeSnapshot(ctx context.Context) *ProbeSnapshot {
	value, _ := ctx.Value(capturedProbeKey{}).(*ProbeSnapshot)
	return value
}
