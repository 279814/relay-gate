package api

import (
	"bytes"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

type refreshErrPublisher struct {
	err error
}

func (p refreshErrPublisher) Invalidate() {}

func (p refreshErrPublisher) Refresh() error { return p.err }

// publishAfterSuccessfulWrite must not log raw Refresh err text that embeds a
// known upstream API key (docs/01 §2.4). Returned error value is unchanged.
func TestPublishAfterSuccessfulWrite_LogRedactsKnownAPIKey(t *testing.T) {
	const fixtureSecret = "sk-PUBLISH-REFRESH-LOG-SECRET99"

	c, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "publish-refresh-log.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s := New(st, log).WithConfigPublisher(refreshErrPublisher{
		err: fmt.Errorf("livecfg refresh: authorization rejected for key %s", fixtureSecret),
	})

	up := &model.Upstream{
		Name: "publish-refresh-log-up", BaseURL: "https://publish-refresh-log.example",
		APIKey: fixtureSecret, Enabled: true,
	}
	up.Defaults()
	if err := st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}

	got := s.publishAfterSuccessfulWrite()
	if got == nil {
		t.Fatal("expected Refresh error to propagate")
	}
	if !strings.Contains(got.Error(), fixtureSecret) {
		t.Fatal("returned error must stay unredacted for callers")
	}
	if strings.Contains(logBuf.String(), fixtureSecret) {
		t.Fatal("publishAfterSuccessfulWrite log leaked known upstream API key")
	}
	if !strings.Contains(logBuf.String(), "写入后刷新配置快照失败") {
		t.Fatal("expected publish refresh failure log line missing from buffer")
	}
}
