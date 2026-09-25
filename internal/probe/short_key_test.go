package probe

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
)

// 脏行/历史短 api_key：探活必须以 config_error 收场且不出网，不得把短串送出。
func TestL1_ShortAPIKeyConfigErrorNoSend(t *testing.T) {
	rt := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		t.Fatal("短钥探活不得 RoundTrip")
		return nil, errors.New("unreachable")
	}}
	up := upstreamFor("https://short-key.example")
	up.APIKey = strings.Repeat("x", model.MinRedactableKeyLen-1)

	p := proberFor(up)
	p.Transport = rt

	out := p.L1(context.Background(), up, fastSettings())
	if rt.count() != 0 {
		t.Fatalf("短钥不得出站，RoundTrip=%d", rt.count())
	}
	if out.Verdict != health.VerdictIgnore {
		t.Fatalf("短钥应 Ignore（config），不得判站挂：%v err=%v", out.Verdict, out.Err)
	}
	if !errors.Is(out.Err, outbound.ErrAuthConfig) {
		t.Fatalf("want ErrAuthConfig，得到 %v", out.Err)
	}
	if out.Err != nil && strings.Contains(out.Err.Error(), up.APIKey) {
		t.Fatalf("错误不得含短钥明文：%v", out.Err)
	}
}
