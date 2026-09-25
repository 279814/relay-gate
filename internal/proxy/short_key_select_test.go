package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
)

// 脏行/历史短 api_key：不得被选中出站；仅候选为短钥时回无可用 Route；
// 同模型下有长钥兄弟站时只用兄弟站；换成达标长度后可再选。
func TestSelect_SkipsShortUpstreamAPIKey(t *testing.T) {
	short := strings.Repeat("x", model.MinRedactableKeyLen-1)
	long := strings.Repeat("y", model.MinRedactableKeyLen)

	t.Run("only short → no outbound, no-route", func(t *testing.T) {
		var hits int
		hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
			hits++
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":"msg_1","type":"message"}`))
		})
		hs.cfg.snap.Upstreams[10].APIKey = short

		rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","messages":[]}`))
		if hits != 0 {
			t.Fatalf("短钥不得出站，上游收到 %d 次", hits)
		}
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("仅短钥候选应回无可用 Route(503)，得到 %d: %s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Authorization"); strings.Contains(got, short) {
			t.Fatalf("客户端响应不得带回短钥，Authorization=%q", got)
		}
		if loc := rec.Header().Get("Location"); strings.Contains(loc, short) {
			t.Fatalf("客户端 Location 不得含短钥：%q", loc)
		}
	})

	t.Run("short sibling skipped, long sibling used", func(t *testing.T) {
		mh := newMultiHarness(t,
			func(w http.ResponseWriter, r *http.Request) {
				t.Error("短钥站不应收到请求")
				w.WriteHeader(http.StatusInternalServerError)
			},
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"id":"msg_1","type":"message"}`))
			},
		)
		mh.cfg.snap.Upstreams[10].APIKey = short
		mh.cfg.snap.Upstreams[11].APIKey = long
		mh.stations[1].key = long

		rec := mh.serve(mh.req())
		if rec.Code != http.StatusOK {
			t.Fatalf("应选长钥兄弟站，得到 %d: %s", rec.Code, rec.Body.String())
		}
		mh.assertHits(t, 0, 1)
		hits, keys, _ := mh.stations[1].stats()
		if hits != 1 || len(keys) != 1 || keys[0] != long {
			t.Fatalf("长钥站应收到自己的 key，hits=%d keys=%v", hits, keys)
		}
		if strings.Contains(rec.Header().Get("Location"), short) {
			t.Fatal("客户端 Location 不得含短钥")
		}
	})

	t.Run("replace short with long → selectable", func(t *testing.T) {
		var hits int
		var gotKey string
		hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
			hits++
			gotKey = r.Header.Get("X-Api-Key")
			if gotKey == "" {
				// AuthAuto 双发；取 Bearer
				auth := r.Header.Get("Authorization")
				gotKey = strings.TrimPrefix(auth, "Bearer ")
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"id":"msg_1","type":"message"}`))
		})
		hs.cfg.snap.Upstreams[10].APIKey = short
		rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","messages":[]}`))
		if hits != 0 || rec.Code == http.StatusOK {
			t.Fatalf("替换前短钥不得出站：hits=%d code=%d", hits, rec.Code)
		}

		hs.cfg.snap.Upstreams[10].APIKey = long
		rec = hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","messages":[]}`))
		if hits != 1 || rec.Code != http.StatusOK {
			t.Fatalf("换成长钥后应可选：hits=%d code=%d body=%s", hits, rec.Code, rec.Body.String())
		}
		if gotKey != long {
			t.Fatalf("出站 key = %q, want long key", gotKey)
		}
	})
}

// 精确名已命中且候选全是短 api_key 时，不得落到前缀或兜底上游（零 RoundTrip）。
// messages / responses / chat completions 共用 selectFor，一并钉住。
func TestSelect_ShortKeyExactDoesNotHitPrefixOrFallback(t *testing.T) {
	short := strings.Repeat("x", model.MinRedactableKeyLen-1)
	long := strings.Repeat("y", model.MinRedactableKeyLen)

	cases := []struct {
		name  string
		path  string
		proto model.Protocol
	}{
		{"messages", "/v1/messages", model.ProtoAnthropic},
		{"responses", "/v1/responses", model.ProtoOpenAIResponses},
		{"chat", "/v1/chat/completions", model.ProtoOpenAIChat},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var hits atomic.Int32
			hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"id":"ok"}`))
			})
			exact := &model.ModelName{ID: 1, Name: "claude-opus-5",
				Protocol: c.proto, MatchMode: model.MatchExact, Enabled: true}
			prefix := &model.ModelName{ID: 2, Name: "claude-",
				Protocol: c.proto, MatchMode: model.MatchPrefix, Enabled: true}
			fallback := &model.ModelName{ID: 9, Name: "catch-all",
				Protocol: c.proto, MatchMode: model.MatchExact, IsFallback: true, Enabled: true}
			upShort := &model.Upstream{ID: 10, Name: "exact-short", BaseURL: hs.up.URL,
				APIKey: short, AuthStyle: model.AuthAuto, Enabled: true}
			upLong := &model.Upstream{ID: 20, Name: "other-long", BaseURL: hs.up.URL,
				APIKey: long, AuthStyle: model.AuthAuto, Enabled: true}
			hs.cfg.snap = router.BuildSnapshot(
				[]*model.ModelName{exact, prefix, fallback},
				[]*model.Upstream{upShort, upLong},
				[]*model.Route{
					{ID: 100, ModelNameID: 1, UpstreamID: 10, Priority: 1, Weight: 100, Enabled: true},
					{ID: 200, ModelNameID: 2, UpstreamID: 20, Priority: 1, Weight: 100, Enabled: true},
					{ID: 900, ModelNameID: 9, UpstreamID: 20, Priority: 1, Weight: 100, Enabled: true},
				},
			)

			r := httptest.NewRequest("POST", c.path,
				strings.NewReader(`{"model":"claude-opus-5","messages":[]}`))
			r.Header.Set("X-Api-Key", hs.relayPW)
			r.Header.Set("Content-Type", "application/json")
			rec := hs.serve(r)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d want 503 body=%s", rec.Code, rec.Body.String())
			}
			if n := hits.Load(); n != 0 {
				t.Fatalf("short-key exact must not RoundTrip prefix/fallback, hits=%d", n)
			}

			// 未配置名仍可走兜底。
			hits.Store(0)
			r = httptest.NewRequest("POST", c.path,
				strings.NewReader(`{"model":"never-configured","messages":[]}`))
			r.Header.Set("X-Api-Key", hs.relayPW)
			r.Header.Set("Content-Type", "application/json")
			rec = hs.serve(r)
			if rec.Code != http.StatusOK {
				t.Fatalf("unknown via fallback status=%d want 200 body=%s", rec.Code, rec.Body.String())
			}
			if n := hits.Load(); n != 1 {
				t.Fatalf("unknown fallback RoundTrips=%d want 1", n)
			}
		})
	}
}
