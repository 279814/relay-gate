package api

// 冲突类错误必须回 409，不能落到 500。
//
// 这三类都是「请求合法但与当前状态冲突」：并发改同一行、还有依赖没清、
// 同 ID 重放换了内容。回 500 会让调用方（以及前端）无从判断该重试、
// 该重新读一遍，还是该改配置 —— 而且日志里会堆一片假的「内部错误」。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

func TestWriteErrMapsConflictErrorsTo409(t *testing.T) {
	server, _ := newTestServer(t)
	for _, testCase := range []struct {
		label string
		err   error
	}{
		{"revision", store.ErrRevisionConflict},
		{"dependency", store.ErrDependencyConflict},
		{"idempotency", store.ErrIdempotencyConflict},
		// 包装过一层也要能认出来：仓储层普遍用 %w 附上原因说明。
		{"wrapped dependency", errors.Join(store.ErrDependencyConflict, errors.New("必须先停用 Upstream"))},
	} {
		recorder := httptest.NewRecorder()
		server.writeErr(recorder, testCase.err)
		if recorder.Code != http.StatusConflict {
			t.Errorf("%s 冲突映射为 %d, want %d", testCase.label, recorder.Code, http.StatusConflict)
		}
		if recorder.Body.Len() == 0 {
			t.Errorf("%s 冲突没有回错误说明，调用方看不出该怎么办", testCase.label)
		}
	}
}

// TestEnableIncompleteUpstreamReturns409 走完整 HTTP 路径：确认「缺 Endpoint
// 时不能启用」这条门禁在 API 层呈现为 409，而不是 500。
func TestEnableIncompleteUpstreamReturns409(t *testing.T) {
	server, handler := newTestServer(t)
	created := do(t, handler, http.MethodPost, "/admin/api/upstreams",
		`{"name":"incomplete","base_url":"https://incomplete.example.com",
		  "api_key":"sk-incomplete-secret","auth_style":"x-api-key","enabled":false}`, true)
	if created.Code != http.StatusOK && created.Code != http.StatusCreated {
		t.Fatalf("建 Upstream = %d: %s", created.Code, created.Body.String())
	}

	upstreams, err := server.st.ListUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 1 {
		t.Fatalf("Upstream = %d 个, want 1", len(upstreams))
	}
	endpoints, err := server.st.ListEndpointsPage(context.Background(),
		model.EndpointFilter{UpstreamID: upstreams[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints.Items) == 0 {
		t.Fatal("新建 Upstream 应自动带上标准 Endpoint")
	}
	// 删掉一个，制造「缺一类」的状态。
	target := endpoints.Items[0]
	if err := server.st.DeleteEndpoint(target.ID, target.Revision); err != nil {
		t.Fatalf("删 Endpoint: %v", err)
	}

	enabled := do(t, handler, http.MethodPut, "/admin/api/upstreams/"+itoa(upstreams[0].ID),
		`{"name":"incomplete","base_url":"https://incomplete.example.com",
		  "auth_style":"x-api-key","enabled":true}`, true)
	if enabled.Code != http.StatusConflict {
		t.Errorf("缺 Endpoint 时启用 = %d: %s, want 409", enabled.Code, enabled.Body.String())
	}
}
