package probe

// 内置版本化模板（P0-06、§8.3）。
//
// 这些断言分两类，混在一起会看不清各自在防什么：
//
//   - **形状类**（第 2、4、5、6 条）：模板发出去的请求必须仍是那个协议
//     能接受的最小请求。写错的后果是一个能编译、能发送、但被上游 400 的
//     模板，而那个 400 会被归类成「站不支持」——一个内置模板的笔误因此
//     变成对上游的错误判决。
//   - **内容类**（第 7 条）：模板里不能有抓包带出来的私人痕迹。这条没有
//     运行时症状，只能靠断言守住 —— 而它守的是「探活模板进了仓库」这件
//     事本身的前提。

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func loadBuiltins(t *testing.T) *BuiltinSet {
	t.Helper()
	set, err := LoadBuiltinTemplates()
	if err != nil {
		t.Fatalf("加载内置模板: %v", err)
	}
	return set
}

// 第 1 条：全部条目可编译，ID 与 revision 唯一，引用文件存在。
//
// 编译放在加载时：一个编译不过的内置模板是**发布事故**而不是运行时错误 ——
// 它是四级解析的最后兜底，坏了就没有下一级可退。所以让它在加载时就炸。
func TestBuiltinManifestLoadsCompilableUniqueEntries(t *testing.T) {
	set := loadBuiltins(t)
	if len(set.Templates()) == 0 {
		t.Fatal("manifest 一个模板都没有")
	}

	seenID := map[string]bool{}
	for _, template := range set.Templates() {
		if seenID[template.ID] {
			t.Errorf("template ID 重复: %q", template.ID)
		}
		seenID[template.ID] = true

		if template.Revision < 1 {
			t.Errorf("%s 的 revision 必须为正数，得到 %d", template.ID, template.Revision)
		}
		if template.Compiled() == nil {
			t.Errorf("%s 没有编译结果", template.ID)
		}
		// 内置模板不能引用 Probe Secret：它是没有任何用户配置时的兜底，
		// 而 Secret 是用户建的。引用了就等于「兜底本身需要先配点什么」。
		if secrets := template.Compiled().RequiredSecrets(); len(secrets) > 0 {
			t.Errorf("%s 引用了 Probe Secret %v，而内置模板必须零配置可用",
				template.ID, secrets)
		}
	}
}

// manifest 必须列全 builtin/ 下的每个模板文件。
//
// 反向断言：漏列一个文件的后果是那个模板**静默不存在** —— 文件在仓库里、
// 看起来已交付，而解析永远选不到它。这种缺失没有任何错误信息。
func TestBuiltinManifestListsEveryEmbeddedTemplateFile(t *testing.T) {
	set := loadBuiltins(t)
	listed := map[string]bool{}
	for _, template := range set.Templates() {
		listed[template.File] = true
	}

	root := filepath.Join("builtin")
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		relative := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		if relative == "manifest.json" {
			return nil
		}
		if !listed[relative] {
			t.Errorf("builtin/%s 存在但未列进 manifest —— 它永远不会被选中", relative)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// 第 2 条：compact Anthropic 保留 ?beta=true、协议版本、流式字段与最小安全消息形状。
//
// 四项各有来源：?beta=true 与协议版本头是 §3.1 抓包实测的路径与必需头
// （缺协议版本直接 400）；stream 必须为 true 否则测不出首 Token 时间；
// 「最小安全形状」是指一条 user 消息，没有 system/tools/metadata。
func TestBuiltinCompactAnthropicKeepsCapturedShape(t *testing.T) {
	set := loadBuiltins(t)
	template, err := set.Compact(model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}

	if template.RawQuery != "beta=true" {
		t.Errorf("compact Anthropic 的固定 query 应为 beta=true（§3.1 实测路径），得到 %q",
			template.RawQuery)
	}
	if got := template.Header("anthropic-version"); got == "" {
		t.Error("缺 anthropic-version，上游直接回 400")
	}
	if !template.StreamExpected {
		t.Error("compact Anthropic 必须期待流式响应 —— 非流式测不出首 Token 时间")
	}

	var body struct {
		Model    string `json:"model"`
		MaxTok   int    `json:"max_tokens"`
		Stream   bool   `json:"stream"`
		Messages []struct {
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(template.Body, &body); err != nil {
		t.Fatalf("compact Anthropic 的 body 不是合法 JSON: %v", err)
	}
	if !body.Stream {
		t.Error("body 里必须 stream:true")
	}
	if body.Model != "{{UPSTREAM_MODEL}}" {
		t.Errorf("模型名必须走占位符（映射后的名字与真实请求一致，§3.3.2），得到 %q", body.Model)
	}
	if len(body.Messages) != 1 || body.Messages[0].Role != "user" {
		t.Fatalf("最小形状是一条 user 消息，得到 %+v", body.Messages)
	}
	if len(body.Messages[0].Content) != 1 || body.Messages[0].Content[0].Type != "text" {
		t.Errorf("消息内容应是单个 text block，得到 %+v", body.Messages[0].Content)
	}
	if body.Messages[0].Content[0].Text != "{{PROBE_PROMPT}}" {
		t.Errorf("prompt 必须走占位符，得到 %q", body.Messages[0].Content[0].Text)
	}
}

// 第 3 条：context-1m 是独立的 calibration 候选，不默认注入全部站。
//
// 为什么这条要单独钉：M0 曾把一个站标成「需 1M」，复核确认是误报
// （§9.1.1 复核点 2）。把 context-1m 加进默认 beta 列表会让所有站的探活
// 都带上一个真实 Claude Code 不发的开关 —— 于是探活请求与真实请求不再
// 是同一个形状，而这正是本项目反复要避免的那类差异。
func TestBuiltinContext1MStaysAnOptInCalibrationCandidate(t *testing.T) {
	set := loadBuiltins(t)

	const marker = "context-1m"
	var candidates []*BuiltinTemplate
	for _, template := range set.Templates() {
		betas := template.Header("anthropic-beta")
		requiresIt := false
		for _, requirement := range template.Requires {
			if strings.Contains(requirement, marker) {
				requiresIt = true
			}
		}
		switch {
		case strings.Contains(betas, marker):
			if !requiresIt {
				t.Errorf("%s 的 anthropic-beta 带 context-1m 却没在 requires 里声明；"+
					"未声明的候选会被当成通用模板选中", template.ID)
			}
			candidates = append(candidates, template)
		case requiresIt:
			t.Errorf("%s 声明需要 context-1m 但 beta 头里没有它", template.ID)
		}
	}

	if len(candidates) == 0 {
		t.Fatal("没有 context-1m 候选模板，anyrouter 这类站无法用内置模板探通（§3.2）")
	}
	for _, template := range candidates {
		if template.Family != model.RecipeCalibration {
			t.Errorf("%s 带 context-1m，必须是 calibration 族（不进常规周期，§8.3），得到 %q",
				template.ID, template.Family)
		}
	}

	// 周期探活选中的那个不能带它。
	compact, err := set.Compact(model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(compact.Header("anthropic-beta"), marker) {
		t.Error("周期探活用的 compact 模板不能带 context-1m —— 真实 Claude Code 不发这个开关")
	}
}

// 第 4 条：Responses 用它端点能接受的最小 max_output_tokens，
// Chat/Anthropic 各用正确的字段名。
//
// 三种协议的参数名不同（§3.3.1），写错的表现是上游 400，而那个 400
// 会被归类成「请求形状被拒」—— 归因落在站上，不在模板上。
func TestBuiltinOutputLimitsUsePerEndpointFieldNames(t *testing.T) {
	set := loadBuiltins(t)

	// Responses 实测 max_output_tokens=1 会被部分站直接拒绝。
	const responsesMinimum = 16
	fields := map[model.EndpointKind]string{
		model.EndpointMessages:        "max_tokens",
		model.EndpointChatCompletions: "max_tokens",
		model.EndpointResponses:       "max_output_tokens",
	}

	for _, template := range set.Templates() {
		field, ok := fields[template.Endpoint]
		if !ok {
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(template.Body, &body); err != nil {
			t.Fatalf("%s 的 body 不是合法 JSON: %v", template.ID, err)
		}
		value, ok := body[field].(float64)
		if !ok {
			t.Errorf("%s（%s）必须用字段 %q 表达输出上限，body 里没有它",
				template.ID, template.Endpoint, field)
			continue
		}
		// 声明值与 body 里的值必须一致：成本估算读的是声明值，而上游读的是
		// body。两者不一致时成本报告会稳定地报一个与实际不同的数。
		if int64(value) != template.MaxOutputTokens {
			t.Errorf("%s 声明 max_output_tokens=%d 而 body 里是 %v，成本估算会失真",
				template.ID, template.MaxOutputTokens, value)
		}
		if template.Endpoint == model.EndpointResponses && int64(value) < responsesMinimum {
			t.Errorf("%s 的 %s=%v 低于实测下限 %d，部分站会直接拒绝",
				template.ID, field, value, responsesMinimum)
		}
		// 另一种协议的字段名不能同时出现：两个都在时，上游按哪个算输出
		// 取决于它自己的实现，而成本估算只认一个。
		for endpoint, other := range fields {
			if endpoint == template.Endpoint || other == field {
				continue
			}
			if _, present := body[other]; present {
				t.Errorf("%s 同时带了 %q 与 %q，输出上限有两个来源",
					template.ID, field, other)
			}
		}
	}
}

// 第 5 条：count_tokens 默认 /v1/messages/count_tokens，无 stream 也无输出 token。
//
// count_tokens 不生成内容，所以它的输出 token 是 0。带 stream 的话，
// 部分站会因为一个它不接受的字段而拒绝整个请求。
func TestBuiltinCountTokensHasNoStreamAndNoOutputTokens(t *testing.T) {
	set := loadBuiltins(t)
	template, err := set.Compact(model.EndpointCountTokens)
	if err != nil {
		t.Fatal(err)
	}

	if got := model.EndpointCountTokens.CanonicalPath(); got != "/v1/messages/count_tokens" {
		t.Fatalf("count_tokens 的 canonical path 变了: %q", got)
	}
	if template.StreamExpected {
		t.Error("count_tokens 不是流式端点")
	}
	if bytes.Contains(template.Body, []byte(`"stream"`)) {
		t.Error("count_tokens 的 body 不能带 stream —— 部分站会因为多一个字段而拒绝")
	}
	if template.MaxOutputTokens != 0 {
		t.Errorf("count_tokens 不生成内容，输出 token 必须为 0，得到 %d",
			template.MaxOutputTokens)
	}
	if template.TimeoutProfile != model.TimeoutCountTokens {
		t.Errorf("count_tokens 必须用 count_tokens 超时档，得到 %q", template.TimeoutProfile)
	}
}

// 第 6 条：models 为 GET、无 body、零模型 token。
func TestBuiltinModelsIsGetWithoutBodyOrTokens(t *testing.T) {
	set := loadBuiltins(t)
	template, err := set.Compact(model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}

	if template.Method != "GET" {
		t.Errorf("models 探活是 GET，得到 %q", template.Method)
	}
	if len(template.Body) != 0 {
		t.Errorf("GET 不能带 body，得到 %d 字节", len(template.Body))
	}
	if template.EstimatedInputTokens != 0 || template.MaxOutputTokens != 0 {
		t.Errorf("models 是零 token 探测（§4.1），得到 in=%d out=%d",
			template.EstimatedInputTokens, template.MaxOutputTokens)
	}
	if template.TimeoutProfile != model.TimeoutL1 {
		t.Errorf("models 必须用 l1 超时档，得到 %q", template.TimeoutProfile)
	}
}

// 第 7 条：模板不含真实会话 ID、用户路径、system、tools、metadata 用户值或认证明文。
//
// 复用 fixture 那套扫描器（highEntropyTokenPattern 等，fixture_test.go）：
// 两套正则必然分叉，而分叉的那一半就是漏网的那一半。
func TestBuiltinTemplatesCarryNoPrivateCaptureRemnants(t *testing.T) {
	// 顶层禁止字段。§8.3 列的是「不得写死」的东西，其中 system / tools /
	// metadata 在 body 里是具名字段，可以直接查。
	forbidden := []string{`"system"`, `"tools"`, `"metadata"`, `"session_id"`, `"user_id"`}

	set := loadBuiltins(t)
	for _, template := range set.Templates() {
		for _, key := range forbidden {
			if bytes.Contains(template.Body, []byte(key)) {
				t.Errorf("%s 的 body 含禁止字段 %s（§8.3）", template.ID, key)
			}
		}
		for _, header := range template.Headers {
			if model.IsAuthHeader(header.Name) {
				t.Errorf("%s 带认证头 %q —— 认证只有 ApplyAuth 一个来源（§7.2）",
					template.ID, header.Name)
			}
		}
	}

	// 整个目录过一遍 fixture 的脱敏扫描：高熵 token、认证值、非公网 URL、
	// Windows 用户路径都在它的判据里。
	if err := scanFixtureSecrets("builtin"); err != nil {
		t.Fatalf("内置模板目录未通过脱敏扫描: %v", err)
	}
}

// 第 8 条：compact 的估算成本不高于对应的 calibration。
//
// 反了的话，周期探活（优先 compact，§8.3）会比一次手动校准更贵 ——
// 而 compact 存在的唯一理由就是省 token。
func TestBuiltinCompactCostsNoMoreThanCalibration(t *testing.T) {
	set := loadBuiltins(t)
	for _, endpoint := range set.Endpoints() {
		compact, err := set.Compact(endpoint)
		if err != nil {
			continue
		}
		for _, template := range set.Templates() {
			if template.Endpoint != endpoint || template.Family != model.RecipeCalibration {
				continue
			}
			if compact.EstimatedCost() > template.EstimatedCost() {
				t.Errorf("%s（compact，%d）比 %s（calibration，%d）更贵，"+
					"而周期探活用的是前者", compact.ID, compact.EstimatedCost(),
					template.ID, template.EstimatedCost())
			}
		}
	}
}

// 第 9 条：fixture 里的已知特殊要求能由某个候选模板明确表达。
//
// 具体到 anthropic_context_1m_required：那个 fixture 是一个站明确要求
// context-1m 的 400。要求「能表达」而不是「默认带上」—— 后者会让所有站
// 都发一个真实客户端不发的开关（见上面第 3 条）。
func TestBuiltinCandidatesExpressFixtureRequirements(t *testing.T) {
	manifest, err := loadFixtureManifest("testdata")
	if err != nil {
		t.Fatal(err)
	}
	set := loadBuiltins(t)

	for _, fixture := range manifest.Cases {
		endpoint := model.EndpointKind(fixture.Endpoint)
		if _, err := set.Compact(endpoint); err != nil {
			t.Errorf("fixture %s 的 endpoint %s 没有 compact 内置模板: %v",
				fixture.ID, endpoint, err)
		}
	}

	body, err := os.ReadFile(filepath.Join("testdata", "responses",
		"anthropic_context_1m_required.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("context-1m")) {
		t.Fatal("前提不成立：该 fixture 已不再要求 context-1m，这条断言失去意义")
	}
	if len(set.Requiring("context-1m")) == 0 {
		t.Error("没有候选模板能表达 context-1m 要求，这类站只能靠手写 Recipe")
	}
}

// 第 10 条：embedded identity 的 TemplateID+revision 唯一，
// 且回读时不依赖 DBVersionID=0 猜来源。
//
// 「猜来源」是指：三种 storage 的判别若只靠「哪些 ID 是 0」，那么一条
// 字段写歪的记录会被读成另一种来源 —— 而 embedded 与 db 的区别决定了
// Store 侧按哪一层重读并比较 facts（capability.go 的 ResolvedEmbedded 分支）。
func TestBuiltinIdentityIsSelfDescribing(t *testing.T) {
	set := loadBuiltins(t)
	seen := map[string]string{}

	for _, template := range set.Templates() {
		identity := template.Identity()
		if err := identity.Validate(); err != nil {
			t.Errorf("%s 的 identity 不合法: %v", template.ID, err)
			continue
		}
		if identity.Storage != model.RecipeStorageEmbedded {
			t.Errorf("%s 的 storage 应为 embedded，得到 %q", template.ID, identity.Storage)
		}
		// storage 自己就说明了来源，不靠「DBVersionID 是 0」推断。
		if identity.TemplateID == "" || identity.Revision < 1 {
			t.Errorf("%s 的 identity 缺 TemplateID/Revision，回读时只能靠零值猜来源: %+v",
				template.ID, identity)
		}

		key := identity.TemplateID + "@" + string(rune(identity.Revision))
		if previous, exists := seen[key]; exists {
			t.Errorf("%s 与 %s 的 TemplateID+revision 相同", template.ID, previous)
		}
		seen[key] = template.ID

		// 按 ID 回查必须拿回同一个模板：这是「不靠猜」的可执行含义。
		found, err := set.ByID(identity.TemplateID)
		if err != nil {
			t.Errorf("按 identity 的 TemplateID 回查失败: %v", err)
			continue
		}
		if found.Revision != identity.Revision {
			t.Errorf("%s 回查到 revision %d，identity 记的是 %d",
				template.ID, found.Revision, identity.Revision)
		}
	}
}

// capture family 的版本号与模板里的 UA 不能分叉。
//
// 规格要求「Claude Code 版本属于可更新的 capture family 元数据；Recipe 固定
// 实际版本，不能把永久最新版写进逻辑」。于是版本号在两处出现：family 的
// 元数据与模板的 user-agent。分叉的后果是元数据说抓的是 A 版而实际发的是
// B 版的 UA —— 一份说不清来源的证据。
func TestBuiltinUserAgentMatchesCaptureFamilyVersion(t *testing.T) {
	set := loadBuiltins(t)
	for _, template := range set.Templates() {
		family, err := set.CaptureFamily(template.CaptureFamily)
		if err != nil {
			t.Errorf("%s 引用了不存在的 capture family %q", template.ID, template.CaptureFamily)
			continue
		}
		if family.ClientVersion == "" {
			// protocol-baseline 这类没有客户端抓包的族：它反过来**不能**
			// 带客户端指纹，否则就是凭空编了一个客户端。
			if agent := template.Header("user-agent"); agent != "" {
				t.Errorf("%s 属于无抓包的 family %q 却带 user-agent %q —— "+
					"那是一个没有证据的客户端指纹", template.ID, family.ID, agent)
			}
			continue
		}
		agent := template.Header("user-agent")
		if agent == "" {
			t.Errorf("%s 属于 family %q（客户端 %s %s）却没有 user-agent",
				template.ID, family.ID, family.Client, family.ClientVersion)
			continue
		}
		if !strings.Contains(agent, family.ClientVersion) {
			t.Errorf("%s 的 user-agent %q 不含 family %q 记录的版本 %q",
				template.ID, agent, family.ID, family.ClientVersion)
		}
	}
}

// 每个 endpoint 至多一个 compact：compact 是周期探活的选择，
// 两个候选就意味着「周期探活用哪个」由遍历顺序决定。
func TestBuiltinCompactIsUniquePerEndpoint(t *testing.T) {
	set := loadBuiltins(t)
	counts := map[model.EndpointKind]int{}
	for _, template := range set.Templates() {
		if template.Family == model.RecipeCompact {
			counts[template.Endpoint]++
		}
	}
	for endpoint, count := range counts {
		if count != 1 {
			t.Errorf("endpoint %s 有 %d 个 compact 模板，周期探活的选择会不确定",
				endpoint, count)
		}
	}
	// 五个 endpoint 都要有兜底 —— 缺一个就意味着那个端点在没有任何
	// 用户配置时探不了，而四级解析的第 4 级本来就是为此存在的。
	for _, endpoint := range []model.EndpointKind{
		model.EndpointModels, model.EndpointMessages, model.EndpointResponses,
		model.EndpointChatCompletions, model.EndpointCountTokens,
	} {
		if counts[endpoint] != 1 {
			t.Errorf("endpoint %s 缺 compact 内置模板", endpoint)
		}
	}
}

// 加载器必须拒绝坏 manifest，而不是跳过坏条目。
//
// 跳过的后果是「少了一个模板」，而那在运行时表现为某个 endpoint 突然
// 没有兜底 —— 一个由 JSON 笔误引起、却发生在探活路径上的故障。
func TestBuiltinLoaderRejectsBadManifests(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*builtinManifestFile)
		wantErr string
	}{
		{
			name:    "未知 capture family",
			mutate:  func(m *builtinManifestFile) { m.Templates[0].CaptureFamily = "nope" },
			wantErr: "capture family",
		},
		{
			name:    "endpoint 与 method 不符",
			mutate:  func(m *builtinManifestFile) { m.Templates[0].Method = "POST" },
			wantErr: "method",
		},
		{
			name:    "revision 为 0",
			mutate:  func(m *builtinManifestFile) { m.Templates[0].Revision = 0 },
			wantErr: "revision",
		},
		{
			name:    "family 无效",
			mutate:  func(m *builtinManifestFile) { m.Templates[0].Family = "manual" },
			wantErr: "family",
		},
		{
			name: "ID 重复",
			mutate: func(m *builtinManifestFile) {
				m.Templates = append(m.Templates, m.Templates[0])
			},
			wantErr: "重复",
		},
		{
			name:    "manifest 版本不认识",
			mutate:  func(m *builtinManifestFile) { m.Version = 99 },
			wantErr: "版本",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			// file 指向一个真实存在的 embed 文件：这里要验的是 manifest 的
			// 校验逻辑，而一个读不到的文件会让每个用例都先在「文件不存在」
			// 上失败 —— 于是断言全部通过却什么都没验到。
			manifest := builtinManifestFile{
				Version: builtinManifestVersion,
				CaptureFamilies: []BuiltinCaptureFamily{{
					ID: "test-family", MetadataRedacted: true,
				}},
				Templates: []builtinTemplateFile{{
					ID: "builtin:test", Revision: 1, File: "models/compact.json",
					Family: model.RecipeCompact, CaptureFamily: "test-family",
					Endpoint: model.EndpointModels, Method: "GET",
					TimeoutProfile: model.TimeoutL1,
				}},
			}
			testCase.mutate(&manifest)

			_, err := buildBuiltinSet(&manifest)
			if err == nil {
				t.Fatalf("坏 manifest 必须拒绝（否则那个 endpoint 静默失去兜底）")
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Errorf("错误应指明问题所在（含 %q），得到 %v", testCase.wantErr, err)
			}
		})
	}

	// 反向验证：上面那份未经 mutate 的 manifest 必须能加载。
	// 不验的话，一个「无论如何都失败」的加载器会让全部用例假绿。
	baseline := builtinManifestFile{
		Version: builtinManifestVersion,
		CaptureFamilies: []BuiltinCaptureFamily{{
			ID: "test-family", MetadataRedacted: true,
		}},
		Templates: []builtinTemplateFile{{
			ID: "builtin:test", Revision: 1, File: "models/compact.json",
			Family: model.RecipeCompact, CaptureFamily: "test-family",
			Endpoint: model.EndpointModels, Method: "GET",
			TimeoutProfile: model.TimeoutL1,
		}},
	}
	if _, err := buildBuiltinSet(&baseline); err != nil {
		t.Fatalf("未经改动的 manifest 应能加载，否则上面每个用例都是假绿: %v", err)
	}
}

// 默认探活头模板必须来自内置 manifest，不能是第二份硬编码。
//
// 管理界面展示的「默认头」与探活实际发的头必须是同一份。两份的后果是
// 用户照着界面上的清单调指纹，而实际发出去的是另一套 —— 排查时对着
// 界面完全看不出问题。
func TestDefaultHeaderTemplateComesFromBuiltinManifest(t *testing.T) {
	set := loadBuiltins(t)
	compact, err := set.Compact(model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}

	shown := DefaultHeaderTemplate()
	if len(shown) == 0 {
		t.Fatal("默认头模板是空的")
	}
	for _, header := range compact.Headers {
		value, ok := shown[strings.ToLower(header.Name)]
		if !ok {
			t.Errorf("内置 compact 模板有头 %q，界面上的默认清单里没有", header.Name)
			continue
		}
		if value != strings.Join(header.Values, ",") {
			t.Errorf("头 %q 的值不一致：模板 %q，界面 %q",
				header.Name, strings.Join(header.Values, ","), value)
		}
	}

	// 副本语义：改返回值不能污染全局。
	shown["user-agent"] = "tampered"
	if again := DefaultHeaderTemplate(); again["user-agent"] == "tampered" {
		t.Error("DefaultHeaderTemplate 返回的必须是副本")
	}
}
