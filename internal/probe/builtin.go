package probe

// 版本化内置模板（P0-06、§8.3）。
//
// 这是四级解析的最后一级（§8.2）。它存在的理由不是「少写点 Go」：探活 body
// 原先在 buildProbeBody 里按协议临时拼 map，于是「探活到底发了什么」只能靠
// 读代码回答 —— 而那个答案要同时解释三种协议的字段名差异、max_output_tokens
// 的实测下限、以及哪些头是抓包来的哪些是猜的。改成带 revision 的数据文件后，
// 这些问题由文件回答，且每一条都被断言钉住（builtin_test.go）。
//
// capture family 与模板分开记：客户端版本会随升级变化，而 §3.1 的原话是
// 「内置探活不能把一次抓包中的版本号、会话 ID 或 beta 列表永久写死」。
// 一个 Recipe 固定的是**当时那个**版本；升级客户端时新增一个 family 与一批
// 新 revision 的模板，旧的留着 —— 已经落库的观察结论仍指向它当时用的那份。

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

// builtin 目录随二进制一起打包。
//
// 必须 embed 而不是运行时读文件：这一级是「没有任何用户配置时仍要能探活」
// 的兜底，而一个依赖外部文件的兜底会在部署少拷一个目录时静默消失 ——
// 症状是所有未配置 Recipe 的站探不了，而错误指向的是「找不到文件」。
//
//go:embed builtin
var builtinFS embed.FS

// builtinManifestVersion 是本代码能读的 manifest 版本。
//
// 不认识的版本直接拒绝而不是尽力解析：manifest 描述的是**要发出去的请求**，
// 半懂半猜地解析一份未来格式，最好的结果是报错，最坏的是发一个字段缺失的
// 请求 —— 而那会被上游报成「请求形状被拒」，归因落在站上而不在这份文件上。
const builtinManifestVersion = 1

// BuiltinCaptureFamily 是一批模板共同的证据来源。
//
// ClientVersion 为空表示「没有客户端抓包」（protocol-baseline）。那种族的模板
// **不能**带客户端指纹 —— 编一个 UA 出来等于伪造证据来源，而下游会把它当成
// 「真实客户端就是这么发的」。
type BuiltinCaptureFamily struct {
	ID               string `json:"id"`
	Client           string `json:"client,omitempty"`
	ClientVersion    string `json:"client_version,omitempty"`
	MetadataRedacted bool   `json:"metadata_redacted"`
	Note             string `json:"note,omitempty"`
}

// BuiltinTemplate 是一条内置模板。
//
// Body 是原始字节而不是 map：body 可以不是 JSON（§8.5「body 是任意原始字节」），
// 而 Compiled 只替换占位符、其余字节原样保留。
type BuiltinTemplate struct {
	ID            string             `json:"id"`
	Revision      int64              `json:"revision"`
	File          string             `json:"file"`
	Family        model.RecipeSource `json:"family"`
	CaptureFamily string             `json:"capture_family"`

	Endpoint       model.EndpointKind        `json:"endpoint"`
	Method         string                    `json:"method"`
	TimeoutProfile model.ProbeTimeoutProfile `json:"timeout_profile"`
	StreamExpected bool                      `json:"stream_expected"`

	RawQuery string                 `json:"raw_query,omitempty"`
	Headers  []model.HeaderTemplate `json:"headers,omitempty"`
	Body     []byte                 `json:"body,omitempty"`

	// EstimatedInputTokens 与 MaxOutputTokens 服务成本估算（§5.2d）。
	// MaxOutputTokens 必须与 body 里那个字段的值一致，否则成本报告会稳定地
	// 报一个与实际不同的数（builtin_test.go 第 4 条钉住这点）。
	EstimatedInputTokens int64 `json:"estimated_input_tokens"`
	MaxOutputTokens      int64 `json:"max_output_tokens"`

	// Requires 声明这个候选需要上游支持什么（如 `beta:context-1m-2025-08-07`）。
	// 非空即意味着它不是通用模板 —— 选择器按它过滤，而不是把开关注入全部站。
	Requires []string `json:"requires,omitempty"`

	MinimalOutput string `json:"minimal_output,omitempty"`
	Note          string `json:"note,omitempty"`

	compiled *probetemplate.CompiledRecipe
}

// Compiled 返回编译好的模板。加载时就编译，见 LoadBuiltinTemplates。
func (template *BuiltinTemplate) Compiled() *probetemplate.CompiledRecipe {
	if template == nil {
		return nil
	}
	return template.compiled
}

// Header 取某个头的值（多值以逗号连接）。名字大小写不敏感。
//
// 逗号连接而不是只返回第一个：anthropic-beta 这类头的语义就是一个逗号分隔的
// 列表，只看第一项会让「带没带 context-1m」这个判断在多值写法下失效。
func (template *BuiltinTemplate) Header(name string) string {
	if template == nil {
		return ""
	}
	for _, header := range template.Headers {
		if strings.EqualFold(header.Name, name) {
			return strings.Join(header.Values, ",")
		}
	}
	return ""
}

// Identity 是这份模板在 ProbeExecution 里的身份（§19.1）。
//
// storage 自己就说明来源，不靠「哪些 ID 是 0」推断：Store 侧按 ResolvedLayer
// 决定重读哪一层并比较 facts（store/capability.go 的 ResolvedEmbedded 分支），
// 认错来源会让比较落在错误的字段上。
func (template *BuiltinTemplate) Identity() model.RecipeIdentity {
	return model.RecipeIdentity{
		Storage:    model.RecipeStorageEmbedded,
		Origin:     template.Family,
		TemplateID: template.ID,
		Revision:   template.Revision,
	}
}

// EstimatedCost 是这次探活的估算 token 上界。
//
// 上界而不是期望值：输出按 max_output_tokens 计，而实际生成通常更少（判定
// 一出就断流，§4.1）。成本估算宁可高估 —— 低估会让「探活策略是否过激」这个
// 判断偏向「没问题」，而那正是最不该出错的方向。
func (template *BuiltinTemplate) EstimatedCost() int64 {
	return template.EstimatedInputTokens + template.MaxOutputTokens
}

// BuiltinSet 是加载并编译好的全部内置模板。
type BuiltinSet struct {
	families  map[string]BuiltinCaptureFamily
	templates []*BuiltinTemplate
	byID      map[string]*BuiltinTemplate
	compact   map[model.EndpointKind]*BuiltinTemplate
}

// Templates 按 manifest 顺序返回全部模板。
//
// 返回切片副本而不是内部切片：调用方 sort 一下就会打乱「compact 唯一性」
// 之外的顺序假设，而那种影响只在另一个测试里显形。
func (set *BuiltinSet) Templates() []*BuiltinTemplate {
	if set == nil {
		return nil
	}
	return append([]*BuiltinTemplate(nil), set.templates...)
}

// Endpoints 返回有内置模板的 endpoint，顺序稳定。
func (set *BuiltinSet) Endpoints() []model.EndpointKind {
	if set == nil {
		return nil
	}
	kinds := make([]model.EndpointKind, 0, len(set.compact))
	for kind := range set.compact {
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(left, right int) bool { return kinds[left] < kinds[right] })
	return kinds
}

// CaptureFamily 按 ID 取证据来源。
func (set *BuiltinSet) CaptureFamily(id string) (BuiltinCaptureFamily, error) {
	family, ok := set.families[id]
	if !ok {
		return BuiltinCaptureFamily{}, fmt.Errorf("未知 capture family %q", id)
	}
	return family, nil
}

// ByID 按 template ID 取模板。
//
// 供持久化回读用：一条 execution 记的是 TemplateID+revision，重放它时要能
// 拿回同一份内容。找不到时报错而不是回 nil —— 那说明这条记录来自一个已被
// 删掉的模板，静默用另一份内容重放会得出一个无法解释的比较结果。
func (set *BuiltinSet) ByID(id string) (*BuiltinTemplate, error) {
	template, ok := set.byID[id]
	if !ok {
		return nil, fmt.Errorf("未知内置模板 %q", id)
	}
	return template, nil
}

// Compact 取该 endpoint 用于周期探活的模板（§8.3：周期优先 compact-native）。
func (set *BuiltinSet) Compact(endpoint model.EndpointKind) (*BuiltinTemplate, error) {
	template, ok := set.compact[endpoint]
	if !ok {
		return nil, fmt.Errorf("endpoint %s 没有内置 compact 模板", endpoint)
	}
	return template, nil
}

// Requiring 返回声明需要某项能力的候选模板。
//
// 子串匹配：requires 里写的是 `beta:context-1m-2025-08-07`，而调用方通常只
// 知道上游错误信息里的 `context-1m`。要求完整匹配的话，每个调用点都得知道
// 完整的 beta 名与日期后缀 —— 而那个后缀会随 beta 版本变化。
func (set *BuiltinSet) Requiring(capability string) []*BuiltinTemplate {
	var found []*BuiltinTemplate
	for _, template := range set.templates {
		for _, requirement := range template.Requires {
			if strings.Contains(requirement, capability) {
				found = append(found, template)
				break
			}
		}
	}
	return found
}

// ── 加载 ────────────────────────────────────────────────

// builtinManifestFile 是 manifest.json 的形状。
type builtinManifestFile struct {
	Version         int                    `json:"version"`
	CaptureFamilies []BuiltinCaptureFamily `json:"capture_families"`
	Templates       []builtinTemplateFile  `json:"templates"`
}

// builtinTemplateFile 是 manifest 里的一条，内容部分在 File 指向的文件里。
//
// 元数据与内容分开存：一条 200 行的 body 塞进 manifest 会让「有哪些模板」
// 这个问题需要翻几百行才能回答，而那正是 manifest 要解决的问题。
type builtinTemplateFile struct {
	ID            string             `json:"id"`
	Revision      int64              `json:"revision"`
	File          string             `json:"file"`
	Family        model.RecipeSource `json:"family"`
	CaptureFamily string             `json:"capture_family"`

	Endpoint       model.EndpointKind        `json:"endpoint"`
	Method         string                    `json:"method"`
	TimeoutProfile model.ProbeTimeoutProfile `json:"timeout_profile"`
	StreamExpected bool                      `json:"stream_expected"`

	EstimatedInputTokens int64    `json:"estimated_input_tokens"`
	MaxOutputTokens      int64    `json:"max_output_tokens"`
	Requires             []string `json:"requires,omitempty"`
	MinimalOutput        string   `json:"minimal_output,omitempty"`
	Note                 string   `json:"note,omitempty"`
}

// builtinContentFile 是单个模板文件的形状。
//
// body_text 与 body_base64 互斥，与管理 API 的约定一致（§8.5）。两个都给时
// 报错而不是挑一个：那意味着写模板的人对内容有两种想法，而我们无从知道哪个
// 是他要的。
type builtinContentFile struct {
	RawQuery   string                 `json:"raw_query,omitempty"`
	Headers    []model.HeaderTemplate `json:"headers,omitempty"`
	BodyText   string                 `json:"body_text,omitempty"`
	BodyBase64 string                 `json:"body_base64,omitempty"`
	Note       string                 `json:"note,omitempty"`
}

var (
	builtinOnce sync.Once
	builtinSet  *BuiltinSet
	builtinErr  error
)

// LoadBuiltinTemplates 加载并编译全部内置模板，结果缓存。
//
// 缓存是安全的：内容来自 embed，进程生命周期内不会变。缓存的收益不是省 IO
// 而是省编译 —— 每次探活都编译一遍七份模板是纯浪费，而它们的编译结果是
// 只读的（Render 不改 CompiledRecipe）。
func LoadBuiltinTemplates() (*BuiltinSet, error) {
	builtinOnce.Do(func() {
		var manifest builtinManifestFile
		content, err := builtinFS.ReadFile("builtin/manifest.json")
		if err != nil {
			builtinErr = fmt.Errorf("读取内置模板 manifest: %w", err)
			return
		}
		decoder := json.NewDecoder(strings.NewReader(string(content)))
		// 未知字段报错：manifest 里多一个拼错的键（`timeout_profil`）会让那一项
		// 落回零值，而零值 timeout profile 在编译时才失败 —— 错误指向的是
		// 「profile 无效」，不是「你把键拼错了」。
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&manifest); err != nil {
			builtinErr = fmt.Errorf("解析内置模板 manifest: %w", err)
			return
		}
		builtinSet, builtinErr = buildBuiltinSet(&manifest)
	})
	return builtinSet, builtinErr
}

// buildBuiltinSet 校验 manifest 并编译每条模板。
//
// 任何一条不合法就整体失败，不跳过坏条目：跳过的后果是某个 endpoint 静默
// 失去兜底，而那在运行时表现为「这个端点探不了」，错误信息与 JSON 笔误
// 之间没有任何可见联系。
func buildBuiltinSet(manifest *builtinManifestFile) (*BuiltinSet, error) {
	if manifest.Version != builtinManifestVersion {
		return nil, fmt.Errorf("内置模板 manifest 版本 %d 不受支持（本代码只读 %d）",
			manifest.Version, builtinManifestVersion)
	}

	set := &BuiltinSet{
		families: make(map[string]BuiltinCaptureFamily, len(manifest.CaptureFamilies)),
		byID:     make(map[string]*BuiltinTemplate, len(manifest.Templates)),
		compact:  make(map[model.EndpointKind]*BuiltinTemplate),
	}
	for _, family := range manifest.CaptureFamilies {
		if family.ID == "" {
			return nil, fmt.Errorf("capture family 缺少 id")
		}
		if _, exists := set.families[family.ID]; exists {
			return nil, fmt.Errorf("capture family %q 重复", family.ID)
		}
		if !family.MetadataRedacted {
			// 与 fixture manifest 同一条门禁：一份没脱敏的抓包不该进仓库。
			return nil, fmt.Errorf("capture family %q 未声明元数据已脱敏", family.ID)
		}
		set.families[family.ID] = family
	}

	for index := range manifest.Templates {
		entry := &manifest.Templates[index]
		// ID 唯一性在读文件**之前**查：它是 manifest 自身的一致性，与文件内容
		// 无关。放到后面的话，两条同 ID 且其中一条文件名写错的 manifest 会先
		// 报「文件不存在」——而真正的问题是那两条本该只有一条。
		if entry.ID == "" {
			return nil, fmt.Errorf("内置模板缺少 id")
		}
		if _, exists := set.byID[entry.ID]; exists {
			return nil, fmt.Errorf("内置模板 ID %q 重复", entry.ID)
		}

		template, err := loadBuiltinTemplate(set, entry)
		if err != nil {
			return nil, err
		}
		set.byID[template.ID] = template
		set.templates = append(set.templates, template)

		if template.Family == model.RecipeCompact {
			if previous, exists := set.compact[template.Endpoint]; exists {
				return nil, fmt.Errorf("endpoint %s 有两个 compact 模板（%q 与 %q），"+
					"周期探活的选择会由遍历顺序决定", template.Endpoint, previous.ID, template.ID)
			}
			set.compact[template.Endpoint] = template
		}
	}
	return set, nil
}

func loadBuiltinTemplate(set *BuiltinSet, entry *builtinTemplateFile) (*BuiltinTemplate, error) {
	if entry.ID == "" {
		return nil, fmt.Errorf("内置模板缺少 id")
	}
	if entry.Revision < 1 {
		return nil, fmt.Errorf("内置模板 %q 的 revision 必须为正数，得到 %d", entry.ID, entry.Revision)
	}
	switch entry.Family {
	case model.RecipeCompact, model.RecipeCalibration, model.RecipeBasic:
	default:
		// 只收 §8.3 的三类。manual / learned 是用户与学习器的来源，
		// 一条内置模板声称自己是 manual 会让 origin 这个字段失去含义。
		return nil, fmt.Errorf("内置模板 %q 的 family %q 不是 §8.3 的三类之一"+
			"（compact_native / calibration_native / basic_protocol）", entry.ID, entry.Family)
	}
	if _, err := set.CaptureFamily(entry.CaptureFamily); err != nil {
		return nil, fmt.Errorf("内置模板 %q 的 capture family 无效: %w", entry.ID, err)
	}
	if want := entry.Endpoint.Method(); entry.Method != want {
		// endpoint 决定 method（models 是 GET，其余 POST）。不一致时报错而不是
		// 按 endpoint 纠正：manifest 是这份内容的唯一声明，静默纠正会让文件
		// 说的和实际发的不是一回事。
		return nil, fmt.Errorf("内置模板 %q 的 method %q 与 endpoint %s 要求的 %q 不符",
			entry.ID, entry.Method, entry.Endpoint, want)
	}

	content, err := loadBuiltinContent(entry)
	if err != nil {
		return nil, err
	}

	template := &BuiltinTemplate{
		ID: entry.ID, Revision: entry.Revision, File: entry.File,
		Family: entry.Family, CaptureFamily: entry.CaptureFamily,
		Endpoint: entry.Endpoint, Method: entry.Method,
		TimeoutProfile: entry.TimeoutProfile, StreamExpected: entry.StreamExpected,
		RawQuery: content.RawQuery, Headers: content.Headers,
		EstimatedInputTokens: entry.EstimatedInputTokens,
		MaxOutputTokens:      entry.MaxOutputTokens,
		Requires:             entry.Requires,
		MinimalOutput:        entry.MinimalOutput, Note: entry.Note,
	}
	if template.Body, err = builtinBody(entry.ID, content); err != nil {
		return nil, err
	}

	// 走 ProbeRecipeVersion 的那套校验而不是只调 CompileContent：
	// ValidateForEndpoint 还管 timeout profile 与 endpoint 的对应关系
	// （models 必须 l1、count_tokens 必须 count_tokens），而一份内置模板
	// 配错超时档的表现是解析出来后在别处被拒 —— 那时错误指向超时档，
	// 不指向这个文件。
	compiled, err := probetemplate.Compile(entry.Endpoint, model.ProbeRecipeVersion{
		Method:         template.Method,
		FixedRawQuery:  template.RawQuery,
		Headers:        template.Headers,
		Body:           template.Body,
		BodyIsText:     content.BodyBase64 == "",
		StreamExpected: template.StreamExpected,
		TimeoutProfile: template.TimeoutProfile,
	})
	if err != nil {
		return nil, fmt.Errorf("编译内置模板 %q（%s）: %w", entry.ID, entry.File, err)
	}
	// 内置模板不能引用 Probe Secret：这一级是「用户什么都没配」时的兜底，
	// 而 Secret 是用户建的。引用了就等于兜底本身需要先配点什么。
	if secrets := compiled.RequiredSecrets(); len(secrets) > 0 {
		return nil, fmt.Errorf("内置模板 %q 引用了 Probe Secret %v，"+
			"而它必须零配置可用", entry.ID, secrets)
	}
	template.compiled = compiled
	return template, nil
}

func loadBuiltinContent(entry *builtinTemplateFile) (*builtinContentFile, error) {
	if entry.File == "" {
		return nil, fmt.Errorf("内置模板 %q 缺少 file", entry.ID)
	}
	// 只接受 builtin/ 下的相对路径。embed.FS 本身不越界，但 `..` 会让
	// manifest 看起来能指向仓库别处 —— 拒掉比解释为什么它无效更省事。
	clean := path.Clean(entry.File)
	if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
		return nil, fmt.Errorf("内置模板 %q 的 file %q 必须是 builtin/ 下的相对路径",
			entry.ID, entry.File)
	}
	raw, err := builtinFS.ReadFile(path.Join("builtin", clean))
	if err != nil {
		return nil, fmt.Errorf("读取内置模板 %q 的文件 %q: %w", entry.ID, entry.File, err)
	}
	var content builtinContentFile
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&content); err != nil {
		return nil, fmt.Errorf("解析内置模板 %q 的文件 %q: %w", entry.ID, entry.File, err)
	}
	return &content, nil
}

// builtinBody 解出 body 字节，落实 body_text / body_base64 互斥（§8.5）。
func builtinBody(id string, content *builtinContentFile) ([]byte, error) {
	if content.BodyText != "" && content.BodyBase64 != "" {
		return nil, fmt.Errorf("内置模板 %q 同时给了 body_text 与 body_base64，两者互斥（§8.5）", id)
	}
	if content.BodyBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(content.BodyBase64)
		if err != nil {
			return nil, fmt.Errorf("内置模板 %q 的 body_base64 不是合法 base64: %w", id, err)
		}
		return decoded, nil
	}
	if content.BodyText == "" {
		return nil, nil
	}
	return []byte(content.BodyText), nil
}
