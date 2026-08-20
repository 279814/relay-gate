package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

type legacyUpstreamConfig struct {
	id            int64
	baseURL       string
	apiKey        string
	authStyle     model.AuthStyle
	fullURLMode   bool
	l1Path        string
	probeHeaders  map[string]string
	createdAt     int64
	updatedAt     int64
	protocolCount map[model.Protocol]struct{}
}

type legacyModelConfig struct {
	id             int64
	name           string
	protocol       model.Protocol
	probePrompt    string
	probeMaxTokens int
}

type legacyRouteConfig struct {
	id            int64
	upstreamID    int64
	model         legacyModelConfig
	upstreamModel string
}

func backfillSchemaTwo(ctx context.Context, db schemaTwoExecutor, cipher *Cipher) error {
	probeMode, err := legacyProbeMode(ctx, db)
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `UPDATE upstream SET probe_mode=?`, probeMode); err != nil {
		return fmt.Errorf("迁移 probe_mode: %w", err)
	}

	upstreams, err := loadLegacyUpstreamConfigs(ctx, db, cipher)
	if err != nil {
		return err
	}
	models, err := loadLegacyModelConfigs(ctx, db)
	if err != nil {
		return err
	}
	routes, err := loadLegacyRouteConfigs(ctx, db, models)
	if err != nil {
		return err
	}
	for _, route := range routes {
		upstream := upstreams[route.upstreamID]
		if upstream == nil {
			return fmt.Errorf("%w: route %d 指向不存在的 upstream %d", ErrUnknownSchema, route.id, route.upstreamID)
		}
		upstream.protocolCount[route.model.protocol] = struct{}{}
	}

	for _, upstream := range orderedLegacyUpstreams(upstreams) {
		if err := backfillLegacyEndpoints(ctx, db, cipher, upstream); err != nil {
			return err
		}
		if err := backfillLegacyModelsRecipe(ctx, db, cipher, upstream); err != nil {
			return err
		}
	}
	for _, route := range routes {
		upstream := upstreams[route.upstreamID]
		if err := backfillLegacyRouteRecipes(ctx, db, cipher, upstream, route); err != nil {
			return err
		}
	}
	return nil
}

func legacyProbeMode(ctx context.Context, db schemaTwoExecutor) (model.ProbeMode, error) {
	rows, err := db.QueryContext(ctx, `SELECT value FROM setting WHERE key='settings'`)
	if err != nil {
		return "", fmt.Errorf("读取 legacy settings: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", err
		}
		return model.ProbeModeActive, nil
	}
	var raw []byte
	if err := rows.Scan(&raw); err != nil {
		return "", fmt.Errorf("扫描 legacy settings: %w", err)
	}
	if rows.Next() {
		return "", fmt.Errorf("%w: settings key 出现重复行", ErrUnknownSchema)
	}
	settings, err := DecodeLegacySettings(raw)
	if err != nil {
		return "", fmt.Errorf("迁移 legacy settings: %w", err)
	}
	if settings.ProbeEnabled {
		return model.ProbeModeActive, nil
	}
	return model.ProbeModeLazy, nil
}

func loadLegacyUpstreamConfigs(ctx context.Context, db schemaTwoExecutor, cipher *Cipher) (map[int64]*legacyUpstreamConfig, error) {
	rows, err := db.QueryContext(ctx, `SELECT id,base_url,api_key_enc,auth_style,full_url_mode,l1_path,
		probe_headers,created_at,updated_at FROM upstream ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取 legacy upstream: %w", err)
	}
	defer rows.Close()
	result := make(map[int64]*legacyUpstreamConfig)
	for rows.Next() {
		var item legacyUpstreamConfig
		var encrypted, headersJSON string
		if err := rows.Scan(&item.id, &item.baseURL, &encrypted, &item.authStyle, &item.fullURLMode,
			&item.l1Path, &headersJSON, &item.createdAt, &item.updatedAt); err != nil {
			return nil, fmt.Errorf("扫描 legacy upstream: %w", err)
		}
		plain, err := cipher.Decrypt(encrypted)
		if err != nil {
			return nil, fmt.Errorf("解密 legacy upstream %d: %w", item.id, err)
		}
		item.apiKey = plain
		item.probeHeaders = make(map[string]string)
		if headersJSON != "" {
			if err := json.Unmarshal([]byte(headersJSON), &item.probeHeaders); err != nil {
				return nil, fmt.Errorf("upstream %d probe_headers: %w", item.id, err)
			}
		}
		item.protocolCount = make(map[model.Protocol]struct{})
		result[item.id] = &item
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func loadLegacyModelConfigs(ctx context.Context, db schemaTwoExecutor) (map[int64]legacyModelConfig, error) {
	rows, err := db.QueryContext(ctx, `SELECT id,name,protocol,probe_prompt,probe_max_tokens FROM model_name ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取 legacy model_name: %w", err)
	}
	defer rows.Close()
	result := make(map[int64]legacyModelConfig)
	for rows.Next() {
		var item legacyModelConfig
		if err := rows.Scan(&item.id, &item.name, &item.protocol, &item.probePrompt, &item.probeMaxTokens); err != nil {
			return nil, fmt.Errorf("扫描 legacy model_name: %w", err)
		}
		if !item.protocol.Valid() {
			return nil, fmt.Errorf("%w: model_name %d protocol=%q", ErrUnknownSchema, item.id, item.protocol)
		}
		result[item.id] = item
	}
	return result, rows.Err()
}

func loadLegacyRouteConfigs(ctx context.Context, db schemaTwoExecutor, models map[int64]legacyModelConfig) ([]legacyRouteConfig, error) {
	rows, err := db.QueryContext(ctx, `SELECT id,model_name_id,upstream_id,upstream_model FROM route ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取 legacy route: %w", err)
	}
	defer rows.Close()
	var result []legacyRouteConfig
	for rows.Next() {
		var item legacyRouteConfig
		var modelID int64
		if err := rows.Scan(&item.id, &modelID, &item.upstreamID, &item.upstreamModel); err != nil {
			return nil, fmt.Errorf("扫描 legacy route: %w", err)
		}
		modelValue, ok := models[modelID]
		if !ok {
			return nil, fmt.Errorf("%w: route %d 指向不存在的 model_name %d", ErrUnknownSchema, item.id, modelID)
		}
		item.model = modelValue
		result = append(result, item)
	}
	return result, rows.Err()
}

func orderedLegacyUpstreams(values map[int64]*legacyUpstreamConfig) []*legacyUpstreamConfig {
	ids := make([]int64, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	result := make([]*legacyUpstreamConfig, 0, len(ids))
	for _, id := range ids {
		result = append(result, values[id])
	}
	return result
}

func backfillLegacyEndpoints(ctx context.Context, db schemaTwoExecutor, cipher *Cipher, upstream *legacyUpstreamConfig) error {
	legacyURLID := int64(0)
	legacyURLRevision := int64(0)
	multiProtocol := len(upstream.protocolCount) > 1
	if upstream.fullURLMode {
		encrypted, err := cipher.Encrypt(upstream.baseURL)
		if err != nil {
			return err
		}
		inferred := inferredLegacyEndpoint(upstream.protocolCount)
		result, err := db.ExecContext(ctx, `INSERT INTO legacy_full_url
			(upstream_id,url_enc,masked_url,fingerprint,inferred_endpoint,needs_review,revision,created_at,updated_at)
			VALUES (?,?,?,?,?,1,1,?,?)`, upstream.id, encrypted, maskLegacyURL(upstream.baseURL),
			cipher.Fingerprint("legacy-full-url", []byte(upstream.baseURL)), nullableEndpoint(inferred), upstream.createdAt, upstream.updatedAt)
		if err != nil {
			return fmt.Errorf("迁移 upstream %d legacy full URL: %w", upstream.id, err)
		}
		legacyURLID, err = result.LastInsertId()
		if err != nil {
			return err
		}
		legacyURLRevision = 1
	}

	kinds := []model.EndpointKind{model.EndpointModels}
	if upstream.fullURLMode {
		for protocol := range upstream.protocolCount {
			kind, _ := protocol.Endpoint()
			kinds = append(kinds, kind)
			if protocol == model.ProtoAnthropic {
				kinds = append(kinds, model.EndpointCountTokens)
			}
		}
	} else {
		kinds = append(kinds, model.EndpointMessages, model.EndpointResponses,
			model.EndpointChatCompletions, model.EndpointCountTokens)
	}
	kinds = uniqueEndpointKinds(kinds)
	for _, kind := range kinds {
		mode := model.EndpointURLCanonical
		legacyID := int64(0)
		legacyRevision := int64(0)
		needsReview := false
		compatRealOnly := upstream.authStyle == model.AuthAuto
		urlOverride := ""
		if kind == model.EndpointModels {
			// 与创建/更新路径共用同一个翻译函数。三处各写一份的话，
			// 「迁移出来的站」与「新建的站」会得到不同的 models URL，
			// 而那个差异只在探活结果上显形。
			legacyUpstream := model.Upstream{BaseURL: upstream.baseURL, L1Path: upstream.l1Path}
			urlOverride = legacyUpstream.EndpointURLOverride(model.EndpointModels)
		} else if upstream.fullURLMode {
			mode = model.EndpointURLLegacyExact
			legacyID = legacyURLID
			legacyRevision = legacyURLRevision
			needsReview = true
			compatRealOnly = compatRealOnly || multiProtocol
		}
		authMode, headerName := legacyAuthProfile(upstream.authStyle)
		_, err := db.ExecContext(ctx, `INSERT INTO upstream_endpoint
			(upstream_id,endpoint,url_mode,legacy_full_url_id,legacy_full_url_revision,
			 legacy_compat_real_only,url_override,auth_mode,auth_header_name,auth_secret_ref,
			 auth_profile_revision,revision,needs_review,created_at,updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,'upstream_api_key',1,1,?,?,?)`,
			upstream.id, kind, mode, nullablePositiveID(legacyID), legacyRevision,
			compatRealOnly, urlOverride, authMode, headerName, needsReview, upstream.createdAt, upstream.updatedAt)
		if err != nil {
			return fmt.Errorf("迁移 upstream %d endpoint %s: %w", upstream.id, kind, err)
		}
	}
	return nil
}

func backfillLegacyModelsRecipe(ctx context.Context, db schemaTwoExecutor, cipher *Cipher, upstream *legacyUpstreamConfig) error {
	method := http.MethodGet
	if upstream.l1Path == "" {
		method = http.MethodHead
	}
	headers, quarantined := legacyHeaderTemplates(cipher, upstream, model.ProtoAnthropic, false)
	version := model.ProbeRecipeVersion{
		Origin:         model.RecipeLegacyMigration,
		Method:         method,
		Headers:        headers,
		TimeoutProfile: model.TimeoutL1,
		CreatedAt:      upstream.updatedAt,
	}
	return insertLegacyRecipe(ctx, db, model.RecipeScopeUpstream, upstream.id, model.EndpointModels, version, quarantined)
}

func backfillLegacyRouteRecipes(ctx context.Context, db schemaTwoExecutor, cipher *Cipher, upstream *legacyUpstreamConfig, route legacyRouteConfig) error {
	endpoint, _ := route.model.protocol.Endpoint()
	version := legacyRouteRecipeVersion(cipher, upstream, route, endpoint)
	quarantined := legacyValueLooksSecret(route.model.probePrompt, upstream.apiKey)
	if _, headerRisk := legacyHeaderTemplates(cipher, upstream, route.model.protocol, true); headerRisk {
		quarantined = true
	}
	if err := insertLegacyRecipe(ctx, db, model.RecipeScopeRoute, route.id, endpoint, version, quarantined); err != nil {
		return err
	}
	if route.model.protocol == model.ProtoAnthropic {
		countVersion := legacyRouteRecipeVersion(cipher, upstream, route, model.EndpointCountTokens)
		if err := insertLegacyRecipe(ctx, db, model.RecipeScopeRoute, route.id, model.EndpointCountTokens, countVersion, quarantined); err != nil {
			return err
		}
	}
	return nil
}

func legacyRouteRecipeVersion(cipher *Cipher, upstream *legacyUpstreamConfig, route legacyRouteConfig, endpoint model.EndpointKind) model.ProbeRecipeVersion {
	stream := endpoint != model.EndpointCountTokens
	headers, _ := legacyHeaderTemplates(cipher, upstream, route.model.protocol, stream)
	maxTokens := route.model.probeMaxTokens
	if maxTokens <= 0 {
		maxTokens = 1
	}
	var body string
	timeout := model.TimeoutL2Standard
	switch endpoint {
	case model.EndpointMessages:
		body = fmt.Sprintf(`{"max_tokens":%d,"messages":[{"content":"{{PROBE_PROMPT}}","role":"user"}],"model":"{{UPSTREAM_MODEL}}","stream":true}`, maxTokens)
	case model.EndpointCountTokens:
		body = `{"messages":[{"content":"{{PROBE_PROMPT}}","role":"user"}],"model":"{{UPSTREAM_MODEL}}"}`
		timeout = model.TimeoutCountTokens
	case model.EndpointResponses:
		if maxTokens < 16 {
			maxTokens = 16
		}
		body = fmt.Sprintf(`{"input":"{{PROBE_PROMPT}}","max_output_tokens":%d,"model":"{{UPSTREAM_MODEL}}","stream":true}`, maxTokens)
	case model.EndpointChatCompletions:
		body = fmt.Sprintf(`{"max_tokens":%d,"messages":[{"content":"{{PROBE_PROMPT}}","role":"user"}],"model":"{{UPSTREAM_MODEL}}","stream":true}`, maxTokens)
	}
	return model.ProbeRecipeVersion{
		Origin:         model.RecipeLegacyMigration,
		Method:         http.MethodPost,
		Headers:        headers,
		Body:           []byte(body),
		BodyIsText:     true,
		StreamExpected: stream,
		TimeoutProfile: timeout,
		CreatedAt:      upstream.updatedAt,
	}
}

func insertLegacyRecipe(ctx context.Context, db schemaTwoExecutor, scope model.RecipeScope, scopeID int64, endpoint model.EndpointKind, version model.ProbeRecipeVersion, quarantined bool) error {
	status := model.RecipeLegacy
	if quarantined {
		status = model.RecipeQuarantined
	}
	upstreamID, routeID := nullableScopeIDs(scope, scopeID)
	result, err := db.ExecContext(ctx, `INSERT INTO probe_recipe
		(upstream_id,route_id,endpoint,status,pinned,revision,active_binding_revision,created_at,updated_at)
		VALUES (?,?,?,?,0,1,1,?,?)`, upstreamID, routeID, endpoint, status, version.CreatedAt, version.CreatedAt)
	if err != nil {
		return fmt.Errorf("迁移 %s %d recipe %s: %w", scope, scopeID, endpoint, err)
	}
	recipeID, err := result.LastInsertId()
	if err != nil {
		return err
	}
	version.RecipeID = recipeID
	version.Version = 1
	content := probetemplate.TemplateContent{Method: version.Method, RawQuery: version.FixedRawQuery, Headers: version.Headers, Body: version.Body}
	required, scanErr := probetemplate.ScanRequiredSecrets(endpoint, content)
	if scanErr != nil {
		if !quarantined {
			return fmt.Errorf("编译 legacy recipe %s/%d/%s: %w", scope, scopeID, endpoint, scanErr)
		}
		version.Headers = []model.HeaderTemplate{{Name: "X-Relay-Legacy-Quarantine", Values: []string{"redacted"}}}
		version.Body = nil
		version.BodyIsText = false
		version.StreamExpected = false
		if endpoint != model.EndpointModels {
			version.Body = []byte(`{}`)
			version.BodyIsText = true
		}
		required = nil
	}
	headersJSON, err := json.Marshal(version.Headers)
	if err != nil {
		return err
	}
	versionResult, err := db.ExecContext(ctx, `INSERT INTO probe_recipe_version
		(recipe_id,version,origin,method,fixed_raw_query,headers_json,body,body_is_text,
		 stream_expected,timeout_profile,created_at) VALUES (?,1,?,?,?,?,?,?,?,?,?)`,
		recipeID, version.Origin, version.Method, version.FixedRawQuery, string(headersJSON), version.Body,
		version.BodyIsText, version.StreamExpected, version.TimeoutProfile, version.CreatedAt)
	if err != nil {
		return fmt.Errorf("迁移 recipe version %d/%s: %w", recipeID, endpoint, err)
	}
	versionID, err := versionResult.LastInsertId()
	if err != nil {
		return err
	}
	for _, name := range required {
		if _, err := db.ExecContext(ctx, `INSERT INTO recipe_version_required_secret
			(recipe_version_id,name,bound_name_snapshot) VALUES (?,?,?)`, versionID, name, name); err != nil {
			return fmt.Errorf("迁移 recipe required secret %q: %w", name, err)
		}
	}
	if _, err := db.ExecContext(ctx, `UPDATE probe_recipe SET draft_version_id=?,published_version_id=? WHERE id=?`, versionID, versionID, recipeID); err != nil {
		return fmt.Errorf("绑定 legacy recipe version: %w", err)
	}
	return nil
}

var legacyDefaultProbeHeaders = map[string]string{
	"User-Agent":     "claude-cli/2.1.220 (external, sdk-cli)",
	"X-App":          "cli",
	"Accept":         "application/json",
	"Content-Type":   "application/json",
	"Anthropic-Beta": "claude-code-20250219,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advanced-tool-use-2025-11-20,effort-2025-11-24,fallback-credit-2026-06-01",
	"Anthropic-Dangerous-Direct-Browser-Access": "true",
	"X-Stainless-Lang":                          "js",
	"X-Stainless-Package-Version":               "0.70.1",
	"X-Stainless-Os":                            "Windows",
	"X-Stainless-Arch":                          "x64",
	"X-Stainless-Runtime":                       "node",
	"X-Stainless-Retry-Count":                   "0",
}

func legacyHeaderTemplates(cipher *Cipher, upstream *legacyUpstreamConfig, protocol model.Protocol, stream bool) ([]model.HeaderTemplate, bool) {
	values := make(map[string]string, len(legacyDefaultProbeHeaders)+len(upstream.probeHeaders)+1)
	for name, value := range legacyDefaultProbeHeaders {
		values[http.CanonicalHeaderKey(name)] = value
	}
	if protocol == model.ProtoAnthropic {
		values["Anthropic-Version"] = "2023-06-01"
	}
	if stream {
		values["Accept"] = "text/event-stream"
	}
	quarantined := false
	for name, value := range upstream.probeHeaders {
		canonical := http.CanonicalHeaderKey(name)
		if canonical == "" || strings.ContainsAny(name, "\r\n\x00") {
			quarantined = true
			continue
		}
		if value == "" {
			delete(values, canonical)
			continue
		}
		if model.IsAuthHeader(canonical) {
			if value != upstream.apiKey && value != "Bearer "+upstream.apiKey {
				quarantined = true
			}
			continue
		}
		if value == upstream.apiKey {
			value = "{{UPSTREAM_API_KEY}}"
		} else if strings.Contains(value, upstream.apiKey) && upstream.apiKey != "" {
			value = strings.ReplaceAll(value, upstream.apiKey, "{{UPSTREAM_API_KEY}}")
		} else if legacyValueLooksSecret(value, upstream.apiKey) || strings.ContainsAny(value, "\r\n\x00") {
			quarantined = true
			value = "redacted:" + cipher.Fingerprint("legacy-probe-header", []byte(value))
		}
		values[canonical] = value
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]model.HeaderTemplate, 0, len(names))
	for _, name := range names {
		result = append(result, model.HeaderTemplate{Name: name, Values: []string{values[name]}})
	}
	return result, quarantined
}

func legacyValueLooksSecret(value, known string) bool {
	if known != "" && strings.Contains(value, known) {
		return false
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "sk-") || strings.Contains(lower, "rk-") || strings.HasPrefix(lower, "bearer ") {
		return true
	}
	compact := 0
	for _, char := range value {
		if unicode.IsLetter(char) || unicode.IsDigit(char) || strings.ContainsRune("_-", char) {
			compact++
		} else {
			compact = 0
		}
		if compact >= 32 {
			return true
		}
	}
	return false
}

func legacyAuthProfile(style model.AuthStyle) (model.AuthMode, string) {
	switch style {
	case model.AuthBearer:
		return model.AuthModeBearer, "Authorization"
	case model.AuthXAPIKey:
		return model.AuthModeXAPIKey, "X-Api-Key"
	default:
		return model.AuthModeLegacyAutoRealOnly, ""
	}
}

func inferredLegacyEndpoint(protocols map[model.Protocol]struct{}) model.EndpointKind {
	if len(protocols) != 1 {
		return ""
	}
	for protocol := range protocols {
		kind, _ := protocol.Endpoint()
		return kind
	}
	return ""
}

func nullableEndpoint(kind model.EndpointKind) any {
	if kind == "" {
		return nil
	}
	return kind
}

func nullablePositiveID(id int64) any {
	if id <= 0 {
		return nil
	}
	return id
}

func nullableScopeIDs(scope model.RecipeScope, id int64) (any, any) {
	if scope == model.RecipeScopeUpstream {
		return id, nil
	}
	return nil, id
}

func uniqueEndpointKinds(values []model.EndpointKind) []model.EndpointKind {
	seen := make(map[model.EndpointKind]struct{}, len(values))
	result := make([]model.EndpointKind, 0, len(values))
	for _, value := range values {
		if !value.Valid() {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func maskLegacyURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "***"
	}
	return parsed.Scheme + "://" + parsed.Host + "/…"
}
