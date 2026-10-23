/* Bounded Security Center management. Evidence stays in the existing Sample. */
export const securityManagementState = () => ({
  review: null, routeTarget: null, ignoreDraft: null, rules: [], ruleTotal: 0, ruleCursor: '', ruleNext: '',
  diagnostics: [], diagnosticTotal: 0, diagnosticNext: '', diagnosticSource: '', diagnosticVerdict: '', diagnosticLoading: false,
  ruleScope: '', ruleActive: '', busy: false, conflict: false, error: '', evidence: null, alertStatus: null,
});
const findingPath = id => '/security/findings/' + encodeURIComponent(id);
const copyRule = rule => ({id: rule.id, scope: rule.scope, rule_id: rule.rule_id, route_id: rule.route_id,
  enabled: rule.enabled, revision: rule.revision, permanent: rule.expires_at_ms === 0,
  expires: localTime(rule.expires_at_ms || Date.now() + 86400000)});
function localTime(ms) { const date = new Date(ms); return new Date(ms - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16); }
const reasonText = reason => ({untrusted_finding: '发现未记录可信扫描关联，原始证据不可用', incomplete_scan: '扫描不完整，不能确认原始证据',
  sample_missing_or_ambiguous: '样本未保留或关联不唯一，原始证据不可用', original_response_unavailable: '原始响应视图未知、不完整或已省略',
  original_upstream_response: '已关联完整的原上游响应，读取须再次认证'})[reason] || '原始证据状态未知';

export function createSecurityManagement(shell, api) {
  let ruleRead = {}, routeRead = {}, diagnosticRead = {};
  const fail = (state, error) => { state.management.error = error?.message || '安全管理操作失败'; if (error?.data?.persisted === true && error?.data?.code === 'config_activation_pending') {state.management.conflict = true; state.management.error = '操作已保存，激活待确认；请重新载入核对，勿重复提交。';} else if (error?.status === 409) {state.management.conflict = true; state.management.error = '版本冲突，编辑已保留；请关闭后重新载入，勿重复提交。';} };
  shell.inspectSecurityRoute = async function(finding) {
    const state = this.security, m = state.management, token = {}; if (m.busy) return; routeRead = token; m.routeTarget = null; m.error = ''; m.conflict = false;
    try { const route = await api.get('/routes/' + finding.route_id); if (this.security !== state || routeRead !== token) return;
      if (!finding.upstream_id || route.upstream_id !== finding.upstream_id) throw new Error('Route 当前上游与发现记录不一致，无法直接操作；请到路由页核对');
      m.routeTarget = {id: route.id, upstream_id: route.upstream_id, revision: route.revision, enabled: route.enabled};
    } catch(error) {if (this.security === state && routeRead === token) fail(state, error);}
  };
  shell.disableSecurityRoute = async function() {
    const state = this.security, m = state.management, route = m.routeTarget; if (!route || !route.enabled || m.busy || m.conflict) return; m.busy = true; m.error = '';
    try {const result = await api.put('/routes/' + route.id, {expected_revision: route.revision, enabled: false}); if (this.security !== state) return;
      if (result?.persisted === true && result?.activation_pending === true) {m.conflict = true; m.error = 'Route 已保存，激活待确认；请重新载入后核对，勿重复提交。'; return;}
      m.routeTarget = result;
    } catch(error) {if (this.security === state) fail(state, error);} finally {m.busy = false;}
  };
  shell.loadSecurityDiagnostics = async function(cursor = '') {
    const state = this.security, m = state.management, token = {}; diagnosticRead = token; m.diagnosticLoading = true; m.diagnostics = []; m.diagnosticTotal = 0; m.diagnosticNext = ''; m.error = '';
    try { const route = Number(state.routeID), upstream = Number(state.upstreamID);
      if (![route, upstream].every(id => Number.isSafeInteger(id) && id >= 0)) throw new Error('诊断 Route 或 Upstream ID 无效');
      const query = new URLSearchParams({limit: '25'}); if (cursor) query.set('cursor', cursor); if (route) query.set('route_id', String(route)); if (upstream) query.set('upstream_id', String(upstream)); if (m.diagnosticSource) query.set('source', m.diagnosticSource); if (m.diagnosticVerdict) query.set('verdict', m.diagnosticVerdict);
      const page = await api.get('/security/diagnostics?' + query); if (this.security !== state || diagnosticRead !== token) return;
      if (!Array.isArray(page.items) || page.items.length > 25 || !Number.isSafeInteger(page.total) || page.total < 0) throw new Error('安全诊断分页响应无效');
      m.diagnostics = page.items; m.diagnosticTotal = page.total; m.diagnosticNext = page.next_cursor || '';
    } catch(error) {if (this.security === state && diagnosticRead === token) fail(state, error);} finally {if (this.security === state && diagnosticRead === token) m.diagnosticLoading = false;}
  };
  shell.inspectSecurityDiagnostic = async function(execution) {
    const state = this.security, token = {}; diagnosticRead = token; this.executionDrawer = null;
    try {const detail = await api.get('/security/diagnostics/' + encodeURIComponent(execution.ID)); if (this.security !== state || diagnosticRead !== token) return; this.executionDrawer = detail;}
    catch(error) {if (this.security === state && diagnosticRead === token) fail(state, error);}
  };
  shell.editSecurityReview = function(finding) { const m = this.security.management; if (m.busy) return; m.review = {findingID: finding.id, status: finding.review?.status || 'open', revision: finding.review?.revision || 1}; m.ignoreDraft = null; m.conflict = false; m.error = ''; };
  shell.closeSecurityManagement = function() { const m = this.security.management; if (m.busy) return; m.review = null; m.ignoreDraft = null; m.conflict = false; m.error = ''; };
  shell.saveSecurityReview = async function() {
    const state = this.security, m = state.management, draft = m.review;
    if (!draft || m.busy || m.conflict) return;
    m.busy = true; m.error = '';
    try { await api.put(findingPath(draft.findingID) + '/review', {expected_revision: draft.revision, status: draft.status}); if (this.security !== state) return; m.review = null; await this.loadSecurityFindings(); }
    catch(error) { if (this.security === state) fail(state, error); }
    finally { m.busy = false; }
  };
  shell.newSecurityIgnore = function(finding, scope) {
    const m = this.security.management; if (m.busy || !['rule', 'route'].includes(scope)) return;
    m.ignoreDraft = copyRule({id: 0, scope, rule_id: scope === 'rule' ? finding.rule_id : '', route_id: scope === 'route' ? finding.route_id : 0, enabled: true, expires_at_ms: Date.now() + 86400000, revision: 0});
    m.review = null; m.conflict = false; m.error = '';
  };
  shell.editSecurityIgnore = function(rule) { const m = this.security.management; if (m.busy) return; m.ignoreDraft = copyRule(rule); m.review = null; m.conflict = false; m.error = ''; };
  shell.loadSecurityIgnoreRules = async function(cursor = '') {
    const state = this.security, m = state.management, token = {}; ruleRead = token;
    m.rules = []; m.ruleTotal = 0; m.ruleNext = ''; m.ruleCursor = cursor; m.error = '';
    const query = new URLSearchParams({limit: '25'}); if (cursor) query.set('cursor', cursor); if (m.ruleScope) query.set('scope', m.ruleScope); if (m.ruleActive) query.set('active', m.ruleActive);
    try { const result = await api.get('/security/ignore-rules?' + query); if (this.security !== state || ruleRead !== token) return;
      if (!Array.isArray(result.rules) || result.rules.length > 25 || !Number.isSafeInteger(result.total) || result.total < 0) throw new Error('忽略规则分页响应无效');
      m.rules = result.rules; m.ruleTotal = result.total; m.ruleNext = result.next_cursor || '';
    } catch(error) { if (this.security === state && ruleRead === token) fail(state, error); }
  };
  shell.saveSecurityIgnore = async function() {
    const state = this.security, m = state.management, draft = m.ignoreDraft; if (!draft || m.busy || m.conflict) return;
    m.busy = true; m.error = '';
    try {
      const expires = draft.permanent ? 0 : new Date(draft.expires).getTime();
      if (!Number.isSafeInteger(expires) || expires < 0 || expires > 0 && expires <= Date.now()) throw new Error('到期时间须为未来时刻，或明确选择不过期');
      const body = {scope: draft.scope, rule_id: draft.rule_id, route_id: draft.route_id, expires_at_ms: expires, enabled: draft.enabled};
      if (draft.id) { body.expected_revision = draft.revision; await api.put('/security/ignore-rules/' + draft.id, body); } else await api.post('/security/ignore-rules', body);
      if (this.security !== state) return; m.ignoreDraft = null; await this.loadSecurityIgnoreRules(); await this.loadSecurityFindings();
    } catch(error) { if (this.security === state) fail(state, error); } finally { m.busy = false; }
  };
  shell.deleteSecurityIgnore = async function(rule) {
    const state = this.security, m = state.management; if (m.busy || m.conflict) return; m.busy = true; m.error = '';
    try { await api.request('DELETE', '/security/ignore-rules/' + rule.id, {expected_revision: rule.revision}); if (this.security !== state) return; await this.loadSecurityIgnoreRules(); await this.loadSecurityFindings(); }
    catch(error) { if (this.security === state) fail(state, error); } finally { m.busy = false; }
  };
  shell.openSecurityEvidence = async function(finding) {
    const state = this.security; state.management.evidence = {findingID: finding.id, password: '', busy: true, available: false, reason: '', error: '', body: '', format: '', status: 0};
    const evidence = state.management.evidence;
    try { const result = await api.get(findingPath(finding.id) + '/evidence-metadata'); if (this.security !== state || state.management.evidence !== evidence) return; evidence.available = result.available === true; evidence.reason = reasonText(result.reason); }
    catch(error) { if (this.security === state && state.management.evidence === evidence) evidence.error = error?.message || '证据关联读取失败'; }
    finally { evidence.busy = false; }
  };
  shell.closeSecurityEvidence = function() { const evidence = this.security.management.evidence; if (evidence) { evidence.password = ''; evidence.body = ''; } this.security.management.evidence = null; };
  shell.readSecurityEvidence = async function() {
    const state = this.security, evidence = state.management.evidence; if (!evidence || evidence.busy || !evidence.available || !evidence.password) return;
    const password = evidence.password; evidence.password = ''; evidence.busy = true; evidence.error = ''; evidence.body = '';
    try { const result = await api.post(findingPath(evidence.findingID) + '/evidence', {password}); if (this.security !== state || state.management.evidence !== evidence) return;
      evidence.available = result.available === true; evidence.reason = reasonText(result.reason); evidence.status = result.status || 0;
      if (result.available) { const encoded = result.body || ''; const bytes = Uint8Array.from(atob(encoded), value => value.charCodeAt(0));
        const contentEncoding = Object.entries(result.headers || {}).find(([key]) => key.toLowerCase() === 'content-encoding')?.[1]?.join(',');
        try { if (contentEncoding && contentEncoding !== 'identity') throw new Error('encoded'); evidence.body = new TextDecoder('utf-8', {fatal: true}).decode(bytes); evidence.format = '原上游 UTF-8 正文'; }
        catch { evidence.body = encoded; evidence.format = '原上游编码字节（Base64；未经解压或文本替换）'; }
      }
    } catch(error) { if (this.security === state && state.management.evidence === evidence) evidence.error = error?.message || '原始证据读取失败'; }
    finally { evidence.busy = false; }
  };
  shell.loadSecurityAlertStatus = async function() { const state = this.security; try {const status = await api.get('/security/alert-status'); if (this.security === state) state.management.alertStatus = status;} catch(error) {if (this.security === state) fail(state, error);} };
}
