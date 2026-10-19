/* transforms.mjs — P4 declarative transform admin UI (§15).
 * Pure text (x-text). Does not modify dirty app.js.
 */

const initialState = () => ({
  sets: [],
  bindings: [],
  executions: [],
  selectedId: 0,
  selected: null,
  newName: '',
  draftRulesJSON: '[]',
  requestReencode: false,
  reqFailPolicy: 'fail_closed',
  resFailPolicy: 'fail_open',
  note: '',
  routeId: '',
  endpointId: '',
  previewPhase: 'request',
  previewBody: '',
  previewResult: '',
  loading: false,
  selectedRead: 0,
  bindingRead: 0,
  bindingTarget: '',
  bindingRevision: null,
  setNextCursor: '',
  setTotal: 0,
  bindingNextCursor: '',
  bindingTotal: 0,
  versions: [],
  versionNextCursor: '',
  versionTotal: 0,
  versionRead: 0,
  activationPending: false,
  budgetRevision: 0,
  budgetBaselineRequestMs: 50,
  budgetBaselineSSEMs: 10,
  budgetRequestMs: 50,
  budgetSSEMs: 10,
  budgetAudit: [],
});

export function createTransformsFeature(shell, api) {
  shell.transforms = initialState();

  shell.changeTransformLifecycle = async function changeTransformLifecycle(action) {
    const state = this.transforms, selected = state.selected;
    if (!selected || state.activationPending || !['disable','enable','archive'].includes(action)) return;
    try {
      const data = await api.post('/transforms/' + selected.id + '/' + action,{expected_revision:selected.revision});
      if (this.transforms !== state || state.selected !== selected) return;
      state.selected = data;
      this.msg = '状态已更新：' + data.state;
      await this.loadTransforms();
    } catch (error) {
      if (this.transforms !== state) return;
      if (error.data?.persisted) state.activationPending = true;
      this.err = error.message || String(error);
    }
  };
  shell.loadTransformVersions = async function loadTransformVersions(next = false) {
    const state = this.transforms, id = state.selectedId;
    if (!id || (next && !state.versionNextCursor)) return;
    const read = ++state.versionRead;
    try {
      const data = await api.get('/transforms/' + id + '/versions?limit=50' + (next ? '&cursor=' + encodeURIComponent(state.versionNextCursor) : ''));
      if (this.transforms !== state || state.selectedId !== id || state.versionRead !== read) return;
      state.versions = data.versions || []; state.versionNextCursor = data.next_cursor || ''; state.versionTotal = data.total || 0;
    } catch (error) { if (this.transforms === state && state.selectedId === id && state.versionRead === read) this.err = error.message || String(error); }
  };
  shell.rollbackTransform = async function rollbackTransform(versionId) {
    const state = this.transforms;
    const route = Number(state.routeId), endpoint = Number(state.endpointId);
    if (state.activationPending || state.bindingTarget !== route + ':' + endpoint || !state.bindingRevision) {
      this.err = '请先加载已有目标绑定并核对版本'; return;
    }
    try {
      const data = await api.post('/transforms/rollback',{route_id:route,endpoint_id:endpoint,version_id:versionId,expected_revision:state.bindingRevision});
      if (this.transforms !== state) return;
      state.bindingRevision = null; state.bindingTarget = '';
      this.msg = '已回滚到版本 #' + data.published_id;
      await this.loadTransforms();
    } catch (error) {
      if (this.transforms !== state) return;
      if (error.data?.persisted) state.activationPending = true;
      this.err = error.message || String(error);
    }
  };

  shell.loadTransformBinding = async function loadTransformBinding() {
    const state = this.transforms;
    const read = ++state.bindingRead;
    const route = Number(state.routeId), endpoint = Number(state.endpointId);
    state.bindingRevision = null; state.bindingTarget = '';
    if (!Number.isSafeInteger(route) || route < 1 || !Number.isSafeInteger(endpoint) || endpoint < 1) {
      this.err = '绑定需要有效的 Route 和 Endpoint ID'; return;
    }
    try {
      const data = await api.get('/transform-bindings?route_id=' + route + '&endpoint_id=' + endpoint + '&limit=1');
      if (this.transforms !== state || state.bindingRead !== read || Number(state.routeId) !== route || Number(state.endpointId) !== endpoint) return;
      state.bindingTarget = route + ':' + endpoint;
      state.bindingRevision = data.bindings?.[0]?.revision ?? 0;
      this.msg = data.bindings?.length ? '目标绑定版本 ' + state.bindingRevision + '，转换集 #' + data.bindings[0].set_id : '目标尚未绑定，版本 0';
    } catch (error) { if (this.transforms === state && state.bindingRead === read) this.err = error.message || String(error); }
  };
  shell.reloadTransformBudgets = async function reloadTransformBudgets() {
    const state = this.transforms;
    try {
      const data = await api.get('/transforms/budgets');
      if (this.transforms !== state) return;
      Object.assign(state, {budgetRevision:data.revision,budgetRequestMs:data.budgets.request_ms,budgetSSEMs:data.budgets.sse_event_ms,
        budgetBaselineRequestMs:data.budgets.request_ms,budgetBaselineSSEMs:data.budgets.sse_event_ms,budgetAudit:data.audit || []});
    } catch (error) { if (this.transforms === state) this.err = error.message || String(error); }
  };
  shell.nextTransformPage = async function nextTransformPage(kind) {
    const state = this.transforms;
    const sets = kind === 'sets';
    const cursor = sets ? state.setNextCursor : state.bindingNextCursor;
    if (!cursor || state.loading) return;
    state.loading = true;
    try {
      const data = await api.get((sets ? '/transforms' : '/transform-bindings') + '?limit=50&cursor=' + encodeURIComponent(cursor));
      if (this.transforms !== state) return;
      if (sets) { state.sets = data.sets || []; state.setNextCursor = data.next_cursor || ''; state.setTotal = data.total || 0; }
      else { state.bindings = data.bindings || []; state.bindingNextCursor = data.next_cursor || ''; state.bindingTotal = data.total || 0; }
    } catch (error) { if (this.transforms === state) this.err = error.message || String(error); }
    finally { state.loading = false; }
  };

  shell.loadTransforms = async function loadTransforms() {
    const state = this.transforms;
    try {
      this.transforms.loading = true;
      const [sets, bindings, executions, budgets] = await Promise.all([
        api.get('/transforms'),
        api.get('/transform-bindings'),
        api.get('/transform-executions?limit=50'),
        api.get('/transforms/budgets'),
      ]);
      if (this.transforms !== state) return;
      this.transforms.sets = sets.sets || [];
      state.setNextCursor = sets.next_cursor || '';
      state.setTotal = sets.total || 0;
      this.transforms.bindings = bindings.bindings || [];
      state.bindingNextCursor = bindings.next_cursor || '';
      state.bindingTotal = bindings.total || 0;
      this.transforms.executions = executions.executions || [];
      if (budgets && budgets.budgets && !state.budgetRevision) {
        state.budgetRevision = budgets.revision;
        state.budgetBaselineRequestMs = budgets.budgets.request_ms;
        state.budgetBaselineSSEMs = budgets.budgets.sse_event_ms;
        this.transforms.budgetRequestMs = budgets.budgets.request_ms;
        this.transforms.budgetSSEMs = budgets.budgets.sse_event_ms;
        this.transforms.budgetAudit = budgets.audit || [];
      }
    } catch (e) {
      if (this.transforms !== state) return;
      this.err = e && e.message ? e.message : String(e);
    } finally {
      state.loading = false;
    }
  };

  shell.selectTransformSet = async function selectTransformSet(set) {
    const state = this.transforms;
    const read = ++state.selectedRead;
    if (!set.draft) {
      try { set = await api.get('/transforms/' + set.id); }
      catch (error) { if (this.transforms === state && read === state.selectedRead) this.err = error.message || String(error); return; }
      if (this.transforms !== state || read !== state.selectedRead) return;
    }
    this.transforms.selectedId = set.id;
    this.transforms.selected = set;
    state.versions = []; state.versionNextCursor = ''; state.versionTotal = 0; ++state.versionRead;
    const draft = set.draft || {};
    const rules = draft.rules || [];
    this.transforms.requestReencode = rules.some((r) => r.kind === 'request_reencode');
    this.transforms.draftRulesJSON = JSON.stringify(rules.filter((r) => r.kind !== 'request_reencode'), null, 2);
    this.transforms.reqFailPolicy = draft.req_fail_policy || 'fail_closed';
    this.transforms.resFailPolicy = draft.res_fail_policy || 'fail_open';
    this.transforms.note = draft.note || '';
  };

  shell.createTransformSet = async function createTransformSet() {
    const state = this.transforms;
    try {
      const name = (this.transforms.newName || '').trim();
      if (!name) {
        this.err = '请填写转换集名称';
        return;
      }
      const set = await api.post('/transforms', { name });
      if (this.transforms !== state) return;
      this.transforms.newName = '';
      this.msg = '已创建转换集 #' + set.id;
      await this.loadTransforms();
      if (this.transforms !== state) return;
      this.selectTransformSet(set);
    } catch (e) {
      if (this.transforms !== state) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.saveTransformDraft = async function saveTransformDraft() {
    const state = this.transforms;
    const selectedRead = state.selectedRead;
    try {
      let rules;
      try {
        rules = JSON.parse(this.transforms.draftRulesJSON || '[]');
      } catch (pe) {
        this.err = '规则 JSON 无效：' + (pe && pe.message ? pe.message : pe);
        return;
      }
      if (!Array.isArray(rules)) {
        this.err = '规则必须是 JSON 数组';
        return;
      }
      rules = rules.filter((r) => r && r.kind !== 'request_reencode');
      if (this.transforms.requestReencode) rules.unshift({ kind: 'request_reencode' });
      const set = await api.put('/transforms/' + this.transforms.selectedId + '/draft', {
        expected_revision: state.selected?.revision,
        rules,
        req_fail_policy: this.transforms.reqFailPolicy,
        res_fail_policy: this.transforms.resFailPolicy,
        note: this.transforms.note,
      });
      if (this.transforms !== state) return;
      if (state.selectedRead !== selectedRead) return;
      this.msg = '草稿已保存（revision ' + (set.draft && set.draft.revision) + '）';
      this.selectTransformSet(set);
      await this.loadTransforms();
    } catch (e) {
      if (this.transforms !== state) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.previewTransform = async function previewTransform() {
    const state = this.transforms;
    const selectedRead = state.selectedRead;
    try {
      const data = await api.post('/transforms/' + this.transforms.selectedId + '/preview', {
        expected_revision: state.selected?.revision,
        phase: this.transforms.previewPhase || 'request',
        body: this.transforms.previewBody || '',
        resp_body: this.transforms.previewBody || '',
        status: 200,
      });
      if (this.transforms !== state) return;
      if (state.selectedRead !== selectedRead) return;
      this.transforms.previewResult = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    } catch (e) {
      if (this.transforms !== state) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.publishTransform = async function publishTransform() {
    const state = this.transforms;
    const selectedRead = state.selectedRead;
    if (state.activationPending) { this.err = '转换已保存但尚待激活，请先检查服务状态，勿重复发布'; return; }
    try {
      const routeId = Number(this.transforms.routeId);
      const endpointId = Number(this.transforms.endpointId);
      if (!routeId || !endpointId) {
        this.err = '发布需要 route_id 与 endpoint_id';
        return;
      }
      if (state.bindingTarget !== routeId + ':' + endpointId || state.bindingRevision === null) {
        this.err = '请先加载目标绑定并核对版本'; return;
      }
      const data = await api.post('/transforms/' + this.transforms.selectedId + '/publish', {
        expected_revision: state.selected?.revision,
        expected_binding_revision: state.bindingRevision,
        route_id: routeId,
        endpoint_id: endpointId,
      });
      if (this.transforms !== state) return;
      if (state.selectedRead !== selectedRead) return;
      this.msg = '已发布 version=' + (data.version && data.version.id);
      state.selected.revision = data.set_revision;
      state.bindingRevision = data.binding.revision;
      await this.loadTransforms();
    } catch (e) {
      if (this.transforms !== state) return;
      if (e.data?.persisted) state.activationPending = true;
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.shadowTransform = async function shadowTransform() {
    const state = this.transforms;
    const selectedRead = state.selectedRead;
    try {
      const routeId = Number(this.transforms.routeId);
      const endpointId = Number(this.transforms.endpointId);
      if (!routeId || !endpointId) {
        this.err = 'Shadow 需要 route_id 与 endpoint_id';
        return;
      }
      if (state.bindingTarget !== routeId + ':' + endpointId || state.bindingRevision === null) {
        this.err = '请先加载目标绑定并核对版本'; return;
      }
      const data = await api.post('/transforms/' + this.transforms.selectedId + '/shadow', {
        expected_revision: state.selected?.revision,
        expected_binding_revision: state.bindingRevision,
        route_id: routeId,
        endpoint_id: endpointId,
      });
      if (this.transforms !== state) return;
      if (state.selectedRead !== selectedRead) return;
      this.msg = '已 shadow version=' + (data.version && data.version.id);
      state.selected.revision = data.set_revision;
      state.bindingRevision = data.binding.revision;
      await this.loadTransforms();
    } catch (e) {
      if (this.transforms !== state) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.saveTransformBudgets = async function saveTransformBudgets() {
    const state = this.transforms;
    try {
      const requestMs = Number(this.transforms.budgetRequestMs);
      const sseMs = Number(this.transforms.budgetSSEMs);
      const raising = requestMs > state.budgetBaselineRequestMs || sseMs > state.budgetBaselineSSEMs;
      if (this.transforms !== state) return;
      let confirmRaise = false;
      if (raising) {
        confirmRaise = window.confirm(
          '提高转换执行预算需要二次确认并写入审计。确定将 request_ms=' +
            requestMs +
            '、sse_event_ms=' +
            sseMs +
            '？'
        );
        if (!confirmRaise) {
          this.msg = '已取消提高预算';
          return;
        }
      }
      const data = await api.put('/transforms/budgets', {
        expected_revision: state.budgetRevision,
        request_ms: requestMs,
        sse_event_ms: sseMs,
        confirm_raise: confirmRaise,
      });
      if (this.transforms !== state) return;
      this.transforms.budgetRequestMs = data.budgets.request_ms;
      this.transforms.budgetSSEMs = data.budgets.sse_event_ms;
      this.transforms.budgetAudit = data.audit || [];
      state.budgetRevision = data.revision;
      state.budgetBaselineRequestMs = data.budgets.request_ms;
      state.budgetBaselineSSEMs = data.budgets.sse_event_ms;
      this.msg = raising ? '已提高执行预算并记录审计' : '已更新执行预算';
    } catch (e) {
      if (this.transforms !== state) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };
  const originalReset = shell.reset;
  shell.reset = function resetTransforms() {
    this.transforms = initialState();
    return originalReset?.call(this);
  };
}

export function mergeTransformsTab(shell) {
  if (!Array.isArray(shell.tabs)) return;
  if (shell.tabs.some((t) => t && t.id === 'transforms')) return;
  const secIdx = shell.tabs.findIndex((t) => t && t.id === 'security');
  const tab = { id: 'transforms', name: '转换' };
  if (secIdx >= 0) shell.tabs.splice(secIdx + 1, 0, tab);
  else shell.tabs.push(tab);
}
