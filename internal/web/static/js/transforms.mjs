/* transforms.mjs — P4 declarative transform admin UI (§15).
 * Pure text (x-text). Does not modify dirty app.js.
 */

export function createTransformsFeature(shell, api) {
  shell.transforms = {
    sets: [],
    bindings: [],
    executions: [],
    selectedId: 0,
    selected: null,
    newName: '',
    draftRulesJSON: '[]',
    reqFailPolicy: 'fail_closed',
    resFailPolicy: 'fail_open',
    note: '',
    routeId: '',
    endpointId: '',
    previewPhase: 'request',
    previewBody: '',
    previewResult: '',
    loading: false,
    budgetRequestMs: 50,
    budgetSSEMs: 10,
    budgetAudit: [],
  };

  shell.loadTransforms = async function loadTransforms() {
    try {
      this.transforms.loading = true;
      const [sets, bindings, executions, budgets] = await Promise.all([
        api.get('/transforms'),
        api.get('/transform-bindings'),
        api.get('/transform-executions?limit=50'),
        api.get('/transforms/budgets'),
      ]);
      this.transforms.sets = sets.sets || [];
      this.transforms.bindings = bindings.bindings || [];
      this.transforms.executions = executions.executions || [];
      if (budgets && budgets.budgets) {
        this.transforms.budgetRequestMs = budgets.budgets.request_ms;
        this.transforms.budgetSSEMs = budgets.budgets.sse_event_ms;
        this.transforms.budgetAudit = budgets.audit || [];
      }
      if (this.transforms.selectedId) {
        const still = this.transforms.sets.find((s) => s.id === this.transforms.selectedId);
        if (still) this.selectTransformSet(still);
        else {
          this.transforms.selectedId = 0;
          this.transforms.selected = null;
        }
      }
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    } finally {
      this.transforms.loading = false;
    }
  };

  shell.selectTransformSet = function selectTransformSet(set) {
    this.transforms.selectedId = set.id;
    this.transforms.selected = set;
    const draft = set.draft || {};
    this.transforms.draftRulesJSON = JSON.stringify(draft.rules || [], null, 2);
    this.transforms.reqFailPolicy = draft.req_fail_policy || 'fail_closed';
    this.transforms.resFailPolicy = draft.res_fail_policy || 'fail_open';
    this.transforms.note = draft.note || '';
  };

  shell.createTransformSet = async function createTransformSet() {
    try {
      const name = (this.transforms.newName || '').trim();
      if (!name) {
        this.err = '请填写转换集名称';
        return;
      }
      const set = await api.post('/transforms', { name });
      this.transforms.newName = '';
      this.msg = '已创建转换集 #' + set.id;
      await this.loadTransforms();
      this.selectTransformSet(set);
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.saveTransformDraft = async function saveTransformDraft() {
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
      const set = await api.put('/transforms/' + this.transforms.selectedId + '/draft', {
        rules,
        req_fail_policy: this.transforms.reqFailPolicy,
        res_fail_policy: this.transforms.resFailPolicy,
        note: this.transforms.note,
      });
      this.msg = '草稿已保存（revision ' + (set.draft && set.draft.revision) + '）';
      await this.loadTransforms();
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.previewTransform = async function previewTransform() {
    try {
      const data = await api.post('/transforms/' + this.transforms.selectedId + '/preview', {
        phase: this.transforms.previewPhase || 'request',
        body: this.transforms.previewBody || '',
        resp_body: this.transforms.previewBody || '',
        status: 200,
      });
      this.transforms.previewResult = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.publishTransform = async function publishTransform() {
    try {
      const routeId = Number(this.transforms.routeId);
      const endpointId = Number(this.transforms.endpointId);
      if (!routeId || !endpointId) {
        this.err = '发布需要 route_id 与 endpoint_id';
        return;
      }
      const data = await api.post('/transforms/' + this.transforms.selectedId + '/publish', {
        route_id: routeId,
        endpoint_id: endpointId,
      });
      this.msg = '已发布 version=' + (data.version && data.version.id);
      await this.loadTransforms();
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.shadowTransform = async function shadowTransform() {
    try {
      const routeId = Number(this.transforms.routeId);
      const endpointId = Number(this.transforms.endpointId);
      if (!routeId || !endpointId) {
        this.err = 'Shadow 需要 route_id 与 endpoint_id';
        return;
      }
      const data = await api.post('/transforms/' + this.transforms.selectedId + '/shadow', {
        route_id: routeId,
        endpoint_id: endpointId,
      });
      this.msg = '已 shadow version=' + (data.version && data.version.id);
      await this.loadTransforms();
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.saveTransformBudgets = async function saveTransformBudgets() {
    try {
      const requestMs = Number(this.transforms.budgetRequestMs);
      const sseMs = Number(this.transforms.budgetSSEMs);
      const curReq = Number(this.transforms._lastReqMs || 50);
      const curSSE = Number(this.transforms._lastSSEMs || 10);
      // Prefer last loaded values for raise detection; fall back to defaults.
      let raising = false;
      try {
        const cur = await api.get('/transforms/budgets');
        const b = (cur && cur.budgets) || {};
        raising = requestMs > Number(b.request_ms) || sseMs > Number(b.sse_event_ms);
      } catch (_) {
        raising = requestMs > curReq || sseMs > curSSE;
      }
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
        request_ms: requestMs,
        sse_event_ms: sseMs,
        confirm_raise: confirmRaise,
      });
      this.transforms.budgetRequestMs = data.budgets.request_ms;
      this.transforms.budgetSSEMs = data.budgets.sse_event_ms;
      this.transforms.budgetAudit = data.audit || [];
      this.msg = raising ? '已提高执行预算并记录审计' : '已更新执行预算';
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
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
