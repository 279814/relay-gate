/* probes.mjs — Probe/Capability 管理功能对象（P0-15）。
 *
 * app.js 只做 shell；本模块挂载列表、抽屉与分页。所有网络经注入的 api client。
 * 不修改、不覆盖工作区脏 app.js；装配由 boot.mjs 完成。
 */

import { bindEscape, focusFirst, openModalLock } from './modal.mjs';
import { field, parseProbeHeadersJSON } from './api.mjs';

export { parseProbeHeadersJSON, field };

const PROBE_TABS = [
  { id: 'capabilities', name: '能力' },
  { id: 'recipes', name: '配方' },
  { id: 'executions', name: '执行' },
  { id: 'calibrations', name: '校准' },
  { id: 'probe-runtime', name: '探活诊断' },
];

function emptyList(extraFilter) {
  return {
    items: [],
    next_cursor: '',
    loading: false,
    filter: Object.assign({}, extraFilter || {}),
  };
}

/**
 * @param {object} shell Alpine 组件实例
 * @param {ReturnType<import('./api.mjs').createApiClient>} api
 */
export function createProbeFeature(shell, api) {
  Object.assign(shell, {
    probeModuleReady: false,
    probeModuleError: '',
    stateRevision: 0,

    endpoints: emptyList({ upstream_id: '' }),
    secrets: emptyList({}),
    recipes: emptyList({}),
    executions: emptyList({}),
    capabilities: emptyList({}),
    reachability: emptyList({}),
    calibrations: emptyList({}),
    probeCostDaily: emptyList({}),
    probeRuntime: null,
    executionDrawer: null,
    recipeDetail: null,
    calibrationDetail: null,
    endpointForm: null,
    secretForm: null,
    recipeForm: null,
    calibForm: { route_id: 0, endpoint: 'messages' },
    reachByUpstream: {},
    capByRouteEndpoint: {},
    _modalUnlock: null,
    _escUnbind: null,

    f: field,

    capabilityBadge(row) {
      if (!row) return { text: 'unknown', stale: false };
      const expires = field(row, 'ExpiresAt', 'expires_at') || 0;
      const state = field(row, 'State', 'state') || 'unknown';
      const now = Date.now();
      if (expires > 0 && expires <= now) return { text: 'expired', stale: true };
      return { text: state, stale: false };
    },

    lazyProbeWarning(up) {
      if (!up) return '';
      const mode = field(up, 'probe_mode', 'ProbeMode') || '';
      if (mode === 'lazy') {
        return 'Lazy 模式不会周期请求；点「测试」会产生一次真实模型调用。';
      }
      return '';
    },

    runtimeDropWarn() {
      const r = this.probeRuntime;
      if (!r) return '';
      const cap = field(r, 'DroppedByCapacity', 'dropped_by_capacity') || 0;
      const pers = field(r, 'DroppedByPersistence', 'dropped_by_persistence') || 0;
      const cand = field(r, 'DroppedCandidates', 'dropped_candidates') || 0;
      if (cap || pers || cand) {
        return `旁路观测有丢弃（capacity=${cap}, persistence=${pers}, candidates=${cand}），不阻断转发。`;
      }
      return '';
    },

    reachStateFor(upstreamID) {
      const row = this.reachByUpstream[upstreamID];
      return row ? (field(row, 'State', 'state') || '—') : '—';
    },

    capStateFor(routeID, endpoint) {
      const key = `${routeID}:${endpoint || 'messages'}`;
      const row = this.capByRouteEndpoint[key];
      if (!row) return '—';
      return this.capabilityBadge(row).text;
    },

    async loadPaged(listKey, path, reset) {
      const list = this[listKey];
      if (!list) return;
      if (reset) {
        list.items = [];
        list.next_cursor = '';
      }
      list.loading = true;
      try {
        const q = new URLSearchParams();
        q.set('limit', '50');
        if (!reset && list.next_cursor) q.set('cursor', list.next_cursor);
        if (list.filter) {
          for (const [k, v] of Object.entries(list.filter)) {
            if (v !== '' && v != null) q.set(k, String(v));
          }
        }
        const page = await api.get(`${path}?${q}`);
        const items = field(page, 'Items', 'items') || [];
        list.items = reset ? items : list.items.concat(items);
        list.next_cursor = field(page, 'NextCursor', 'next_cursor') || '';
      } catch (e) {
        if (e.status === 400) {
          this.err = (e.message || '分页游标无效') + '。已清空筛选，请从首屏重载。';
          list.items = [];
          list.next_cursor = '';
        } else if (e.status !== 503) {
          this.err = e.message;
        }
      } finally {
        list.loading = false;
      }
    },

    onProbeFilterChange(listKey) {
      const list = this[listKey];
      if (!list) return;
      list.next_cursor = '';
      list.items = [];
    },

    async loadEndpoints(reset = true) { await this.loadPaged('endpoints', '/upstream-endpoints', reset); },
    async loadSecrets(reset = true) { await this.loadPaged('secrets', '/probe-secrets', reset); },
    async loadRecipes(reset = true) { await this.loadPaged('recipes', '/probe-recipes', reset); },
    async loadExecutions(reset = true) { await this.loadPaged('executions', '/probe-executions', reset); },
    async loadCapabilities(reset = true) {
      await this.loadPaged('capabilities', '/capabilities', reset);
      this._indexCapabilities();
    },
    async loadReachability(reset = true) {
      await this.loadPaged('reachability', '/reachability', reset);
      this._indexReachability();
    },
    async loadCalibrations(reset = true) { await this.loadPaged('calibrations', '/calibrations', reset); },
    async loadProbeCostDaily(reset = true) { await this.loadPaged('probeCostDaily', '/probe-costs', reset); },

    _indexReachability() {
      const map = {};
      for (const row of this.reachability.items || []) {
        const id = field(row, 'UpstreamID', 'upstream_id');
        if (id != null) map[id] = row;
      }
      this.reachByUpstream = map;
    },
    _indexCapabilities() {
      const map = {};
      for (const row of this.capabilities.items || []) {
        const scope = field(row, 'ScopeType', 'scope_type');
        const scopeID = field(row, 'ScopeID', 'scope_id');
        const ep = field(row, 'Endpoint', 'endpoint') || '';
        if (scope === 'route' || scope === 'RecipeScopeRoute') {
          map[`${scopeID}:${ep}`] = row;
        }
      }
      this.capByRouteEndpoint = map;
    },

    async loadProbeRuntime() {
      try {
        this.probeRuntime = await api.get('/probe-runtime');
      } catch (e) {
        if (e.status !== 503) this.err = e.message;
      }
    },

    async refreshHealthSide() {
      try {
        await Promise.all([
          this.loadReachability(true),
          this.loadCapabilities(true),
        ]);
      } catch {
        /* 可选增强列 */
      }
    },

    async openExecution(id) {
      try {
        this.executionDrawer = await api.get('/probe-executions/' + encodeURIComponent(id));
        this._lockModal(() => this.closeExecution());
        this.$nextTick(() => focusFirst(this.$refs && this.$refs.execDrawer));
      } catch (e) {
        this.err = e.message;
      }
    },
    closeExecution() {
      this.executionDrawer = null;
      this._unlockModal();
    },

    async openRecipe(id) {
      try {
        this.recipeDetail = await api.get('/probe-recipes/' + encodeURIComponent(id));
        this._lockModal(() => { this.recipeDetail = null; this._unlockModal(); });
      } catch (e) {
        this.err = e.message;
      }
    },

    async openCalibration(id) {
      try {
        this.calibrationDetail = await api.get('/calibrations/' + encodeURIComponent(id));
        this._lockModal(() => { this.calibrationDetail = null; this._unlockModal(); });
      } catch (e) {
        this.err = e.message;
      }
    },

    _lockModal(onEsc) {
      this._unlockModal();
      this._modalUnlock = openModalLock();
      this._escUnbind = bindEscape(onEsc);
    },
    _unlockModal() {
      if (this._escUnbind) { this._escUnbind(); this._escUnbind = null; }
      if (this._modalUnlock) { this._modalUnlock(); this._modalUnlock = null; }
    },

    async createRecipe() {
      const f = this.recipeForm || {};
      const { ok } = await this.run(
        () => api.post('/probe-recipes', {
          scope: f.scope || 'upstream',
          scope_id: Number(f.scope_id) || 0,
          endpoint: f.endpoint || 'messages',
        }),
        '已创建配方（draft）',
      );
      if (ok) {
        this.recipeForm = null;
        await this.loadRecipes(true);
      }
    },

    async createSecret() {
      const f = this.secretForm || {};
      const { ok } = await this.run(
        () => api.post('/probe-secrets', { name: f.name, value: f.value }),
        '已创建 Secret（值不回显）',
      );
      if (ok) {
        this.secretForm = null;
        await this.loadSecrets(true);
      }
    },

    async clearSecret(id, rev) {
      if (!confirm('清除该 Secret 的值？名称保留。')) return;
      const { ok } = await this.run(
        () => api.put('/probe-secrets/' + id, { value: '', expected_revision: rev }),
        '已清除 Secret 值',
      );
      if (ok) await this.loadSecrets(true);
    },

    endpointEditable(endpoint) {
      const auth = field(endpoint, 'auth_profile', 'AuthProfile') || {};
      const mode = field(endpoint, 'url_mode', 'URLMode');
      return (!mode || mode === 'canonical') &&
        !field(endpoint, 'needs_review', 'NeedsReview') &&
        !field(endpoint, 'legacy_compat_real_only', 'LegacyCompatRealOnly') &&
        !field(endpoint, 'legacy_full_url_id', 'LegacyFullURLID') &&
        !field(endpoint, 'legacy_full_url_revision', 'LegacyFullURLRevision') &&
        field(auth, 'mode', 'Mode') !== 'legacy_auto_real_only';
    },

    editEndpoint(endpoint) {
      if (endpoint && !this.endpointEditable(endpoint)) {
        this.err = '旧兼容端点请使用 URL 审核或认证校准';
        return;
      }
      const auth = endpoint ? field(endpoint, 'auth_profile', 'AuthProfile') || {} : { mode: 'x_api_key', secret_ref: 'upstream_api_key' };
      const headers = field(auth, 'manual_headers', 'ManualHeaders') || [];
      this.endpointForm = {
        saving: false,
        conflict: false,
        pending: false,
        id: field(endpoint, 'id', 'ID'),
        upstream_id: field(endpoint, 'upstream_id', 'UpstreamID') || '',
        endpoint: field(endpoint, 'endpoint', 'Endpoint', 'Kind') || 'messages',
        url_override: field(endpoint, 'url_override', 'URLOverride') || '',
        fixed_query_template: field(endpoint, 'fixed_query_template', 'FixedQueryTemplate') || '',
        revision: field(endpoint, 'revision', 'Revision') || 0,
        auth_profile: {
          mode: field(auth, 'mode', 'Mode') || '',
          secret_ref: field(auth, 'secret_ref', 'SecretRef') || '',
          header_name: field(auth, 'header_name', 'HeaderName') || '',
          query_name: field(auth, 'query_name', 'QueryName') || '',
          manual_headers: JSON.parse(JSON.stringify(headers)),
        },
        manual_headers_raw: JSON.stringify(headers, null, 2),
      };
    },

    async saveEndpoint() {
      const f = this.endpointForm;
      if (!f || f.saving || f.conflict || f.pending || this.authed !== true) return;
      if (!this.endpointEditable(f)) { this.err = '旧兼容端点请使用 URL 审核或认证校准'; return; }
      const id = field(f, 'id', 'ID');
      const revision = Number(field(f, 'revision', 'Revision')) || 0;
      if (id && revision < 1) { this.err = '请重新读取 Endpoint 版本后再编辑'; return; }
      const profile = field(f, 'auth_profile', 'AuthProfile') || {};
      const auth = {};
      for (const key of ['mode', 'header_name', 'query_name', 'secret_ref', 'manual_headers']) {
        if (profile[key] !== undefined) auth[key] = profile[key];
      }
      if (f.manual_headers_raw !== undefined) {
        try { auth.manual_headers = JSON.parse(f.manual_headers_raw); }
        catch { this.err = '认证头模板须为合法 JSON 数组'; return; }
        if (!Array.isArray(auth.manual_headers)) { this.err = '认证头模板须为 JSON 数组'; return; }
      }
      const body = {
        upstream_id: Number(field(f, 'upstream_id', 'UpstreamID')) || 0,
        endpoint: field(f, 'endpoint', 'Endpoint', 'Kind') || 'messages',
        url_override: field(f, 'url_override', 'URLOverride') || '',
        fixed_query_template: field(f, 'fixed_query_template', 'FixedQueryTemplate') || '',
        auth_profile: auth,
      };
      if (id) body.expected_revision = revision;
      f.saving = true;
      this.err = ''; this.msg = '';
      try {
        if (id) await api.put('/upstream-endpoints/' + id, body);
        else await api.post('/upstream-endpoints', body);
        if (this.endpointForm !== f || this.authed !== true) return;
        this.endpointForm = null;
        this.msg = id ? '已更新 Endpoint' : '已创建 Endpoint';
        await this.loadEndpoints(true);
      } catch (error) {
        if (this.endpointForm !== f || this.authed !== true) return;
        if (error.status === 409) {
          f.conflict = true;
          this.err = 'Endpoint 版本已变化，草稿已保留；请重新读取后确认';
        } else if (error.status === 503 && error.data?.code === 'config_activation_pending' && error.data.persisted === true) {
          f.pending = true;
          f.persisted_id = error.data.id;
          f.persisted_revision = error.data.new_revision;
          this.err = 'Endpoint 已保存，激活待确认；草稿已保留，请重新读取已保存版本后确认';
        } else {
          this.err = error.message || 'Endpoint 保存失败';
        }
      } finally {
        f.saving = false;
      }
    },

    async deleteEndpoint(endpoint) {
      const list = this.endpoints;
      if (this.authed !== true || !endpoint || endpoint.deleting || endpoint.delete_pending || endpoint.delete_conflict) return;
      if (!this.endpointEditable(endpoint)) { this.err = '旧兼容端点不能通过普通管理入口删除'; return; }
      const id = Number(field(endpoint, 'id', 'ID'));
      const revision = Number(field(endpoint, 'revision', 'Revision'));
      if (!Number.isSafeInteger(id) || id < 1 || !Number.isSafeInteger(revision) || revision < 1) { this.err = '请重新加载 Endpoint 版本'; return; }
      if (!globalThis.confirm('仅停用 Upstream 且没有 Route 或历史记录时允许删除 Endpoint。确认删除？')) return;
      endpoint.deleting = true;
      this.err = ''; this.msg = '';
      try {
        await api.del('/upstream-endpoints/' + id + '?expected_revision=' + revision);
        if (this.authed !== true || this.endpoints !== list || !list.items.includes(endpoint)) return;
        list.items = list.items.filter(row => Number(field(row, 'id', 'ID')) !== id);
        this.msg = 'Endpoint #' + id + ' 已删除';
      } catch (error) {
        if (this.authed !== true || this.endpoints !== list || !list.items.includes(endpoint)) return;
        if (error.status === 503 && error.data?.code === 'config_activation_pending' && error.data.persisted === true) {
          endpoint.delete_pending = true;
          this.msg = 'Endpoint #' + id + ' 已删除，待激活；请重新加载列表确认';
        } else if (error.status === 409 || error.status === 404) {
          endpoint.delete_conflict = true;
          this.err = 'Endpoint 版本已变化或记录已不存在；请重新加载列表确认';
        } else { this.err = error.message || 'Endpoint 删除失败'; }
      } finally { endpoint.deleting = false; }
    },

    async reloadEndpoint() {
      const f = this.endpointForm;
      if (!f || f.saving || this.authed !== true) return;
      const id = f.id || f.persisted_id;
      if (!id || !globalThis.confirm('重新读取会替换当前草稿。确认已复制需要保留的修改？')) return;
      f.saving = true;
      try {
        const endpoint = await api.get('/upstream-endpoints/' + id);
        if (this.endpointForm !== f || this.authed !== true) return;
        this.editEndpoint(endpoint);
        this.err = '';
        this.msg = '已重新读取 Endpoint 保存版本，请确认配置后继续';
      } catch (error) {
        if (this.endpointForm !== f || this.authed !== true) return;
        this.err = error.message || 'Endpoint 重新读取失败';
      } finally {
        f.saving = false;
      }
    },

    async planCalibration() {
      const f = this.calibForm || {};
      const { ok } = await this.run(
        () => api.post('/calibrations', {
          route_id: Number(f.route_id) || 0,
          endpoint: f.endpoint || 'messages',
        }),
        '已创建校准计划',
      );
      if (ok) await this.loadCalibrations(true);
    },

    async startCalibration(id, rev) {
      await this.run(
        () => api.post('/calibrations/' + encodeURIComponent(id) + '/start', {
          expected_revision: rev,
        }),
        '校准已启动',
      );
      await this.loadCalibrations(true);
    },

    async cancelCalibration(id, rev) {
      await this.run(
        () => api.post('/calibrations/' + encodeURIComponent(id) + '/cancel', {
          expected_revision: rev,
        }),
        '校准已取消',
      );
      await this.loadCalibrations(true);
    },

    parseHeadersOrThrow(raw) {
      return parseProbeHeadersJSON(raw);
    },

    stageMS(exec, startKey, endKey) {
      const a = field(exec, ...startKey) || 0;
      const b = field(exec, ...endKey) || 0;
      if (!a || !b || b < a) return '—';
      return (b - a) + 'ms';
    },
  });

  return shell;
}

export function mergeProbeTabs(shell) {
  if (!Array.isArray(shell.tabs)) return;
  const have = new Set(shell.tabs.map((t) => t.id));
  for (const t of PROBE_TABS) {
    if (!have.has(t.id)) shell.tabs.push(t);
  }
}

export function probeTabIds() {
  return PROBE_TABS.map((t) => t.id);
}
