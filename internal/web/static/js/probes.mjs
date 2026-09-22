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

    async saveEndpoint() {
      const f = this.endpointForm;
      if (!f) return;
      const id = field(f, 'id', 'ID');
      const body = {
        upstream_id: Number(field(f, 'upstream_id', 'UpstreamID')) || 0,
        endpoint: field(f, 'endpoint', 'Endpoint', 'Kind') || 'messages',
        url_mode: field(f, 'url_mode', 'URLMode') || 'canonical',
        url_override: field(f, 'url_override', 'URLOverride') || '',
        fixed_query_template: field(f, 'fixed_query_template', 'FixedQueryTemplate') || '',
        auth_profile: field(f, 'auth_profile', 'AuthProfile') || {},
        expected_revision: Number(field(f, 'revision', 'Revision')) || 0,
      };
      const { ok } = await this.run(async () => {
        if (id) {
          await api.put('/upstream-endpoints/' + id, body);
        } else {
          await api.post('/upstream-endpoints', body);
        }
      }, id ? '已更新 Endpoint' : '已创建 Endpoint');
      if (ok) {
        this.endpointForm = null;
        await this.loadEndpoints(true);
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
