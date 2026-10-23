const ENDPOINTS = ['models', 'messages', 'responses', 'chat_completions', 'count_tokens'];
const TRIGGERS = ['scheduled', 'manual', 'recovery', 'calibration', 'real_traffic'];
const ORIGINS = ['manual', 'learned', 'compact_native', 'calibration_native', 'basic_protocol', 'legacy_migration'];
const IDENTITY_FIELDS = [
  { key: 'storage', label: '存储身份', options: ['db', 'profile', 'embedded'] },
  { key: 'recipe_id', label: 'Recipe ID', type: 'number' },
  { key: 'version_id', label: 'DB 版本 ID', type: 'number' },
  { key: 'profile_id', label: 'Profile ID', type: 'number' },
  { key: 'template_id', label: 'Builtin key' },
  { key: 'identity_revision', label: 'Profile/Builtin 修订', type: 'number' },
];

function initialStatistics() {
  const end = new Date();
  const start = new Date(end);
  start.setUTCDate(start.getUTCDate() - 6);
  return {
    basis: 'executions', scope: 'route', limit: 50,
    filter: { day_from: start.toISOString().slice(0, 10), day_to: end.toISOString().slice(0, 10),
      endpoint: '', trigger: '', origin: '', route_id: '', upstream_id: '', canary_source: '',
      ...Object.fromEntries(IDENTITY_FIELDS.map(field => [field.key, ''])) },
    items: [], total_rows: 0, next_cursor: '', previous_cursor: '',
    loading: false, error: '', coverage: null, request: 0,
  };
}

export function createProbeStatisticsFeature(shell, api) {
  Object.assign(shell, {
    probeStatistics: initialStatistics(),

    statisticsFilterFields() {
      const basis = this.probeStatistics.basis;
      const canary = basis === 'canary';
      return [
        { key: 'day_from', label: 'UTC 起始日', type: 'date' },
        { key: 'day_to', label: 'UTC 截止日', type: 'date' },
        { key: 'upstream_id', label: 'Upstream ID', type: 'number' },
        { key: 'route_id', label: 'Route ID', type: 'number' },
        { key: 'endpoint', label: '端点', options: canary ? ENDPOINTS.filter(value => !['models', 'count_tokens'].includes(value)) : ENDPOINTS },
        { key: 'trigger', label: '触发来源', options: canary ? ['manual', 'scheduled'] : basis === 'daily' ? TRIGGERS.filter(value => value !== 'real_traffic') : TRIGGERS },
        ...(canary ? [{ key: 'canary_source', label: 'Canary 来源', options: ['manual', 'periodic'] }] : [{ key: 'origin', label: '配方来源', options: ORIGINS }]),
        ...(basis === 'executions' ? IDENTITY_FIELDS : []),
      ];
    },

    onStatisticsFilterChange() {
      const state = this.probeStatistics;
      state.request++;
      state.items = []; state.total_rows = 0;
      state.next_cursor = ''; state.previous_cursor = '';
      state.loading = false; state.error = ''; state.coverage = null;
      if (state.basis !== 'executions') {
        for (const field of IDENTITY_FIELDS) state.filter[field.key] = '';
        if (state.filter.trigger === 'real_traffic') state.filter.trigger = '';
      }
      if (state.basis === 'canary') {
        state.filter.origin = '';
        if (!['manual', 'scheduled'].includes(state.filter.trigger)) state.filter.trigger = '';
        if (['models', 'count_tokens'].includes(state.filter.endpoint)) state.filter.endpoint = '';
      } else { state.filter.canary_source = ''; }
    },

    async loadProbeStatistics(direction = 'first') {
      if (this.authed === false) return false;
      const state = this.probeStatistics;
      const cursor = direction === 'next' ? state.next_cursor : direction === 'previous' ? state.previous_cursor : '';
      if (direction !== 'first' && !cursor) return false;
      const request = ++state.request;
      const signature = () => JSON.stringify([state.basis, state.scope, state.limit, state.filter]);
      const requestedFilter = signature();
      state.loading = true; state.error = '';
      if (direction === 'first') { state.items = []; state.next_cursor = ''; state.previous_cursor = ''; }
      const ownsRequest = () => this.probeStatistics === state && state.request === request && this.authed !== false;
      const current = () => ownsRequest() && signature() === requestedFilter;
      try {
        const query = new URLSearchParams({ basis: state.basis, scope: state.scope, limit: String(state.limit) });
        if (cursor) query.set('cursor', cursor);
        for (const [key, value] of Object.entries(state.filter)) if (value !== '' && value != null) query.set(key, String(value));
        const page = await api.get('/probe-statistics?' + query);
        if (!current()) return false;
        // Each response replaces the visible page. No client loop or growing
        // list fetches the retained execution/cost history into the browser.
        state.items = page.items || [];
        state.total_rows = page.total_rows ?? 0;
        state.next_cursor = page.next_cursor || '';
        state.previous_cursor = page.previous_cursor || '';
        state.coverage = page.coverage || null;
        return true;
      } catch (error) {
        if (current()) state.error = error.message || '统计读取失败';
        return false;
      } finally { if (ownsRequest()) state.loading = false; }
    },

    statisticsNumber(value) { return value == null ? 'unknown' : Number(value).toLocaleString('zh-CN'); },
    statisticsRateText(value) { return value == null ? 'unknown' : (Number(value) * 100).toFixed(1) + '%'; },
    statisticsTokenText(value, unknownRows) {
      if (value == null) return 'unknown';
      if (unknownRows == null) return this.statisticsNumber(value) + '（覆盖 unknown）';
      return this.statisticsNumber(value) + (unknownRows > 0 ? `（另 ${this.statisticsNumber(unknownRows)} 次 unknown）` : '');
    },
    statisticsTriggerText(value, canarySource) {
      if (canarySource === 'manual') return 'Canary · 手动';
      if (canarySource === 'periodic') return 'Canary · 周期';
      return ({ scheduled: '周期', manual: '手动（canary 未区分）', recovery: '恢复', calibration: '校准', real_traffic: '真实流量观察' })[value] || 'unknown';
    },
    statisticsRecipeText(row) {
      if (this.probeStatistics.basis === 'canary') return 'Canary 诊断（独立成本，非 Recipe）';
      if (this.probeStatistics.basis === 'daily') return '未记录 Recipe 身份';
      if (row.binding_use === 'real_traffic_context') return '真实流量上下文（非 Recipe 执行）';
      const legacy = row.origin === 'legacy_migration' ? ' · legacy' : '';
      if (row.storage === 'db') return `Recipe #${row.recipe_id} · 版本 ID #${row.version_id}${legacy}`;
      if (row.storage === 'profile') return `Profile #${row.profile_id} · 修订 ${row.identity_revision}${legacy}`;
      if (row.storage === 'embedded') return `${row.template_id || 'unknown'} · 修订 ${row.identity_revision}${legacy}`;
      return 'legacy/unknown';
    },
    statisticsRowKey(row) {
      return JSON.stringify([row.day_utc, row.scope_id, row.upstream_id, row.endpoint, row.trigger, row.origin,
        row.binding_use, row.storage, row.recipe_id, row.version_id, row.profile_id, row.template_id, row.identity_revision]);
    },
  });
  const originalReset = shell.reset;
  shell.reset = function resetProbeStatistics() {
    this.probeStatistics = initialStatistics();
    return originalReset?.call(this);
  };
  return shell;
}
