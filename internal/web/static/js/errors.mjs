/* Recent errors: failed metadata, bounded pages, plain text only (§13.2). */
const initialState = () => ({
  failed_count: 0, latest: null, logs: [], open: false, loading: false, next_cursor: '',
  upstream_id: '', route_id: '', protocol: '', outcome: '', from_time: '', to_time: '',
});
const filterFields = ['upstream_id', 'route_id', 'protocol', 'outcome', 'from_time', 'to_time'];
const filterIdentity = state => JSON.stringify(filterFields.map(key => state[key]));

function filterQuery(state) {
  const query = new URLSearchParams({limit: '50'});
  for (const key of ['upstream_id', 'route_id', 'protocol', 'outcome']) {
    if (state[key]) query.set(key, String(state[key]));
  }
  for (const [field, parameter] of [['from_time', 'from_ms'], ['to_time', 'to_ms']]) {
    if (!state[field]) continue;
    const ms = new Date(state[field]).getTime();
    if (!Number.isFinite(ms)) throw new Error('错误时间筛选无效');
    query.set(parameter, String(ms));
  }
  return query;
}

function selectProbeFilter(receiver, name, row) {
  const list = receiver[name];
  if (!list || !row.route_id || !row.endpoint_kind) {
    receiver.err = '此历史日志缺少 Route 或协议关联，无法定位探活记录';
    return false;
  }
  for (const key of Object.keys(list.filter)) list.filter[key] = '';
  Object.assign(list.filter, {route_id: String(row.route_id), upstream_id: String(row.upstream_id), endpoint: row.endpoint_kind});
  receiver.onProbeFilterChange(name);
  return true;
}

export function createRecentErrorsFeature(shell, api) {
  shell.recentErrors = initialState();
  let activeRead = {};
  let activeLink = {};

  async function loadPage(receiver, append) {
    const state = receiver.recentErrors;
    if (append && (state.loading || !state.next_cursor)) return;
    const request = {}; activeRead = request;
    const filter = filterIdentity(state);
    const owns = () => receiver.recentErrors === state && activeRead === request;
    const current = () => owns() && filterIdentity(state) === filter;
    state.loading = true;
    if (state.open) receiver.err = '';
    try {
      const query = filterQuery(state);
      if (append) query.set('cursor', state.next_cursor);
      const data = await api.get('/recent-errors?' + query);
      if (!current()) return;
      const logs = Array.isArray(data.logs) ? data.logs : [];
      state.logs = append ? state.logs.concat(logs) : logs;
      state.failed_count = data.failed_count ?? 0;
      state.next_cursor = data.next_cursor || '';
      if (!append) state.latest = data.latest || null;
    } catch (error) {
      if (current() && state.open) receiver.err = error.message || String(error);
    } finally {
      if (owns()) state.loading = false;
    }
  }

  // Automatic home refresh must not reset the modal's selected page.
  shell.refreshRecentErrors = async function refreshRecentErrors(force = false) {
    if (this.recentErrors.open && !force) return;
    if (force) activeLink = {};
    await loadPage(this, false);
  };
  shell.openRecentErrors = async function openRecentErrors() {
    this.recentErrors.open = true;
    await this.refreshRecentErrors(true);
  };
  shell.applyRecentErrorFilters = async function applyRecentErrorFilters() {
    this.recentErrors.logs = [];
    this.recentErrors.next_cursor = '';
    await this.refreshRecentErrors(true);
  };
  shell.closeRecentErrors = function closeRecentErrors() {
    activeRead = {}; activeLink = {};
    this.recentErrors.open = false;
    this.recentErrors.loading = false;
  };
  shell.loadMoreRecentErrors = async function loadMoreRecentErrors() {
    await loadPage(this, true);
  };

  shell.openRecentErrorCapabilities = async function openRecentErrorCapabilities(row) {
    if (!selectProbeFilter(this, 'capabilities', row)) return;
    this.closeRecentErrors(); this.tab = 'capabilities';
    for (const key of Object.keys(this.reachability.filter)) this.reachability.filter[key] = '';
    this.reachability.filter.upstream_id = String(row.upstream_id);
    this.onProbeFilterChange('reachability');
    await Promise.all([this.loadCapabilities(true), this.loadReachability(true)]);
  };
  shell.openRecentErrorExecutions = async function openRecentErrorExecutions(row) {
    if (!selectProbeFilter(this, 'executions', row)) return;
    this.closeRecentErrors(); this.tab = 'executions';
    await this.loadExecutions(true);
  };
  shell.openRecentErrorRequestLogs = async function openRecentErrorRequestLogs(row) {
    if (!row.req_id) { this.err = '历史日志未记录 ReqID'; return; }
    const state = this.recentErrors;
    const request = {}; activeLink = request;
    const current = () => this.recentErrors === state && activeLink === request;
    try {
      const query = new URLSearchParams({req_id: row.req_id, limit: '200'});
      const data = await api.get('/request-logs?' + query);
      if (!current()) return;
      this.reqLogs = Array.isArray(data.logs) ? data.logs : [];
      this.reqLogsTotal = this.reqLogs.length;
      this.retryStats = null;
      this.expandedLogs = {[row.req_id]: true};
      this.logFilter = {outcome: '', upstream_id: '', only_retried: false, only_failed: false};
      this.closeRecentErrors(); this.tab = 'reqlogs';
      this.msg = '已定位 ReqID ' + row.req_id + '（最多显示 200 次尝试；刷新将返回普通日志列表）';
    } catch (error) {
      if (current()) this.err = error.message || String(error);
    }
  };
  shell.openRecentErrorSample = async function openRecentErrorSample(row) {
    if (!Number.isSafeInteger(row.sample_id) || row.sample_id < 1) { this.err = '此请求没有留下可关联的样本'; return; }
    this.closeRecentErrors();
    await this.openSample(row.sample_id); // Existing password reauthentication, never a body GET.
  };
  shell.copyRecentError = async function copyRecentError(text) {
    const state = this.recentErrors;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text == null ? '' : String(text));
        if (this.recentErrors === state) this.msg = '已复制脱敏错误文本';
      }
    } catch {
      if (this.recentErrors === state) this.err = '复制失败';
    }
  };
  const originalReset = shell.reset;
  shell.reset = function resetErrors() {
    activeRead = {}; activeLink = {};
    this.recentErrors = initialState();
    return originalReset?.call(this);
  };
}
