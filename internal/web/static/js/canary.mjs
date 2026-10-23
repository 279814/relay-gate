const initialCanary = () => ({
  running: false, runRequest: 0, result: null, runError: '',
  upstreamId: '', policy: null, draft: { route_id: '', enabled: false, interval_sec: 3600 },
  loading: false, saving: false, policyRequest: 0, policyError: '', conflict: false,
});
const positiveID = value => Number.isSafeInteger(Number(value)) && Number(value) > 0;

export function createCanaryFeature(shell, api) {
  shell.canary = initialCanary();
  Object.assign(shell, {
    onCanaryRouteChange() {
      const state = this.canary;
      state.runRequest++; state.running = false; state.result = null; state.runError = '';
    },
    onCanaryUpstreamChange() {
      const state = this.canary;
      state.policyRequest++; state.loading = false; state.saving = false;
      state.policy = null; state.conflict = false; state.policyError = '';
      state.draft = { route_id: '', enabled: false, interval_sec: 3600 };
    },
    async runSecurityCanary() {
      const state = this.canary;
      if (this.authed === false || state.running) return false;
      const route = String(this.security.canaryRouteId);
      if (!positiveID(route)) { state.runError = '请填写正数 Route ID'; return false; }
      const request = ++state.runRequest;
      state.running = true; state.result = null; state.runError = '';
      const owns = () => this.canary === state && state.runRequest === request && this.authed !== false;
      const current = () => owns() && String(this.security.canaryRouteId) === route;
      try {
        const data = await api.post('/security/canary', { route_id: Number(route) });
        if (!current()) return false;
        if (!data?.execution_id || data.canary?.execution_id !== data.execution_id) throw new Error('未返回已持久保存的 Canary 结果');
        state.result = data;
        this.msg = 'Canary ' + this.canaryVerdictText(data.canary.verdict) + ' · ' + data.execution_id;
        await this.loadSecurityFindings();
        return true;
      } catch (error) {
        if (current()) state.runError = error.message || 'Canary 执行失败';
        return false;
      } finally { if (owns()) state.running = false; }
    },
    async loadCanaryPolicy() {
      const state = this.canary;
      if (this.authed === false || state.loading || state.saving) return false;
      const upstream = String(state.upstreamId);
      if (!positiveID(upstream)) { state.policyError = '请填写正数 Upstream ID'; return false; }
      const request = ++state.policyRequest;
      state.loading = true; state.policyError = '';
      const owns = () => this.canary === state && state.policyRequest === request && this.authed !== false;
      const current = () => owns() && String(state.upstreamId) === upstream;
      try {
        const data = await api.get('/security/canary-policy/' + Number(upstream));
        if (!current()) return false;
        state.policy = data; state.conflict = false;
        state.draft = { route_id: data.route_id || '', enabled: data.enabled === true, interval_sec: data.interval_sec };
        return true;
      } catch (error) {
        if (current()) state.policyError = error.message || 'Canary 策略读取失败';
        return false;
      } finally { if (owns()) state.loading = false; }
    },
    async saveCanaryPolicy() {
      const state = this.canary;
      if (this.authed === false || state.loading || state.saving || state.conflict || !state.policy) return false;
      const upstream = String(state.upstreamId);
      const interval = Number(state.draft.interval_sec);
      if (state.policy.upstream_id !== Number(upstream)) {
        state.policyError = '目标已改变，请重新载入该 Upstream 的策略'; return false;
      }
      if (!positiveID(upstream) || !positiveID(state.draft.route_id) || !Number.isInteger(interval) || interval < 300 || interval > 86400) {
        state.policyError = '请填写有效 Route ID 和 300–86400 秒周期'; return false;
      }
      const revision = state.policy.revision;
      if (!Number.isSafeInteger(revision) || revision < 0) { state.policyError = '当前策略 revision 不可用，请重新载入'; return false; }
      const request = ++state.policyRequest;
      const draft = JSON.stringify(state.draft);
      const body = { route_id: Number(state.draft.route_id), enabled: state.draft.enabled === true, interval_sec: interval, revision };
      state.saving = true; state.policyError = '';
      const owns = () => this.canary === state && state.policyRequest === request && this.authed !== false;
      const current = () => owns() && String(state.upstreamId) === upstream;
      try {
        const data = await api.put('/security/canary-policy/' + Number(upstream), body);
        if (!current()) return false;
        state.policy = data; state.conflict = false;
        if (JSON.stringify(state.draft) === draft) state.draft = { route_id: data.route_id, enabled: data.enabled === true, interval_sec: data.interval_sec };
        this.msg = 'Canary 周期策略已保存';
        return true;
      } catch (error) {
        if (current()) {
          state.policyError = error.message || 'Canary 策略保存失败';
          if (error.status === 409) state.conflict = true;
        }
        return false;
      } finally { if (owns()) state.saving = false; }
    },
    canaryFlagText(value) { return value === true ? '匹配' : value === false ? '不匹配' : 'unknown'; },
    canaryVerdictText(value) {
      return ({ passed: '通过', violation: '约束违例', incomplete: '观测不完整', canceled: '已取消', execution_failed: '执行失败', not_sent: '未发送' })[value] || 'unknown';
    },
    viewCanaryCosts() {
      if (!this.probeStatistics) return;
      this.probeStatistics.basis = 'canary';
      this.probeStatistics.filter.route_id = ''; this.probeStatistics.filter.upstream_id = '';
      this.onStatisticsFilterChange();
      this.go('probe-statistics');
    },
  });
  const originalReset = shell.reset;
  shell.reset = function resetCanary() {
    this.canary = initialCanary();
    return originalReset?.call(this);
  };
}

