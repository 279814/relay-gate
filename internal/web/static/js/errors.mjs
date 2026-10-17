/* errors.mjs — P2 recent-errors home strip + modal (§13.2).
 * Pure text only (x-text). Does not modify dirty app.js.
 */

const initialState = () => ({
  failed_count: 0,
  latest: null,
  logs: [],
  open: false,
  upstream_id: '',
  loading: false,
});

export function createRecentErrorsFeature(shell, api) {
  shell.recentErrors = initialState();

  shell.refreshRecentErrors = async function refreshRecentErrors() {
    const state = this.recentErrors;
    try {
      const q = new URLSearchParams({ limit: '20' });
      if (this.recentErrors.upstream_id) {
        q.set('upstream_id', String(this.recentErrors.upstream_id));
      }
      const data = await api.get('/recent-errors?' + q.toString());
      if (this.recentErrors !== state) return;
      this.recentErrors.failed_count = data.failed_count || 0;
      this.recentErrors.latest = data.latest || null;
      this.recentErrors.logs = Array.isArray(data.logs) ? data.logs : [];
    } catch (e) {
      /* home strip is best-effort */
    }
  };

  shell.openRecentErrors = async function openRecentErrors() {
    this.recentErrors.open = true;
    await this.refreshRecentErrors();
  };

  shell.closeRecentErrors = function closeRecentErrors() {
    this.recentErrors.open = false;
  };

  shell.copyRecentError = async function copyRecentError(text) {
    const state = this.recentErrors;
    const value = text == null ? '' : String(text);
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(value);
        if (this.recentErrors !== state) return;
        this.msg = '已复制错误原文';
      }
    } catch {
      if (this.recentErrors !== state) return;
      this.err = '复制失败';
    }
  };

  shell.loadMoreRecentErrors = async function loadMoreRecentErrors() {
    const state = this.recentErrors;
    const logs = this.recentErrors.logs || [];
    if (!logs.length) return;
    const last = logs[logs.length - 1];
    const q = new URLSearchParams({
      limit: '20',
      before_id: String(last.id),
    });
    if (this.recentErrors.upstream_id) {
      q.set('upstream_id', String(this.recentErrors.upstream_id));
    }
    try {
      const data = await api.get('/recent-errors?' + q.toString());
      if (this.recentErrors !== state) return;
      const more = Array.isArray(data.logs) ? data.logs : [];
      this.recentErrors.logs = logs.concat(more);
      this.recentErrors.failed_count = data.failed_count || this.recentErrors.failed_count;
    } catch (e) {
      if (this.recentErrors !== state) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };
  const originalReset = shell.reset;
  shell.reset = function resetErrors() {
    this.recentErrors = initialState();
    return originalReset?.call(this);
  };
}
