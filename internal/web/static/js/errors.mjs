/* errors.mjs — P2 recent-errors home strip + modal (§13.2).
 * Pure text only (x-text). Does not modify dirty app.js.
 */

export function createRecentErrorsFeature(shell, api) {
  shell.recentErrors = {
    failed_count: 0,
    latest: null,
    logs: [],
    open: false,
    upstream_id: '',
    loading: false,
  };

  shell.refreshRecentErrors = async function refreshRecentErrors() {
    try {
      const q = new URLSearchParams({ limit: '20' });
      if (this.recentErrors.upstream_id) {
        q.set('upstream_id', String(this.recentErrors.upstream_id));
      }
      const data = await api.get('/recent-errors?' + q.toString());
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
    const value = text == null ? '' : String(text);
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(value);
        this.msg = '已复制错误原文';
      }
    } catch {
      this.err = '复制失败';
    }
  };

  shell.loadMoreRecentErrors = async function loadMoreRecentErrors() {
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
      const more = Array.isArray(data.logs) ? data.logs : [];
      this.recentErrors.logs = logs.concat(more);
      this.recentErrors.failed_count = data.failed_count || this.recentErrors.failed_count;
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
  };
}
