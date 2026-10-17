/* runtime.mjs — service gate UI helpers (§13.5 maintenance / warmup).
 * Pure text bindings. Assembled by boot.mjs and bindings.check.js.
 */

export function createRuntimeStateFeature(shell) {
  // Reset replaces this request owner, including logout followed by a new
  // login before an older request finishes. It is local to this feature.
  let owner = {};
  shell.displayState = shell.displayState || 'running';
  shell.maintenanceReason = shell.maintenanceReason || '';
  shell.warmup = shell.warmup || null;
  if (typeof shell.stateRevision !== 'number') shell.stateRevision = 0;
  shell.stateBlocked = false;
  shell.stateBusy = false;

  shell.applyStatePayload = function applyStatePayload(st, { explicit = false } = {}) {
    if (this.authed === false) return false;
    if (!st || !Number.isSafeInteger(st.revision) || st.revision < 1) return false;
    if (!explicit && (this.stateBlocked || this.stateBusy)) return false;
    if (!explicit && st.revision < this.stateRevision) return false;
    this.stateRevision = st.revision;
    this.running = st.state === 'running';
    this.displayState = st.effective || st.state || (this.running ? 'running' : 'paused');
    this.maintenanceReason = st.maintenance_reason || '';
    this.warmup = st.warmup || null;
    if (explicit) this.stateBlocked = false;
    return true;
  };

  shell.refreshState = async function refreshState() {
    if (this.stateBusy || this.stateBlocked) return false;
    const requestOwner = owner;
    try {
      const state = await this.api('GET', '/state');
      if (owner !== requestOwner || this.authed === false) return false;
      return this.applyStatePayload(state);
    } catch { return false; }
  };

  shell.reloadState = async function reloadState() {
    if (this.stateBusy) return false;
    const requestOwner = owner;
    this.stateBusy = true;
    try {
      const state = await this.api('GET', '/state');
      if (owner !== requestOwner || this.authed === false) return false;
      if (!this.applyStatePayload(state, {explicit:true})) throw new Error('服务状态缺少有效版本');
      this.err = ''; this.msg = '已重新读取服务状态，请确认后操作';
      return true;
    } catch (error) {
      if (owner === requestOwner && this.authed !== false) this.err = error.message;
      return false;
    } finally { if (owner === requestOwner) this.stateBusy = false; }
  };

  shell.toggleState = async function toggleState() {
    if (this.stateBusy || this.stateBlocked || this.stateRevision < 1) return false;
    if (this.displayState === 'maintenance') { this.err = '维护中不可切换启停'; return false; }
    const next = this.running ? 'paused' : 'running';
    const requestOwner = owner;
    this.stateBusy = true; this.err = ''; this.msg = '';
    try {
      const state = await this.api('POST', '/state', {state:next, expected_revision:this.stateRevision});
      if (owner !== requestOwner || this.authed === false) return false;
      if (!this.applyStatePayload(state, {explicit:true})) throw new Error('状态已提交，请重新加载确认版本');
      this.msg = next === 'paused' ? '已暂停：停止新请求与合成探活，真实在途请求继续完成' : '已恢复：渐进复核 Active 路由，Lazy 路由按需触发；负状态保留';
      this.loadHealth?.();
      return true;
    } catch (error) {
      if (owner !== requestOwner || this.authed === false) return false;
      if (error.status === 409) {
        this.stateBlocked = true;
        this.err = '服务状态版本已变化，请显式重新加载服务状态后确认操作';
      } else if (error.status === 503) {
        this.stateBlocked = true;
        this.err = error.data?.persisted === true ? '服务状态已保存，转换尚未完成；请重新加载服务状态后确认' : '服务状态暂不可用，请重新加载服务状态后确认';
      } else { this.err = error.message; }
      return false;
    } finally { if (owner === requestOwner) this.stateBusy = false; }
  };

  const originalReset = shell.reset;
  shell.reset = function resetRuntimeState() {
    owner = {};
    originalReset?.call(this);
    this.stateRevision = 0; this.stateBlocked = false; this.stateBusy = false;
    this.running = false; this.displayState = 'paused'; this.maintenanceReason = ''; this.warmup = null;
  };

  shell.stateLabel = function stateLabel() {
    if (this.displayState === 'maintenance') return '维护中';
    return this.running ? '运行中' : '已暂停';
  };

  shell.stateTagClass = function stateTagClass() {
    if (this.displayState === 'maintenance') return 'warn';
    return this.running ? 'ok' : 'warn';
  };

  shell.warmupNote = function warmupNote() {
    const w = this.warmup;
    if (!w || !w.active || this.displayState !== 'running') return '';
    return '暖机中：' + (w.pending || 0) + '/' + (w.total || 0) + ' Route 待复核（负状态已保留）';
  };
}
