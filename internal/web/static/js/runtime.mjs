/* runtime.mjs — service gate UI helpers (§13.5 maintenance / warmup).
 * Pure text bindings. Assembled by boot.mjs and bindings.check.js.
 */

export function createRuntimeStateFeature(shell) {
  shell.displayState = shell.displayState || 'running';
  shell.maintenanceReason = shell.maintenanceReason || '';
  shell.warmup = shell.warmup || null;
  if (typeof shell.stateRevision !== 'number') shell.stateRevision = 0;

  shell.applyStatePayload = function applyStatePayload(st) {
    if (!st) return;
    this.stateRevision = st.revision || 0;
    this.running = st.state === 'running';
    this.displayState = st.effective || st.state || (this.running ? 'running' : 'paused');
    this.maintenanceReason = st.maintenance_reason || '';
    this.warmup = st.warmup || null;
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
