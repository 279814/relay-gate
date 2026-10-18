/* credentials.mjs — P2 credential view/rotate/grace/audit (§12.4–12.7).
 * Pure text (x-text). Does not modify dirty app.js.
 */

const initialState = () => ({
  status: null,
  master_key: '',
  relay_key: '',
  admin_password: '',
  password: '',
  new_master: '',
  loading: false,
  rotating_master: false,
});

export function createCredentialsFeature(shell, api) {
  shell.credentials = initialState();
  let action = {};
  let statusRequest = {};
  let revealTimer = null;
  let graceTimer = null;

  function beginAction(receiver) {
    clearTimeout(revealTimer);
    revealTimer = null;
    receiver.credentials.master_key = '';
    receiver.credentials.loading = false;
    statusRequest = {};
    action = {};
    return action;
  }

  function updateGrace(receiver, state, seconds) {
    clearTimeout(graceTimer);
    graceTimer = null;
    if (!state.status) state.status = {};
    const status = state.status;
    const valid = typeof seconds === 'number' && Number.isFinite(seconds) && seconds > 0;
    const deadline = Date.now() + (valid ? seconds * 1000 : 0);
    let timer = null;
    const tick = () => {
      if (receiver.credentials !== state || state.status !== status || graceTimer !== timer) return;
      const remaining = Math.max(0, deadline - Date.now());
      status.relay_grace_seconds_left = Math.ceil(remaining / 1000);
      if (remaining > 0) {
        timer = setTimeout(tick, Math.min(1000, remaining));
        graceTimer = timer;
      } else {
        graceTimer = null;
      }
    };
    tick();
  }

  shell.loadCredentials = async function loadCredentials() {
    const state = this.credentials;
    const request = {};
    statusRequest = request;
    const current = () => this.credentials === state && statusRequest === request;
    try {
      state.loading = true;
      const status = await api.get('/credentials');
      if (!current()) return;
      state.status = status;
      updateGrace(this, state, status?.relay_grace_seconds_left);
    } catch (e) {
      if (!current()) return;
      this.err = e && e.message ? e.message : String(e);
    } finally {
      if (current()) state.loading = false;
    }
  };

  shell.revealMasterKey = async function revealMasterKey() {
    const state = this.credentials;
    if (state.rotating_master || this.displayState === 'maintenance') {
      this.err = '维护或轮换中暂不可查看 Master Key';
      return;
    }
    const request = beginAction(this);
    const current = () => this.credentials === state && action === request;
    try {
      const data = await api.post('/credentials/reveal-master', {
        password: state.password,
      });
      if (!current()) return;
      if (typeof data.ttl_sec !== 'number' || !Number.isFinite(data.ttl_sec) ||
          data.ttl_sec <= 0 || data.ttl_sec * 1000 > 2147483647) {
        throw new Error('Master Key 显示时限无效，请重新查看');
      }
      state.master_key = data.master_key || '';
      const timer = setTimeout(() => {
        if (!current() || revealTimer !== timer) return;
        revealTimer = null;
        state.master_key = '';
      }, data.ttl_sec * 1000);
      revealTimer = timer;
      this.msg = 'Master Key 已短时显示（' + data.ttl_sec + 's）';
      await this.loadCredentials();
    } catch (e) {
      if (!current()) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.rotateRelayKey = async function rotateRelayKey() {
    const state = this.credentials;
    if (this.displayState === 'maintenance') {
      this.err = '维护中禁止凭据轮换';
      return;
    }
    const request = beginAction(this);
    const current = () => this.credentials === state && action === request;
    state.relay_key = '';
    try {
      const data = await api.post('/credentials/rotate-relay', {
        password: state.password,
      });
      if (!current()) return;
      state.relay_key = data.relay_key || '';
      updateGrace(this, state, data.grace_seconds);
      this.msg = 'Relay Key 已轮换；grace=' + (data.grace_seconds || 0) + 's';
      await this.loadCredentials();
    } catch (e) {
      if (!current()) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.revokeRelayGrace = async function revokeRelayGrace() {
    const state = this.credentials;
    const request = beginAction(this);
    const current = () => this.credentials === state && action === request;
    try {
      await api.post('/credentials/revoke-relay-grace', {
        password: state.password,
      });
      if (!current()) return;
      updateGrace(this, state, 0);
      this.msg = '旧 Relay Key grace 已撤销';
      await this.loadCredentials();
    } catch (e) {
      if (!current()) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.resetAdminPassword = async function resetAdminPassword() {
    const state = this.credentials;
    const request = beginAction(this);
    const current = () => this.credentials === state && action === request;
    try {
      const data = await api.post('/credentials/reset-admin', {
        password: state.password,
      });
      if (!current()) return;
      this.credentials.admin_password = data.admin_password || '';
      this.credentials.password = data.admin_password || '';
      this.msg = '管理员密码已重置（仅此一次明文）';
      await this.loadCredentials();
    } catch (e) {
      if (!current()) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.rotateMasterKey = async function rotateMasterKey() {
    const state = this.credentials;
    if (this.displayState === 'maintenance') {
      this.err = '维护中禁止重复触发 Master Key 轮换';
      return;
    }
    if (!this.canRotateMasterKey()) {
      this.err = this.credentials.status?.blocked_reason || '请先刷新凭据状态，确认轮换条件';
      return;
    }
    const request = beginAction(this);
    const current = () => this.credentials === state && action === request;
    state.rotating_master = true;
    try {
      const data = await api.post('/credentials/rotate-master', {
        password: state.password,
        new_master: state.new_master,
      });
      if (!current()) return;
      this.msg = 'Master Key 已轮换至 ' + (data.new_key_id || '') + '（' + (data.phase || '') + '）';
      this.credentials.new_master = '';
      this.credentials.master_key = '';
      await this.loadCredentials();
      if (!current()) return;
      try {
        const st = await api.get('/state');
        if (!current()) return;
        if (typeof this.applyStatePayload === 'function') this.applyStatePayload(st);
      } catch { /* */ }
    } catch (e) {
      if (!current()) return;
      this.err = e && e.message ? e.message : String(e);
      try {
        const st = await api.get('/state');
        if (!current()) return;
        if (typeof this.applyStatePayload === 'function') this.applyStatePayload(st);
      } catch { /* */ }
    } finally {
      if (this.credentials === state) state.rotating_master = false;
    }
  };

  shell.canRotateMasterKey = function canRotateMasterKey() {
    return this.displayState !== 'maintenance' && !this.credentials.loading &&
      !this.credentials.rotating_master &&
      this.credentials.status?.rotation_allowed === true;
  };
  const originalReset = shell.reset;
  shell.reset = function resetCredentials() {
    beginAction(this);
    clearTimeout(graceTimer);
    graceTimer = null;
    this.credentials = initialState();
    return originalReset?.call(this);
  };
}

export function mergeCredentialsTab(shell) {
  if (!Array.isArray(shell.tabs)) return;
  if (shell.tabs.some((t) => t && t.id === 'credentials')) return;
  const settingsIdx = shell.tabs.findIndex((t) => t && t.id === 'settings');
  const tab = { id: 'credentials', name: '凭据' };
  if (settingsIdx >= 0) shell.tabs.splice(settingsIdx, 0, tab);
  else shell.tabs.push(tab);
}
