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
});

export function createCredentialsFeature(shell, api) {
  shell.credentials = initialState();

  shell.loadCredentials = async function loadCredentials() {
    const state = this.credentials;
    try {
      state.loading = true;
      const status = await api.get('/credentials');
      if (this.credentials !== state) return;
      state.status = status;
    } catch (e) {
      if (this.credentials !== state) return;
      this.err = e && e.message ? e.message : String(e);
    } finally {
      state.loading = false;
    }
  };

  shell.revealMasterKey = async function revealMasterKey() {
    const state = this.credentials;
    try {
      const data = await api.post('/credentials/reveal-master', {
        password: this.credentials.password,
      });
      if (this.credentials !== state) return;
      this.credentials.master_key = data.master_key || '';
      this.msg = 'Master Key 已短时显示（' + (data.ttl_sec || 30) + 's）';
      await this.loadCredentials();
    } catch (e) {
      if (this.credentials !== state) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.rotateRelayKey = async function rotateRelayKey() {
    const state = this.credentials;
    if (this.displayState === 'maintenance') {
      this.err = '维护中禁止凭据轮换';
      return;
    }
    try {
      const data = await api.post('/credentials/rotate-relay', {
        password: this.credentials.password,
      });
      if (this.credentials !== state) return;
      this.credentials.relay_key = data.relay_key || '';
      this.msg = 'Relay Key 已轮换；grace=' + (data.grace_seconds || 0) + 's';
      await this.loadCredentials();
    } catch (e) {
      if (this.credentials !== state) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.revokeRelayGrace = async function revokeRelayGrace() {
    const state = this.credentials;
    try {
      await api.post('/credentials/revoke-relay-grace', {
        password: this.credentials.password,
      });
      if (this.credentials !== state) return;
      this.msg = '旧 Relay Key grace 已撤销';
      await this.loadCredentials();
    } catch (e) {
      if (this.credentials !== state) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.resetAdminPassword = async function resetAdminPassword() {
    const state = this.credentials;
    try {
      const data = await api.post('/credentials/reset-admin', {
        password: this.credentials.password,
      });
      if (this.credentials !== state) return;
      this.credentials.admin_password = data.admin_password || '';
      this.credentials.password = data.admin_password || '';
      this.msg = '管理员密码已重置（仅此一次明文）';
      await this.loadCredentials();
    } catch (e) {
      if (this.credentials !== state) return;
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
    try {
      const data = await api.post('/credentials/rotate-master', {
        password: this.credentials.password,
        new_master: this.credentials.new_master,
      });
      if (this.credentials !== state) return;
      this.msg = 'Master Key 已轮换至 ' + (data.new_key_id || '') + '（' + (data.phase || '') + '）';
      this.credentials.new_master = '';
      this.credentials.master_key = '';
      await this.loadCredentials();
      if (this.credentials !== state) return;
      try {
        const st = await api.get('/state');
        if (this.credentials !== state) return;
        if (typeof this.applyStatePayload === 'function') this.applyStatePayload(st);
      } catch { /* */ }
    } catch (e) {
      if (this.credentials !== state) return;
      this.err = e && e.message ? e.message : String(e);
      try {
        const st = await api.get('/state');
        if (this.credentials !== state) return;
        if (typeof this.applyStatePayload === 'function') this.applyStatePayload(st);
      } catch { /* */ }
    }
  };

  shell.canRotateMasterKey = function canRotateMasterKey() {
    return this.displayState !== 'maintenance' && !this.credentials.loading &&
      this.credentials.status?.rotation_allowed === true;
  };
  const originalReset = shell.reset;
  shell.reset = function resetCredentials() {
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
