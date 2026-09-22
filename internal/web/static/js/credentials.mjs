/* credentials.mjs — P2 credential view/rotate/grace/audit (§12.4–12.7).
 * Pure text (x-text). Does not modify dirty app.js.
 */

export function createCredentialsFeature(shell, api) {
  shell.credentials = {
    status: null,
    master_key: '',
    relay_key: '',
    admin_password: '',
    password: '',
    new_master: '',
    loading: false,
  };

  shell.loadCredentials = async function loadCredentials() {
    try {
      this.credentials.loading = true;
      this.credentials.status = await api.get('/credentials');
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    } finally {
      this.credentials.loading = false;
    }
  };

  shell.revealMasterKey = async function revealMasterKey() {
    try {
      const data = await api.post('/credentials/reveal-master', {
        password: this.credentials.password,
      });
      this.credentials.master_key = data.master_key || '';
      this.msg = 'Master Key 已短时显示（' + (data.ttl_sec || 30) + 's）';
      await this.loadCredentials();
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.rotateRelayKey = async function rotateRelayKey() {
    try {
      const data = await api.post('/credentials/rotate-relay', {
        password: this.credentials.password,
      });
      this.credentials.relay_key = data.relay_key || '';
      this.msg = 'Relay Key 已轮换；grace=' + (data.grace_seconds || 0) + 's';
      await this.loadCredentials();
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.revokeRelayGrace = async function revokeRelayGrace() {
    try {
      await api.post('/credentials/revoke-relay-grace', {
        password: this.credentials.password,
      });
      this.msg = '旧 Relay Key grace 已撤销';
      await this.loadCredentials();
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.resetAdminPassword = async function resetAdminPassword() {
    try {
      const data = await api.post('/credentials/reset-admin', {
        password: this.credentials.password,
      });
      this.credentials.admin_password = data.admin_password || '';
      this.credentials.password = data.admin_password || '';
      this.msg = '管理员密码已重置（仅此一次明文）';
      await this.loadCredentials();
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.rotateMasterKey = async function rotateMasterKey() {
    try {
      const data = await api.post('/credentials/rotate-master', {
        password: this.credentials.password,
        new_master: this.credentials.new_master,
      });
      this.msg = 'Master Key 已轮换至 ' + (data.new_key_id || '') + '（' + (data.phase || '') + '）';
      this.credentials.new_master = '';
      this.credentials.master_key = '';
      await this.loadCredentials();
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
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
