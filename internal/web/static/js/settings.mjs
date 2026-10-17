/* Settings editing keeps the exact revision shown with the user's draft. */
const clone = value => JSON.parse(JSON.stringify(value));
const emptyState = () => ({ revision: 0, original: null, busy: false, loading: false, conflict: false, pending: false, persistedRevision: 0 });

export function createSettingsFeature(shell, api) {
  shell.settingsState = emptyState();

  shell.settingsDirty = function settingsDirty() {
    return this.settings !== null && JSON.stringify(this.settings) !== JSON.stringify(this.settingsState.original);
  };

  shell.loadSettings = async function loadSettings({ discard = false } = {}) {
    const state = this.settingsState;
    if (state.busy || state.loading || (!discard && (state.conflict || state.pending || this.settingsDirty()))) return false;
    state.loading = true;
    try {
      const data = await api.get('/settings');
      if (this.settingsState !== state || this.authed === false || (!discard && this.settingsDirty())) return false;
      if (!data || !data.settings || !Number.isSafeInteger(data.revision) || data.revision < 1) throw new Error('设置响应缺少有效版本，请刷新页面');
      this.settings = clone(data.settings);
      this.limits = data.limits || {};
      this.settingsState = { ...emptyState(), revision: data.revision, original: clone(data.settings) };
      return true;
    } catch (error) {
      if (this.settingsState !== state || this.authed === false) return false;
      this.err = error.message || String(error);
      return false;
    } finally {
      state.loading = false;
    }
  };

  shell.reloadSettings = async function reloadSettings() {
    if (this.settingsState.busy || this.settingsState.loading) return false;
    if (this.settingsDirty() && !globalThis.confirm('重新加载会替换当前草稿。确认已复制需要保留的修改？')) return false;
    const loaded = await this.loadSettings({ discard: true });
    if (loaded) { this.err = ''; this.msg = '已重新读取保存的设置版本'; }
    return loaded;
  };

  shell.saveSettings = async function saveSettings() {
    const state = this.settingsState;
    if (!this.settings || state.revision < 1 || state.busy || state.loading || state.conflict || state.pending) return false;
    const submitted = clone(this.settings);
    // Partial PUT also preserves unchanged large integer settings that a JS
    // client cannot exactly represent. Never resend metadata or a newer revision.
    const patch = {};
    for (const [key, value] of Object.entries(submitted)) {
      if (JSON.stringify(value) !== JSON.stringify(state.original?.[key])) patch[key] = value;
    }
    state.busy = true;
    this.err = '';
    this.msg = '';
    try {
      const data = await api.put('/settings', { ...patch, expected_revision: state.revision });
      if (this.settingsState !== state || this.authed === false) return false;
      if (!data || !data.settings || !Number.isSafeInteger(data.revision) || data.revision < 1) throw new Error('设置已提交，但未取得有效版本，请重新加载确认');
      if (JSON.stringify(this.settings) === JSON.stringify(submitted)) this.settings = clone(data.settings);
      this.settingsState = { ...emptyState(), revision: data.revision, original: clone(data.settings) };
      this.msg = `已保存，当前版本 ${data.revision}`;
      return true;
    } catch (error) {
      if (this.settingsState !== state || this.authed === false) return false;
      if (error.status === 409) {
        state.conflict = true;
        this.err = '设置版本已变化，草稿已保留。请复制需要的修改，再重新加载后保存。';
      } else if (error.status === 503 && error.data?.code === 'config_activation_pending' && error.data.persisted === true) {
        state.pending = true;
        state.persistedRevision = error.data.new_revision;
        this.err = '设置已保存，激活尚未完成。草稿已保留，请重新加载确认后再操作。';
      } else {
        this.err = error.message || String(error);
      }
      return false;
    } finally {
      state.busy = false;
    }
  };

  const originalReset = shell.reset;
  shell.reset = function resetSettings() {
    if (originalReset) originalReset.call(this);
    this.settings = null;
    this.limits = {};
    this.settingsState = emptyState();
  };
  shell.settingsModuleReady = true;
}
