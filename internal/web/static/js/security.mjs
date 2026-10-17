/* security.mjs — P3 Security Center UI (§14.5). Pure text (x-text). */

const initialState = () => ({
  findings: [],
  total: 0,
  severity: '',
  scanText: '',
  canaryRouteId: '',
  smtp: null,
  smtpPassword: '',
  loading: false,
});

export function createSecurityFeature(shell, api) {
  shell.security = initialState();

  shell.loadSecurityFindings = async function loadSecurityFindings() {
    const state = this.security;
    try {
      this.security.loading = true;
      const q = this.security.severity ? ('?severity=' + encodeURIComponent(this.security.severity)) : '';
      const data = await api.get('/security/findings' + q);
      if (this.security !== state) return;
      this.security.findings = data.findings || [];
      this.security.total = data.total || 0;
    } catch (e) {
      if (this.security !== state) return;
      this.err = e && e.message ? e.message : String(e);
    } finally {
      state.loading = false;
    }
  };

  shell.runSecurityScan = async function runSecurityScan() {
    const state = this.security;
    try {
      const data = await api.post('/security/scan', { text: this.security.scanText });
      if (this.security !== state) return;
      this.msg = '扫描完成：' + (data.count || 0) + ' 条 finding';
      await this.loadSecurityFindings();
    } catch (e) {
      if (this.security !== state) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.runSecurityCanary = async function runSecurityCanary() {
    const state = this.security;
    try {
      const routeId = Number(this.security.canaryRouteId);
      const data = await api.post('/security/canary', { route_id: routeId });
      if (this.security !== state) return;
      this.msg = 'Canary 已提交：' + (data.execution_id || data.mode || 'ok');
      await this.loadSecurityFindings();
    } catch (e) {
      if (this.security !== state) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.loadSMTP = async function loadSMTP() {
    const state = this.security;
    try {
      const smtp = await api.get('/security/smtp');
      if (this.security !== state) return;
      state.smtp = smtp;
    } catch (e) {
      if (this.security !== state) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.saveSMTP = async function saveSMTP() {
    const state = this.security;
    try {
      const body = Object.assign({}, this.security.smtp || {}, {
        password: this.security.smtpPassword || undefined,
      });
      const smtp = await api.put('/security/smtp', body);
      if (this.security !== state) return;
      state.smtp = smtp;
      this.security.smtpPassword = '';
      this.msg = 'SMTP 已保存';
    } catch (e) {
      if (this.security !== state) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.testSMTP = async function testSMTP() {
    const state = this.security;
    try {
      await api.post('/security/smtp/test', {});
      if (this.security !== state) return;
      this.msg = '测试邮件已发送';
      await this.loadSecurityFindings();
    } catch (e) {
      if (this.security !== state) return;
      this.err = e && e.message ? e.message : String(e);
    }
  };
  const originalReset = shell.reset;
  shell.reset = function resetSecurity() {
    this.security = initialState();
    return originalReset?.call(this);
  };
}

export function mergeSecurityTab(shell) {
  if (!Array.isArray(shell.tabs)) return;
  if (shell.tabs.some((t) => t && t.id === 'security')) return;
  const credIdx = shell.tabs.findIndex((t) => t && t.id === 'credentials');
  const tab = { id: 'security', name: '安全' };
  if (credIdx >= 0) shell.tabs.splice(credIdx + 1, 0, tab);
  else shell.tabs.push(tab);
}
