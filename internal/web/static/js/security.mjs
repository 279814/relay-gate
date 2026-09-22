/* security.mjs — P3 Security Center UI (§14.5). Pure text (x-text). */

export function createSecurityFeature(shell, api) {
  shell.security = {
    findings: [],
    total: 0,
    severity: '',
    scanText: '',
    canaryRouteId: '',
    smtp: null,
    smtpPassword: '',
    loading: false,
  };

  shell.loadSecurityFindings = async function loadSecurityFindings() {
    try {
      this.security.loading = true;
      const q = this.security.severity ? ('?severity=' + encodeURIComponent(this.security.severity)) : '';
      const data = await api.get('/security/findings' + q);
      this.security.findings = data.findings || [];
      this.security.total = data.total || 0;
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    } finally {
      this.security.loading = false;
    }
  };

  shell.runSecurityScan = async function runSecurityScan() {
    try {
      const data = await api.post('/security/scan', { text: this.security.scanText });
      this.msg = '扫描完成：' + (data.count || 0) + ' 条 finding';
      await this.loadSecurityFindings();
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.runSecurityCanary = async function runSecurityCanary() {
    try {
      const routeId = Number(this.security.canaryRouteId);
      const data = await api.post('/security/canary', { route_id: routeId });
      this.msg = 'Canary 已提交：' + (data.execution_id || data.mode || 'ok');
      await this.loadSecurityFindings();
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.loadSMTP = async function loadSMTP() {
    try {
      this.security.smtp = await api.get('/security/smtp');
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.saveSMTP = async function saveSMTP() {
    try {
      const body = Object.assign({}, this.security.smtp || {}, {
        password: this.security.smtpPassword || undefined,
      });
      this.security.smtp = await api.put('/security/smtp', body);
      this.security.smtpPassword = '';
      this.msg = 'SMTP 已保存';
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
  };

  shell.testSMTP = async function testSMTP() {
    try {
      await api.post('/security/smtp/test', {});
      this.msg = '测试邮件已发送';
      await this.loadSecurityFindings();
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    }
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
