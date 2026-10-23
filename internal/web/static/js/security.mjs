import {createSecurityManagement, securityManagementState} from './security_management.mjs';
/* security.mjs — P3 Security Center UI (§14.5). Pure text (x-text). */

import { createCanaryFeature } from './canary.mjs';

const initialState = () => ({
  findings: [],
  management: securityManagementState(),
  upstreamID: '', ruleID: '', reviewStatus: '', ignored: '',
  total: 0,
  severity: '',
  routeID: '',
  category: '',
  fromTime: '',
  toTime: '',
  pageCursor: '',
  nextCursor: '',
  findingsError: '',
  scanText: '',
  canaryRouteId: '',
  smtp: null,
  smtpPassword: '',
  smtpSaving: false,
  smtpLoading: false,
  smtpConflict: false,
  loading: false,
});

export function createSecurityFeature(shell, api) {
  shell.security = initialState();
  createSecurityManagement(shell, api);
  let findingsRead = {};

  shell.loadSecurityFindings = async function loadSecurityFindings(cursor = '') {
    const state = this.security;
    const request = {}; findingsRead = request;
    const current = () => this.security === state && findingsRead === request;
    state.findings = []; state.total = 0; state.nextCursor = ''; state.findingsError = '';
    state.loading = true; state.pageCursor = cursor;
    try {
      const routeID = Number(state.routeID);
      const upstreamID = Number(state.upstreamID);
      const fromMS = state.fromTime ? new Date(state.fromTime).getTime() : 0;
      const toMS = state.toTime ? new Date(state.toTime).getTime() : 0;
      if (!Number.isSafeInteger(upstreamID) || upstreamID < 0 || !Number.isSafeInteger(routeID) || routeID < 0 || !Number.isSafeInteger(fromMS) || fromMS < 0 || !Number.isSafeInteger(toMS) || toMS < 0 ||
          (toMS && fromMS > toMS) || !/^[a-zA-Z0-9_.:-]{0,64}$/.test(state.category) ||
          !['', 'critical', 'high', 'medium', 'low', 'info'].includes(state.severity)) throw new Error('安全发现筛选无效，请检查 Route、类别和发现时间');
      const q = new URLSearchParams({limit: '25'});
      if (state.severity) q.set('severity', state.severity);
      if (routeID) q.set('route_id', String(routeID));
      if (state.category) q.set('category', state.category);
      if (upstreamID) q.set('upstream_id', String(upstreamID));
      if (state.ruleID) q.set('rule_id', state.ruleID);
      if (state.reviewStatus) q.set('review_status', state.reviewStatus);
      if (state.ignored) q.set('ignored', state.ignored);
      if (fromMS) q.set('from_ms', String(fromMS));
      if (toMS) q.set('to_ms', String(toMS));
      if (cursor) q.set('cursor', cursor);
      const data = await api.get('/security/findings?' + q);
      if (!current()) return;
      if (!Array.isArray(data?.findings) || data.findings.length > 25 || !Number.isSafeInteger(data.total) || data.total < 0) throw new Error('安全发现分页响应无效');
      state.findings = data.findings;
      state.total = data.total;
      state.nextCursor = typeof data.next_cursor === 'string' ? data.next_cursor : '';
    } catch (e) {
      if (!current()) return;
      state.findingsError = e?.message || '安全发现读取失败';
    } finally {
      if (current()) state.loading = false;
    }
  };

  shell.nextSecurityFindings = async function nextSecurityFindings() {
    if (this.security.loading || !this.security.nextCursor) return;
    await this.loadSecurityFindings(this.security.nextCursor);
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

  shell.loadSMTP = async function loadSMTP(force = false) {
    const state = this.security;
    if (state.smtpSaving || state.smtpLoading || (state.smtp && !force)) return;
    state.smtpLoading = true;
    if (force) { this.err = ''; this.msg = ''; }
    try {
      const smtp = await api.get('/security/smtp');
      if (this.security !== state) return;
      state.smtp = smtp;
      state.smtpPassword = '';
      state.smtpConflict = false;
    } catch (e) {
      if (this.security !== state) return;
      this.err = e && e.message ? e.message : String(e);
    } finally {
      state.smtpLoading = false;
    }
  };

  shell.saveSMTP = async function saveSMTP() {
    const state = this.security;
    if (state.smtpSaving || state.smtpLoading || state.smtpConflict) return;
    this.err = '';
    this.msg = '';
    const config = state.smtp;
    const modeCount = Number(config?.use_starttls === true) + Number(config?.use_smtps === true);
    if (!config || modeCount > 1 || (config.enabled === true && modeCount !== 1)) {
      this.err = 'SMTP 必须明确选择 STARTTLS 或 SMTPS 加密模式';
      return;
    }
    if (!Number.isSafeInteger(config.revision) || config.revision < 1 ||
        ![config.aggregation_window_sec, config.rate_limit_window_sec].every(value => Number.isInteger(value) && value >= 1 && value <= 86400)) {
      this.err = 'SMTP 配置版本无效，或聚合、限流窗口不在 1–86400 秒内';
      return;
    }
    state.smtpSaving = true;
    try {
      const body = {expected_revision: config.revision};
      for (const key of ['enabled', 'host', 'port', 'use_starttls', 'use_smtps', 'from', 'recipients', 'username', 'min_severity', 'aggregation_window_sec', 'rate_limit_window_sec']) {
        body[key] = config[key];
      }
      if (state.smtpPassword) body.password = state.smtpPassword;
      const smtp = await api.put('/security/smtp', body);
      if (this.security !== state) return;
      state.smtpPassword = '';
      if (smtp?.config_activation_pending === true) {
        state.smtpConflict = true;
        this.msg = 'SMTP 已保存，激活待确认。请重新加载配置，勿重复提交。';
        return;
      }
      state.smtp = smtp;
      this.msg = 'SMTP 已保存';
    } catch (e) {
      if (this.security !== state) return;
      if (e?.status === 409) {
        state.smtpConflict = true;
        this.err = 'SMTP 配置已被更新，草稿已保留。请重新加载配置后再编辑。';
      } else {
        this.err = e && e.message ? e.message : String(e);
      }
    } finally {
      state.smtpSaving = false;
    }
  };

  shell.setSMTPMode = function setSMTPMode(mode) {
    const config = this.security.smtp;
    if (!config || !['starttls', 'smtps'].includes(mode)) return;
    config.use_starttls = mode === 'starttls';
    config.use_smtps = mode === 'smtps';
    if (!config.port || config.port === 587 || config.port === 465) {
      config.port = config.use_smtps ? 465 : 587;
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
    findingsRead = {};
    this.security = initialState();
    return originalReset?.call(this);
  };
  createCanaryFeature(shell, api);
}

export function mergeSecurityTab(shell) {
  if (!Array.isArray(shell.tabs)) return;
  if (shell.tabs.some((t) => t && t.id === 'security')) return;
  const credIdx = shell.tabs.findIndex((t) => t && t.id === 'credentials');
  const tab = { id: 'security', name: '安全' };
  if (credIdx >= 0) shell.tabs.splice(credIdx + 1, 0, tab);
  else shell.tabs.push(tab);
}
