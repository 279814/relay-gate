/* Captured Attempt facts only; sample bodies never enter this feature. */
import {focusFirst} from './modal.mjs';
const unknown = '未知';
const absent = '未记录';
const initialState = () => ({open: false, loading: false, executionLoading: false, error: '', title: '', reqID: '', sampleID: null, selected: 0, attempts: [], note: ''});
const positive = value => Number.isSafeInteger(value) && value > 0;
const revision = value => positive(value) ? String(value) : '未记录 / 不适用';
const text = value => typeof value === 'string' ? value.slice(0, 128) : '';
const boolean = (value, known) => known && typeof value === 'boolean' ? (value ? '是' : '否') : unknown;
const fact = (label, value) => ({label, value});
const code = (value, options) => options[value] || unknown;
const errorClasses = {
  none: 'none（无上游错误）', unreachable: 'unreachable（不可达）', auth_rejected: 'auth_rejected（认证拒绝）',
  request_shape_rejected: 'request_shape_rejected（请求结构拒绝）', config_error: 'config_error（配置错误）',
  unsupported: 'unsupported（不支持）', model_not_found: 'model_not_found（模型不存在）', rate_limited: 'rate_limited（限流）',
  transient_error: 'transient_error（暂时错误）', fake_alive: 'fake_alive（假活）', partial_failure: 'partial_failure（部分失败）', ignored: 'ignored（未采用）',
};
const effects = {pending: 'pending（待持久化确认）', unavailable: 'unavailable（观察未装配）', dropped: 'dropped（观察被丢弃）',
  applied: 'applied（已应用）', config_stale: 'config_stale（旧配置，未应用）', superseded: 'superseded（已被更新观察替代）',
  not_applicable: 'not_applicable（无适用结论）', ignored: 'ignored（未采用）'};
const diffReasons = {recorded: '已记录结构变化与安全指纹', secret_taint: '因 Secret 污点省略', incomplete: '内容不完整，未比较', sample_disabled: '样本未启用，未增加正文副本'};

function elapsed(start, end) {
  return positive(start) && positive(end) && end >= start ? `${end - start}ms` : absent;
}

function comparison(metadata, prefix, known) {
  const reason = known ? metadata[prefix + '_diff_reason'] : 'unknown';
  const recorded = reason === 'recorded';
  const hash = value => recorded && typeof value === 'string' && /^[a-f0-9]{64}$/.test(value) ? value : absent;
  return {
    label: prefix === 'request' ? '请求结构与指纹' : '响应结构与指纹',
    reason: diffReasons[reason] || '历史未知 / 未记录比较',
    body: recorded ? boolean(metadata[prefix + '_body_changed'], true) : '未比较',
    headers: recorded ? boolean(metadata[prefix + '_headers_changed'], true) : '未比较',
    inputHash: hash(metadata[prefix + '_input_hash']), outputHash: hash(metadata[prefix + '_output_hash']),
  };
}

function presentAttempt(row, kind, index) {
  const metadata = row.metadata || {};
  const known = metadata.version === 1;
  const number = known && positive(metadata.attempt) ? metadata.attempt : positive(row.attempt) ? row.attempt : index + 1;
  const executionID = known && typeof metadata.execution_id === 'string' && /^[a-z0-9-]{1,64}$/.test(metadata.execution_id) ? metadata.execution_id : '';
  const canOpenExecution = !!executionID && metadata.execution_stored === true;
  let executionState = '未记录精确 Execution';
  if (!known) executionState = '历史未知，未记录精确 Execution';
  else if (canOpenExecution) executionState = '精确详情已保存';
  else if (executionID && metadata.capability_effect === 'pending') executionState = '待持久化确认，精确详情尚不可用';
  else if (executionID && metadata.capability_effect === 'dropped') executionState = '观察已丢弃，精确详情未保存';
  else if (executionID) executionState = '精确详情已淘汰或不可用，保留的事实不等于详情仍在';
  const revisions = [
    ['根配置代', 'config_generation'], ['Settings 修订', 'settings_revision'], ['Endpoint ID', 'endpoint_id'],
    ['Endpoint 修订', 'endpoint_revision'], ['Auth Profile 修订', 'auth_profile_revision'],
    ['Upstream 网络修订', 'upstream_network_revision'], ['Upstream 凭据修订', 'upstream_credential_revision'],
    ['Route 行修订', 'route_revision'], ['Route 能力修订', 'route_capability_revision'],
    ['Model 行修订', 'model_revision'], ['Model 能力修订', 'model_capability_revision'],
    ['Transform 版本 ID', 'transform_version_id'], ['请求 Transform 绑定修订', 'request_transform_revision'],
  ].map(([label, key]) => fact(label, known ? revision(metadata[key]) : unknown));
  return {
    key: `${kind}-${positive(row.id) ? row.id : index}`, title: `第 ${number} 次尝试`,
    version: known ? '1' : positive(metadata.version) ? `暂不支持 ${metadata.version}` : '历史未知',
    notice: known ? '' : '历史或版本未知；以下缺失事实不会用当前配置补齐，也不推断为成功或无变化。',
    executionID, canOpenExecution, executionState, revisions,
    responseView: known ? code(metadata.response_view, {unknown: '未知', not_sampled: '未保存样本响应', upstream_attempt_prefix: '已丢弃尝试：上游前缀 / 排空视图', client_response: '客户端写出视图（可能含响应 Transform）'}) : unknown,
    identity: [fact('Route ID', revision(row.route_id)), fact('Upstream ID', revision(row.upstream_id)), fact('ModelName ID', revision(row.model_name_id)),
      fact('出站模型', text(row.model_out) || absent), fact('HTTP 状态', positive(row.resp_status) ? String(row.resp_status) : absent), fact('Outcome', text(row.outcome) || unknown)],
    timings: [fact('排队', elapsed(row.ts_recv, row.ts_sent)), fact('响应头（发送起）', known ? elapsed(row.ts_sent, metadata.response_header_at_ms) : unknown),
      fact('首字节（发送起）', elapsed(row.ts_sent, row.ts_first_byte)), fact('首事件（发送起）', known ? elapsed(row.ts_sent, metadata.first_event_at_ms) : unknown),
      fact('首语义（发送起）', known ? elapsed(row.ts_sent, metadata.first_semantic_at_ms) : unknown), fact('总时长', elapsed(row.ts_recv, row.ts_done)),
      fact('客户端写出', kind === 'log' && Number.isSafeInteger(row.bytes_written) && row.bytes_written >= 0 ? `${row.bytes_written} B` : absent)],
    decisions: [fact('Retry Policy', known ? code(metadata.retry_policy, {safe: 'safe', balanced: 'balanced', aggressive: 'aggressive'}) : unknown),
      fact('重试原因', known ? code(metadata.retry_reason, {safe_connect_failure: '发送前连接失败', policy_retry_after_possible_upstream_accept: '上游可能已接受，由策略允许重试'}) : unknown),
      fact('请求写入证据', known ? code(metadata.request_write_state, {not_written: '未写入', possibly_written: '可能已写入', written: '已写入'}) : unknown),
      fact('实际 Capability effect', known ? code(metadata.capability_effect, effects) : unknown), fact('细 ErrorClass', known ? code(metadata.error_class, errorClasses) : unknown),
      fact('已换站重试', boolean(metadata.retried, known)), fact('半开放行', boolean(metadata.half_open, known)), fact('潜在重复执行', boolean(metadata.duplicate_risk, known)),
      fact('Synthetic completion', boolean(metadata.synthetic_completion, known))],
    diffs: [comparison(metadata, 'request', known), comparison(metadata, 'response', known)],
  };
}

export function createAttemptMetadataFeature(shell, api) {
  shell.attemptMetadata = initialState();
  let activeRead = {};
  let activeExecution = {};

  function open(receiver, view) {
    activeRead = {}; activeExecution = {};
    receiver.sample = null; receiver.hdrExport = null;
    receiver.sampleAccess = null; receiver.samplePassword = ''; receiver.executionDrawer = null;
    receiver.attemptMetadata = {...initialState(), open: true, ...view};
    receiver._lockModal?.(() => receiver.closeAttemptMetadata());
    const opened = receiver.attemptMetadata;
    receiver.$nextTick?.(() => { if (receiver.attemptMetadata === opened && opened.open) focusFirst(receiver.$refs?.attemptMetadataDrawer); });
  }

  shell.openAttemptMetadata = function openAttemptMetadata(row) {
    open(this, {title: 'RequestLog 逐次尝试事实', reqID: text(row.req_id), attempts: [presentAttempt(row, 'log', 0)]});
  };

  shell.openSampleMetadata = async function openSampleMetadata(id) {
    if (!positive(id)) { this.err = '样本 ID 无效'; return; }
    open(this, {title: `样本 #${id} 的尝试元数据`, sampleID: id, loading: true});
    const view = this.attemptMetadata;
    const request = {}; activeRead = request;
    const current = () => this.attemptMetadata === view && activeRead === request && view.open;
    try {
      const data = await api.get(`/samples/${id}/metadata`);
      if (!current()) return;
      if (data?.id !== id || !Array.isArray(data.attempts)) throw new Error('样本元数据响应无效');
      view.reqID = text(data.req_id);
      view.attempts = data.attempts.map((row, index) => presentAttempt(row, 'sample', index));
      const legacy = positive(data.legacy_sample_id) ? '旧样本迁移仅保留已有尝试，不重构未保存的重试。' : '';
      view.note = `${view.attempts.length} 条已保存尝试；声明总数 ${Number.isSafeInteger(data.attempt_count) ? data.attempt_count : '未知'}。${legacy}`;
    } catch (error) {
      if (current()) view.error = error?.status === 404 ? '样本元数据已淘汰或不可用' : (error?.message || '元数据读取失败');
    } finally {
      if (current()) view.loading = false;
    }
  };

  shell.closeAttemptMetadata = function closeAttemptMetadata() {
    activeRead = {}; activeExecution = {};
    this.attemptMetadata = initialState();
    this._unlockModal?.();
  };

  shell.selectMetadataAttempt = function selectMetadataAttempt() {
    activeExecution = {};
    this.attemptMetadata.executionLoading = false;
    this.attemptMetadata.error = '';
  };

  shell.openMetadataExecution = async function openMetadataExecution() {
    const view = this.attemptMetadata;
    const attempt = view.attempts[view.selected];
    if (!attempt?.canOpenExecution || view.executionLoading) return;
    const request = {}; activeExecution = request;
    const current = () => this.attemptMetadata === view && activeExecution === request && view.open;
    view.executionLoading = true; view.error = '';
    try {
      const detail = await api.get('/probe-executions/' + encodeURIComponent(attempt.executionID));
      if (!current()) return;
      this.closeAttemptMetadata();
      this.executionDrawer = detail;
      this._lockModal?.(() => this.closeExecution());
    } catch (error) {
      if (!current()) return;
      if (error?.status === 404) {
        attempt.canOpenExecution = false;
        attempt.executionState = '精确详情已淘汰或不可用';
        view.error = '该精确 Execution 已淘汰或不可用；不会改查同 Route 的其他记录。';
      } else view.error = error?.message || '精确 Execution 读取失败';
    } finally {
      if (current()) view.executionLoading = false;
    }
  };

  shell.openMetadataSampleBody = async function openMetadataSampleBody() {
    const id = this.attemptMetadata.sampleID;
    if (!positive(id)) return;
    this.closeAttemptMetadata();
    await this.openSample(id);
  };

  const originalReset = shell.reset;
  shell.reset = function resetAttemptMetadata() {
    this.closeAttemptMetadata();
    return originalReset?.call(this);
  };
}
