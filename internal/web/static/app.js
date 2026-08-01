/* relay-gate 管理界面。
 *
 * 只有一个 Alpine 组件。分成多个组件要在它们之间同步「上游列表」这类
 * 共享数据，而这个界面小到不值得引入那层协调。
 *
 * 一条贯穿全文的原则：**后端的错误信息原样显示**。
 * model/validate.go 里那些错误是刻意写给人看的（「base_url 不能带路径…
 * 若该站确实用非标准路径，请开启 full_url_mode」），前端把它们换成
 * 「保存失败」就等于把最有用的部分丢掉了。
 */

function app() {
  return {
    // ── 状态 ──────────────────────────────────────────
    authed: false,
    pw: '',
    busy: false,
    err: '',
    msg: '',

    tab: 'health',
    tabs: [
      { id: 'health',    name: '健康看板' },
      { id: 'upstreams', name: '上游' },
      { id: 'models',    name: '模型' },
      { id: 'routes',    name: '路由' },
      { id: 'samples',   name: '样本' },
      { id: 'cost',      name: '探活开销' },
      { id: 'settings',  name: '设置' },
    ],

    running: true,
    health: {},
    runtime: {},
    cost: {},
    upstreams: [],
    modelNames: [],
    routes: [],
    samples: [],
    samplesTotal: 0,
    sampleFilter: { outcome: '' },
    settings: null,
    limits: {},

    upForm: null,
    mnForm: null,
    rtForm: null,
    sample: null,
    hdrExport: null,
    probeResult: null,
    probing: 0,

    autoRefresh: false,
    _timer: null,

    // ── 启动 ──────────────────────────────────────────

    async boot() {
      // 先问「我登录了吗」。这个端点在鉴权之外，未登录时回 false 而不是
      // 401 —— 那是正常流程，不是错误。
      try {
        const r = await fetch('/admin/api/session');
        this.authed = (await r.json()).authenticated === true;
      } catch (e) {
        this.err = '无法连接服务：' + e.message;
        return;
      }
      if (this.authed) await this.loadAll();

      // 自动刷新只在健康看板生效。别的页在编辑表单，刷掉输入很讨厌。
      this.$watch('autoRefresh', v => v ? this.startTimer() : this.stopTimer());
    },

    startTimer() {
      this.stopTimer();
      this._timer = setInterval(() => {
        if (this.tab === 'health' && !this.busy) this.loadHealth();
      }, 3000);
    },

    stopTimer() {
      if (this._timer) { clearInterval(this._timer); this._timer = null; }
    },

    // ── HTTP ─────────────────────────────────────────

    /* api 是所有请求的唯一出口。
     *
     * 两件事集中在这里做，因为漏一处的后果都不好查：
     *   - 401 → 回登录页。会话过期后，界面若继续显示旧数据、每个操作都
     *     静默失败，用户会以为是服务坏了
     *   - 错误信息取后端的 error 字段原文（见文件头的原则）
     */
    async api(method, path, body) {
      const opt = { method, headers: {} };
      if (body !== undefined) {
        opt.headers['Content-Type'] = 'application/json';
        opt.body = JSON.stringify(body);
      }
      const r = await fetch('/admin/api' + path, opt);

      if (r.status === 401) {
        this.reset();
        throw new Error('会话已过期，请重新登录');
      }
      if (r.status === 204) return null;

      const text = await r.text();
      let data = null;
      if (text) {
        try { data = JSON.parse(text); } catch { /* 非 JSON 响应，下面按状态码处理 */ }
      }
      if (!r.ok) {
        const e = new Error((data && data.error) || text || `HTTP ${r.status}`);
        // 带上状态码，让调用方能按码判断而不是去猜错误文案。
        // 探活未启用时几个端点回 503，那是「功能没接」不是「出错了」——
        // 按中文子串匹配来区分的话，后端改一次文案前端就误报。
        e.status = r.status;
        throw e;
      }
      return data;
    },

    /* run 包住所有会写数据的操作：统一置忙、清提示、报错。
     *
     * 不这么做的话，每个 saveXxx 都要自己写一遍 try/finally，
     * 而漏掉 finally 的那个会把界面永久卡在 busy 状态。
     *
     * 返回一个 {ok, data} 而不是直接返回 fn 的结果：调用方需要区分
     * 「失败了」与「成功了但响应体是空的」。DELETE 回 204、api() 给出
     * null，用「结果是否为空」当成败判据的话，这两种情况就分不开了。
     */
    async run(fn, okMsg) {
      this.busy = true;
      this.err = '';
      this.msg = '';
      try {
        const data = await fn();
        if (okMsg) this.msg = okMsg;
        return { ok: true, data };
      } catch (e) {
        this.err = e.message;
        return { ok: false };
      } finally {
        this.busy = false;
      }
    },

    // ── 认证 ─────────────────────────────────────────

    async login() {
      if (!this.pw) { this.err = '请输入口令'; return; }
      const { ok } = await this.run(() => this.api('POST', '/login', { password: this.pw }));
      if (ok) {
        this.pw = '';   // 不留在内存里
        this.authed = true;
        await this.loadAll();
      }
    },

    async logout() {
      try { await this.api('POST', '/logout'); } catch { /* 登出失败也要回登录页 */ }
      this.reset();
    },

    /* reset 回到未登录状态，并**清空所有已加载的数据**。
     *
     * 清数据是必须的，不只是把 authed 置 false：样本里有完整的对话原文
     * 与代码（§3.6），上游列表里有站点地址。不清的话，登出后下一个人在
     * 同一个浏览器登录时，会先看到上一次的数据闪现出来 —— 那些数据本该
     * 随着登出一起消失。
     *
     * 顺带清掉编辑中的表单：留着的话，重新登录后会看到一个半填的弹窗，
     * 而它引用的 id 可能已经被别人改了。
     */
    reset() {
      this.stopTimer();
      this.authed = false;
      this.autoRefresh = false;
      this.err = '';
      this.msg = '';

      this.health = {};
      this.runtime = {};
      this.cost = {};
      this.upstreams = [];
      this.modelNames = [];
      this.routes = [];
      this.samples = [];
      this.samplesTotal = 0;
      this.settings = null;
      this.limits = {};

      this.upForm = null;
      this.mnForm = null;
      this.rtForm = null;
      this.sample = null;
      this.hdrExport = null;
      this.probeResult = null;
      this.tab = 'health';
    },

    // ── 加载 ─────────────────────────────────────────

    async loadAll() {
      await this.run(async () => {
        // 并发拉取。串行的话首屏要等 6 个往返。
        const [st, ups, mns, rts] = await Promise.all([
          this.api('GET', '/state'),
          this.api('GET', '/upstreams'),
          this.api('GET', '/model-names'),
          this.api('GET', '/routes'),
        ]);
        this.running = st.state === 'running';
        this.upstreams = ups || [];
        this.modelNames = mns || [];
        this.routes = rts || [];
      });
      await this.loadHealth();
      await this.loadSettings();
    },

    async loadHealth() {
      try {
        const [h, rt] = await Promise.all([
          this.api('GET', '/health'),
          this.api('GET', '/runtime'),
        ]);
        this.health = h || {};
        this.runtime = rt || {};
      } catch (e) {
        // 503 = 探活未启用，那不是错误，其余页面照常可用（api.Server 在
        // healthView 为 nil 时刻意回 503 而不是让整个管理接口不可用）。
        // 按状态码判断而不是匹配错误文案 —— 后端改一次措辞就会让匹配失效。
        this.health = { routes: [], summary: { total: 0, selectable: 0 } };
        if (e.status !== 503) this.err = e.message;
      }
    },

    async loadSettings() {
      try {
        const s = await this.api('GET', '/settings');
        this.settings = s.settings;
        this.limits = s.limits || {};
      } catch (e) { this.err = e.message; }
    },

    async loadCost() {
      try {
        this.cost = await this.api('GET', '/probe-cost') || {};
      } catch (e) {
        this.cost = {};
        if (e.status !== 503) this.err = e.message; // 理由同 loadHealth
      }
    },

    async loadSamples() {
      const q = new URLSearchParams();
      if (this.sampleFilter.outcome) q.set('outcome', this.sampleFilter.outcome);
      q.set('limit', '100');
      await this.run(async () => {
        const d = await this.api('GET', '/samples?' + q);
        this.samples = d.samples || [];
        this.samplesTotal = d.total || 0;
      });
    },

    // 切页时按需拉数据。一次全拉的话，只想看配置的人也要等样本查询。
    go(tab) {
      this.tab = tab;
      this.err = '';
      this.msg = '';
      if (tab === 'samples' && !this.samples.length) this.loadSamples();
      if (tab === 'cost') this.loadCost();
      if (tab === 'health') this.loadHealth();
    },

    // ── 总闸（§4.8）───────────────────────────────────

    async toggleState() {
      const next = this.running ? 'paused' : 'running';
      const { ok } = await this.run(
        () => this.api('POST', '/state', { state: next }),
        next === 'paused'
          ? '已暂停：新请求返回 503，探活全停。进行中的流式对话会正常收完'
          : '已恢复：全部 Route 置 unknown 并立即重新探活',
      );
      if (ok) {
        this.running = next === 'running';
        this.loadHealth();
      }
    },

    // ── 上游 CRUD ────────────────────────────────────

    editUp(u) {
      if (!u) {
        this.upForm = {
          name: '', base_url: '', api_key: '', auth_style: 'auto',
          l1_path: '/v1/models', proxy_url: '', enabled: true,
          full_url_mode: false, probe_headers_raw: '',
        };
        return;
      }
      // api_key 留空：界面上拿到的是脱敏值，回写它会把假 key 存进库。
      // 真正的「不改」语义由后端负责（PUT 时留空即保持原值）。
      this.upForm = {
        ...u,
        api_key: '',
        api_key_masked: u.api_key,
        probe_headers_raw: u.probe_headers ? JSON.stringify(u.probe_headers, null, 2) : '',
      };
    },

    async saveUp() {
      const f = this.upForm;

      // probe_headers 在界面上是一段文本，存进去必须是对象。
      // 解析失败要当场说清楚是哪儿错了 —— 让它带着一段坏 JSON 提交，
      // 后端只会回一个笼统的「请求体不是合法 JSON」，指不到这个字段。
      let headers;
      try {
        headers = f.probe_headers_raw.trim() ? JSON.parse(f.probe_headers_raw) : {};
      } catch (e) {
        this.err = '探活头不是合法 JSON：' + e.message;
        return;
      }
      if (headers === null || typeof headers !== 'object' || Array.isArray(headers)) {
        this.err = '探活头必须是一个 JSON 对象，例如 {"user-agent": "claude-cli/2.1.220"}';
        return;
      }

      const body = {
        name: f.name, base_url: f.base_url, auth_style: f.auth_style,
        l1_path: f.l1_path, proxy_url: f.proxy_url, enabled: f.enabled,
        full_url_mode: f.full_url_mode, probe_headers: headers,
      };
      // 只在真的填了新 key 时才带上这个字段（后端：留空 = 不改）。
      if (f.api_key) body.api_key = f.api_key;

      // 保存 + 重新拉列表放在**同一个** run 里。
      //
      // 早先把拉列表写在 run 外面，那个裸 await 一旦失败（会话刚过期、
      // 网络抖动）就会变成一个未捕获的 promise rejection —— 界面静默不动，
      // 用户以为保存没生效，而其实存进去了。
      const { ok } = await this.run(async () => {
        f.id ? await this.api('PUT', '/upstreams/' + f.id, body)
             : await this.api('POST', '/upstreams', body);
        this.upstreams = await this.api('GET', '/upstreams') || [];
      }, f.id ? '已保存。改了 key 或地址会立即重新探活' : '已新增');

      if (ok) {
        this.upForm = null;
        this.loadHealth();
      }
    },

    async delUp(u) {
      const n = this.routes.filter(r => r.upstream_id === u.id).length;
      const warn = n ? `\n\n它下面的 ${n} 条路由会一并删除。` : '';
      if (!confirm(`删除上游「${u.name}」？${warn}`)) return;
      const { ok } = await this.run(() => this.api('DELETE', '/upstreams/' + u.id), '已删除');
      if (ok) await this.loadAll();
    },

    // ── 模型 CRUD ────────────────────────────────────

    editMn(m) {
      this.mnForm = m ? { ...m } : {
        name: '', protocol: 'anthropic', match_mode: 'exact',
        is_fallback: false, probe_prompt: '1+1=?', probe_max_tokens: 1,
        enabled: true,
      };
    },

    async saveMn() {
      const f = this.mnForm;
      const body = {
        name: f.name, protocol: f.protocol, match_mode: f.match_mode,
        is_fallback: f.is_fallback, probe_prompt: f.probe_prompt,
        probe_max_tokens: f.probe_max_tokens, enabled: f.enabled,
      };
      const { ok } = await this.run(async () => {
        f.id ? await this.api('PUT', '/model-names/' + f.id, body)
             : await this.api('POST', '/model-names', body);
        this.modelNames = await this.api('GET', '/model-names') || [];
      }, f.id ? '已保存' : '已新增');

      if (ok) {
        this.mnForm = null;
        this.loadHealth();
      }
    },

    async delMn(m) {
      const n = this.routes.filter(r => r.model_name_id === m.id).length;
      const warn = n ? `\n\n它的 ${n} 条路由会一并删除。` : '';
      if (!confirm(`删除模型「${m.name}」？${warn}`)) return;
      const { ok } = await this.run(() => this.api('DELETE', '/model-names/' + m.id), '已删除');
      if (ok) await this.loadAll();
    },

    // ── 路由 CRUD ────────────────────────────────────

    editRt(r) {
      this.rtForm = r ? { ...r } : {
        model_name_id: this.modelNames[0]?.id || 0,
        upstream_id: this.upstreams[0]?.id || 0,
        priority: 1, weight: 100, upstream_model: '',
        max_concurrency: 0, enabled: true,
      };
    },

    async saveRt() {
      const f = this.rtForm;
      const body = {
        model_name_id: f.model_name_id, upstream_id: f.upstream_id,
        priority: f.priority, weight: f.weight,
        upstream_model: f.upstream_model, max_concurrency: f.max_concurrency,
        enabled: f.enabled,
      };
      const { ok } = await this.run(async () => {
        f.id ? await this.api('PUT', '/routes/' + f.id, body)
             : await this.api('POST', '/routes', body);
        this.routes = await this.api('GET', '/routes') || [];
      }, f.id ? '已保存' : '已新增，正在探活');

      if (ok) {
        this.rtForm = null;
        this.loadHealth();
      }
    },

    async delRt(r) {
      if (!confirm(`删除路由「${this.mnName(r.model_name_id)} × ${this.upName(r.upstream_id)}」？`)) return;
      const { ok } = await this.run(() => this.api('DELETE', '/routes/' + r.id), '已删除');
      if (ok) await this.loadAll();
    },

    // ── 设置 ─────────────────────────────────────────

    async saveSettings() {
      await this.run(
        () => this.api('PUT', '/settings', this.settings),
        '已保存，立即生效',
      );
    },

    // ── 探活 ─────────────────────────────────────────

    async probe(routeId) {
      this.probing = routeId;
      this.err = '';
      this.probeResult = null;
      try {
        this.probeResult = await this.api('POST', `/routes/${routeId}/probe`);
        this.loadHealth();
      } catch (e) {
        this.err = e.message;
      } finally {
        this.probing = 0;
      }
    },

    // ── 样本 ─────────────────────────────────────────

    async openSample(id) {
      this.hdrExport = null;
      await this.run(async () => { this.sample = await this.api('GET', '/samples/' + id); });
    },

    async togglePin(s) {
      const { ok, data } = await this.run(
        () => this.api('POST', `/samples/${s.id}/pin`, { pinned: !s.pinned }),
      );
      // 用后端返回的值而不是自己再取反一次：两边各算一遍的话，
      // 一旦后端将来对这个操作加了条件（比如置顶数量上限），
      // 界面就会显示一个并没有生效的状态。
      if (ok && data) s.pinned = data.pinned;
    },

    async clearSamples() {
      if (!confirm('清空样本？置顶的会保留。')) return;
      const { ok, data } = await this.run(
        () => this.api('DELETE', '/samples?keep_pinned=true'));
      if (ok) {
        this.msg = `已删除 ${data?.deleted ?? 0} 条`;
        await this.loadSamples();
      }
    },

    async exportHeaders(sampleId) {
      await this.run(async () => {
        this.hdrExport = await this.api('GET', `/samples/${sampleId}/probe-headers`);
      });
    },

    /* applyHeaders 把导出的头填进对应上游的编辑表单。
     *
     * 不直接写库：这份头影响该站所有探活的成败，静默生效的话，
     * 一次误导出就能让整站判死。让用户看一眼再按保存。
     */
    applyHeaders() {
      const up = this.upstreams.find(u => u.id === this.hdrExport.upstream_id);
      if (!up) {
        this.err = '这条样本对应的上游已被删除，无法填入';
        return;
      }
      this.editUp(up);
      this.upForm.probe_headers_raw = JSON.stringify(this.hdrExport.headers, null, 2);
      this.sample = null;
      this.hdrExport = null;
      this.tab = 'upstreams';
      this.msg = `已填入「${up.name}」的表单，确认后点保存`;
    },

    // ── 显示辅助 ─────────────────────────────────────

    upName(id) { return this.upstreams.find(u => u.id === id)?.name || (id ? `#${id}` : '—'); },
    mnName(id) { return this.modelNames.find(m => m.id === id)?.name || (id ? `#${id}` : '—'); },

    routeLabel(id) {
      const r = this.routes.find(x => x.id === id);
      return r ? `${this.mnName(r.model_name_id)} × ${this.upName(r.upstream_id)}` : `#${id}`;
    },

    inFlightTotal() {
      return Object.values(this.runtime.in_flight || {}).reduce((a, b) => a + b, 0);
    },

    /* stateClass：unknown 不能显示成「有问题」。
     *
     * 它是**乐观**状态 —— 视为可用、正常参与选路（§2.4）。重启后所有
     * Route 都是 unknown，标成红色会让人以为服务坏了。
     */
    stateClass(s) {
      return s === 'alive' ? 'ok' : s === 'dead' ? 'err' : 'unknown';
    },

    verdictClass(v) {
      if (v === 'ok') return 'ok';
      if (v === 'rate_limited') return 'warn';
      if (!v) return 'unknown';
      return 'err';
    },

    outcomeClass(o) {
      if (o === 'ok') return 'ok';
      // client_abort 不是上游的问题（用户自己取消的），别标成红的
      if (o === 'client_abort') return 'unknown';
      return 'err';
    },

    fmtTime(ms) {
      if (!ms) return '—';
      const d = new Date(ms);
      const p = n => String(n).padStart(2, '0');
      return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    },

    ttft(s) {
      return s.ts_first_byte && s.ts_sent ? (s.ts_first_byte - s.ts_sent) + 'ms' : '—';
    },

    dur(s) {
      return s.ts_done && s.ts_recv ? (s.ts_done - s.ts_recv) + 'ms' : '—';
    },

    timeline(s) {
      const parts = [];
      if (s.ts_sent && s.ts_recv) parts.push(`排队 ${s.ts_sent - s.ts_recv}ms`);
      if (s.ts_first_byte && s.ts_sent) parts.push(`首字节 ${s.ts_first_byte - s.ts_sent}ms`);
      if (s.ts_done && s.ts_first_byte) parts.push(`传输 ${s.ts_done - s.ts_first_byte}ms`);
      if (s.ts_done && s.ts_recv) parts.push(`总计 ${s.ts_done - s.ts_recv}ms`);
      return parts.join(' · ') || '—';
    },

    // truncated 是位标记（§3.6.2）。不显示的话，看到一个 256KB 整的 body
    // 无法判断它是恰好这么大还是被砍过 —— 而那会让字节级比对得出错误结论。
    truncNote(flags) {
      const which = [];
      if (flags & 1) which.push('入站 body');
      if (flags & 2) which.push('出站 body');
      if (flags & 4) which.push('响应 body');
      return `以下内容被截断：${which.join('、')}。转发给上游和客户端的仍是完整的，只有这份留档副本被截。`;
    },

    /* b64 解码样本 body。
     *
     * 后端把 body 存成 []byte，encoding/json 编成 base64 —— 这是刻意的：
     * 样本 body 可能含非法 UTF-8（对话里的二进制片段、被截断的多字节字符），
     * 当字符串编码会被替换成 U+FFFD，而「到底是哪些字节」正是这个功能的
     * 全部意义。
     *
     * 所以解码失败是**预期内**的情况，不是异常：TextDecoder 不带 fatal
     * 时会把非法序列换成 U+FFFD，那正好是我们能做的最好展示。
     */
    b64(v) {
      if (!v) return '（空）';
      try {
        const bin = atob(v);
        const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
        const text = new TextDecoder().decode(bytes);
        return this.pretty(text);
      } catch (e) {
        return `（无法解码：${e.message}）`;
      }
    },

    // JSON 就格式化，不是就原样返回。SSE 流原样看最有用。
    pretty(text) {
      const t = text.trim();
      if (!t.startsWith('{') && !t.startsWith('[')) return text;
      try {
        return JSON.stringify(JSON.parse(t), null, 2);
      } catch {
        return text;
      }
    },
  };
}
