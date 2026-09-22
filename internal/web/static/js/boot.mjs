/* boot.mjs — 在 Alpine 启动前增强 window.app。
 *
 * 顺序（index.html）：classic app.js → 本模块 → Alpine defer。
 * 不修改已提交的 app.js；工作区脏 hunk 保持未暂存。
 * Probe 模块失败时显示可见错误，不拖垮既有管理功能。
 */

import { createApiClient } from './api.mjs';
import { createProbeFeature, mergeProbeTabs } from './probes.mjs';
import { createRecentErrorsFeature } from './errors.mjs';
import { createMigrationFeature } from './migration.mjs';
import { createCredentialsFeature, mergeCredentialsTab } from './credentials.mjs';
import { createSecurityFeature, mergeSecurityTab } from './security.mjs';
import { createTransformsFeature, mergeTransformsTab } from './transforms.mjs';
import { createRuntimeStateFeature } from './runtime.mjs';

const base = window.app;
if (typeof base !== 'function') {
  console.error('boot.mjs: window.app 未在模块加载前定义');
} else if (!base.__relayProbeBooted) {
  window.app = function app() {
    const shell = base();
    shell.probeModuleReady = false;
    shell.probeModuleError = '';
    createRuntimeStateFeature(shell);

    const api = createApiClient({
      onUnauthorized: () => {
        if (typeof shell.reset === 'function') shell.reset();
      },
    });

    // 业务网络改走 api.mjs；保留原 api(method,path,body) 形状。
    shell.api = async function apiCompat(method, path, body) {
      return api.request(method, path, body);
    };

    try {
      createProbeFeature(shell, api);
      mergeProbeTabs(shell);
      createRecentErrorsFeature(shell, api);
      createMigrationFeature(shell, api);
      createCredentialsFeature(shell, api);
      mergeCredentialsTab(shell);
      createSecurityFeature(shell, api);
      mergeSecurityTab(shell);
      createTransformsFeature(shell, api);
      mergeTransformsTab(shell);
      shell.probeModuleReady = true;
    } catch (e) {
      shell.probeModuleReady = false;
      shell.probeModuleError = 'Probe 模块加载失败：' + (e && e.message ? e.message : e);
      console.error(shell.probeModuleError, e);
    }

    const origBoot = shell.boot && shell.boot.bind(shell);
    shell.boot = async function boot() {
      if (!this.probeModuleReady && this.probeModuleError) {
        this.err = this.probeModuleError;
      }
      if (origBoot) await origBoot();
      if (this.authed && this.probeModuleReady) {
        try {
          const st = await api.get('/state');
          this.applyStatePayload(st);
        } catch {
          /* state 可选 */
        }
      }
    };

    const origLoadAll = shell.loadAll && shell.loadAll.bind(shell);
    if (origLoadAll) {
      shell.loadAll = async function loadAll() {
        await origLoadAll();
        try {
          const st = await api.get('/state');
          this.applyStatePayload(st);
        } catch { /* */ }
        if (this.probeModuleReady) await this.refreshHealthSide();
        if (typeof this.refreshRecentErrors === 'function') await this.refreshRecentErrors();
      };
    }

    const origLoadHealth = shell.loadHealth && shell.loadHealth.bind(shell);
    if (origLoadHealth) {
      shell.loadHealth = async function loadHealth() {
        await origLoadHealth();
        if (this.probeModuleReady) await this.refreshHealthSide();
        if (typeof this.refreshRecentErrors === 'function') await this.refreshRecentErrors();
      };
    }

    const origGo = shell.go && shell.go.bind(shell);
    shell.go = function go(tab) {
      if (origGo) origGo(tab);
      if (!this.probeModuleReady) return;
      if (tab === 'capabilities') {
        this.loadCapabilities(true);
        this.loadReachability(true);
      } else if (tab === 'recipes') {
        this.loadRecipes(true);
        this.loadSecrets(true);
        this.loadEndpoints(true);
      } else if (tab === 'executions') {
        this.loadExecutions(true);
        this.loadProbeCostDaily(true);
      } else if (tab === 'calibrations') {
        this.loadCalibrations(true);
      } else if (tab === 'probe-runtime') {
        this.loadProbeRuntime();
      } else if (tab === 'credentials') {
        this.loadCredentials();
      } else if (tab === 'security') {
        this.loadSecurityFindings();
        this.loadSMTP();
      } else if (tab === 'transforms') {
        this.loadTransforms();
      } else if (tab === 'health') {
        this.refreshHealthSide();
      }
    };

    // 总闸带 revision；409 刷新 revision。maintenance 禁止切换。
    shell.toggleState = async function toggleState() {
      if (this.displayState === 'maintenance') {
        this.err = '维护中不可切换启停（Master Key 轮换等）';
        return;
      }
      const next = this.running ? 'paused' : 'running';
      const pauseMsg = '已暂停：新请求与合成探活停止；真实在途请求不终止';
      const resumeMsg = '已恢复：将渐进复核 Route，暖机完成前不暗示全部已验证';
      try {
        this.busy = true;
        this.err = '';
        const data = await api.post('/state', {
          state: next,
          expected_revision: this.stateRevision || 0,
        });
        this.applyStatePayload(data);
        this.msg = next === 'paused' ? pauseMsg : resumeMsg;
        this.loadHealth();
      } catch (e) {
        if (e.status === 409) {
          try {
            const st = await api.get('/state');
            this.applyStatePayload(st);
          } catch { /* */ }
          this.err = '状态 revision 冲突，已刷新当前 revision，请重试';
        } else if (e.status === 503 && e.data && e.data.code === 'pause_drain_pending') {
          this.stateRevision = e.data.new_revision || this.stateRevision;
          this.running = false;
          this.displayState = 'paused';
          this.msg = '暂停已持久化，正在排空 synthetic…';
        } else {
          this.err = e.message;
        }
      } finally {
        this.busy = false;
      }
    };

    // Upstream 编辑：补 Active/Lazy、Host Override、TLS Server Name；探活头走 position 提示。
    const origEditUp = shell.editUp && shell.editUp.bind(shell);
    if (origEditUp) {
      shell.editUp = function editUp(u) {
        origEditUp(u);
        if (!this.upForm) return;
        if (!u) {
          this.upForm.probe_mode = 'active';
          this.upForm.host_override = '';
          this.upForm.tls_server_name = '';
        } else {
          this.upForm.probe_mode = u.probe_mode || 'active';
          this.upForm.host_override = u.host_override || '';
          this.upForm.tls_server_name = u.tls_server_name || '';
        }
      };
    }

    const origSaveUp = shell.saveUp && shell.saveUp.bind(shell);
    if (origSaveUp) {
      shell.saveUp = async function saveUp() {
        const f = this.upForm;
        if (!f) return;
        try {
          // 先用带 position 提示的解析器校验；通过后写回紧凑 JSON 再走原逻辑。
          const headers = this.parseHeadersOrThrow
            ? this.parseHeadersOrThrow(f.probe_headers_raw)
            : (f.probe_headers_raw || '').trim() ? JSON.parse(f.probe_headers_raw) : {};
          const prev = f.probe_headers_raw;
          f.probe_headers_raw = JSON.stringify(headers);
          // 劫持一次 api PUT/POST 以附加新字段
          const innerApi = this.api.bind(this);
          this.api = async (method, path, body) => {
            if ((method === 'PUT' || method === 'POST') && String(path).startsWith('/upstreams')) {
              body = Object.assign({}, body, {
                probe_mode: f.probe_mode || 'active',
                host_override: f.host_override || '',
                tls_server_name: f.tls_server_name || '',
              });
            }
            return innerApi(method, path, body);
          };
          try {
            return await origSaveUp();
          } finally {
            this.api = innerApi;
            f.probe_headers_raw = prev;
          }
        } catch (e) {
          this.err = e.message;
        }
      };
    }

    // 手动探活：优先展示 execution_id。
    const origProbe = shell.probe && shell.probe.bind(shell);
    if (origProbe) {
      shell.probe = async function probe(routeId) {
        this.probing = routeId;
        this.err = '';
        this.probeResult = null;
        try {
          const data = await api.post('/routes/' + routeId + '/probe');
          this.probeResult = data;
          if (data && data.execution_id) {
            this.msg = '手动探活完成，execution_id=' + data.execution_id;
          }
          this.loadHealth();
        } catch (e) {
          this.err = e.message;
        } finally {
          this.probing = 0;
        }
      };
    }

    return shell;
  };
  window.app.__relayProbeBooted = true;
}
