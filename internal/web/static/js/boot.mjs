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
import { createCountTokensFeature } from './count_tokens.mjs';
import { createRecipeAdminFeature } from './recipe_admin.mjs';
import { createSettingsFeature } from './settings.mjs';

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
      createCountTokensFeature(shell);
      createRecipeAdminFeature(shell, api);
      createSettingsFeature(shell, api);
      shell.probeModuleReady = true;
    } catch (e) {
      shell.probeModuleReady = false;
      shell.probeModuleError = 'Probe 模块加载失败：' + (e && e.message ? e.message : e);
      console.error(shell.probeModuleError, e);
    }

    // Alpine 把 shell 包成响应式代理后才调用这些方法：原方法必须以调用方的
    // this（代理）执行。bind(shell) 会写到原始对象上，tab / health 等改动不触发渲染。
    const origBoot = shell.boot;
    shell.boot = async function boot() {
      if (!this.probeModuleReady && this.probeModuleError) {
        this.err = this.probeModuleError;
      }
      if (origBoot) await origBoot.call(this);
      if (this.authed && this.probeModuleReady) {
        try {
          const st = await api.get('/state');
          this.applyStatePayload(st);
        } catch {
          /* state 可选 */
        }
      }
    };

    const origLoadAll = shell.loadAll;
    if (origLoadAll) {
      shell.loadAll = async function loadAll() {
        await origLoadAll.call(this);
        try {
          const st = await api.get('/state');
          this.applyStatePayload(st);
        } catch { /* */ }
        if (this.probeModuleReady) await this.refreshHealthSide();
        if (typeof this.refreshRecentErrors === 'function') await this.refreshRecentErrors();
      };
    }

    const origLoadHealth = shell.loadHealth;
    if (origLoadHealth) {
      shell.loadHealth = async function loadHealth() {
        await origLoadHealth.call(this);
        if (this.probeModuleReady) await this.refreshHealthSide();
        if (typeof this.refreshRecentErrors === 'function') await this.refreshRecentErrors();
      };
    }

    const origGo = shell.go;
    shell.go = function go(tab) {
      if (origGo) origGo.call(this, tab);
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
      } else if (tab === 'client-profiles') {
        this.loadProfiles(true);
      } else if (tab === 'credentials') {
        this.loadCredentials();
      } else if (tab === 'security') {
        this.loadSecurityFindings();
        this.loadSMTP();
      } else if (tab === 'transforms') {
        this.loadTransforms();
      } else if (tab === 'health') {
        this.refreshHealthSide();
      } else if (tab === 'upstreams') {
        this.loadHealth();
      }
    };

    // Upstream 编辑：补 Active/Lazy、Host Override、TLS Server Name；探活头走 position 提示。
    const origEditUp = shell.editUp;
    if (origEditUp) {
      shell.editUp = function editUp(u) {
        origEditUp.call(this, u);
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

    const origSaveUp = shell.saveUp;
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
            return await origSaveUp.call(this);
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
