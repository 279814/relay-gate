/* api.mjs — 唯一业务网络出口（P0-15）。
 *
 * session boot、401 reset、CSRF/reauth 与 Probe 调用都走这里。
 * 除本模块与第三方 Alpine 外，业务 JS 不得出现 fetch/XHR/EventSource/WebSocket。
 */

/**
 * @param {{ onUnauthorized?: () => void }} hooks
 */
export function createApiClient(hooks = {}) {
  const onUnauthorized = hooks.onUnauthorized || (() => {});

  async function request(method, path, body) {
    const opt = { method, headers: {}, credentials: 'same-origin' };
    if (body !== undefined) {
      opt.headers['Content-Type'] = 'application/json';
      opt.body = JSON.stringify(body);
    }
    const r = await fetch('/admin/api' + path, opt);
    if (r.status === 401) {
      onUnauthorized();
      const e = new Error('会话已过期，请重新登录');
      e.status = 401;
      throw e;
    }
    if (r.status === 204) return null;
    const text = await r.text();
    let data = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        /* 非 JSON */
      }
    }
    if (!r.ok) {
      const e = new Error((data && (data.error || data.code)) || text || `HTTP ${r.status}`);
      e.status = r.status;
      e.data = data;
      throw e;
    }
    return data;
  }

  return {
    request,
    get: (path) => request('GET', path),
    post: (path, body) => request('POST', path, body),
    put: (path, body) => request('PUT', path, body),
    del: (path) => request('DELETE', path),
  };
}

/** 兼容 Go 默认导出字段名（PascalCase）与显式 snake_case。 */
export function field(obj, ...names) {
  if (obj == null) return undefined;
  for (const n of names) {
    if (Object.prototype.hasOwnProperty.call(obj, n) && obj[n] !== undefined) return obj[n];
  }
  return undefined;
}

/** 解析探活头 JSON；失败时带上 position 附近片段（用户 app.js hunk 的回归实现）。 */
export function parseProbeHeadersJSON(raw) {
  const text = (raw || '').trim();
  if (!text) return {};
  try {
    const headers = JSON.parse(text);
    if (headers === null || typeof headers !== 'object' || Array.isArray(headers)) {
      throw new Error('探活头必须是 JSON 对象');
    }
    return headers;
  } catch (e) {
    let msg = e.message || String(e);
    const m = String(e.message || '').match(/position (\d+)/i);
    if (m) {
      const pos = Number(m[1]);
      const near = text.slice(Math.max(0, pos - 40), pos + 20);
      msg += `（出错位置附近：…${near}…）` +
        '。常见原因：某个头的值里带了真正的换行/回车，JSON 字符串内不允许。' +
        '请把值改成单行；想删掉某个头就把它写成空字符串，不要写多行。';
    }
    const err = new Error('探活头不是合法 JSON：' + msg);
    err.cause = e;
    throw err;
  }
}
