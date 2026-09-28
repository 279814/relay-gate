/* count_tokens.mjs — per-station count_tokens posture (§10).
 *
 * Source of truth is /health `routes[].count_tokens`, the same effective
 * Capability the proxy reads when choosing a count_tokens Route. A station
 * whose Routes disagree is shown as mixed with per-state counts; never
 * collapsed to a single state. Pure text (x-text). Does not modify app.js.
 */

const STATE_ORDER = ['supported', 'unsupported', 'config_error', 'transient_error', 'unknown'];

export function countTokensClass(state) {
  if (state === 'supported') return 'ok';
  if (state === 'unsupported' || state === 'config_error') return 'err';
  if (state === 'transient_error' || state === 'mixed') return 'warn';
  return 'unknown';
}

/**
 * @param {Array<object>} routes /health routes rows
 * @param {number} upstreamID
 * @returns {{state: string, text: string, counts: object, detail: string, routes: Array<{route_id:number, model:string, state:string}>}}
 */
export function summarizeCountTokens(routes, upstreamID) {
  const mine = (routes || []).filter((r) => r && r.upstream_id === upstreamID);
  const list = mine.map((r) => ({
    route_id: r.route_id,
    model: r.model_name || `#${r.model_name_id}`,
    state: r.count_tokens || '',
  }));
  if (!list.length) {
    return { state: 'none', text: '无路由', counts: {}, detail: '', routes: list };
  }
  if (list.some((x) => !x.state)) {
    return { state: 'na', text: '—', counts: {}, detail: '后端未提供 count_tokens 能力', routes: list };
  }
  const counts = {};
  for (const x of list) counts[x.state] = (counts[x.state] || 0) + 1;
  const states = Object.keys(counts).sort(
    (a, b) => STATE_ORDER.indexOf(a) - STATE_ORDER.indexOf(b),
  );
  const detail = list.map((x) => `${x.model} (#${x.route_id}): ${x.state}`).join('\n');
  if (states.length === 1) {
    return { state: states[0], text: states[0], counts, detail, routes: list };
  }
  const text = 'mixed: ' + states.map((s) => `${counts[s]} ${s}`).join(' / ');
  return { state: 'mixed', text, counts, detail, routes: list };
}

export function createCountTokensFeature(shell) {
  shell.countTokensPosture = function countTokensPosture(upstreamID) {
    const sum = summarizeCountTokens((this.health && this.health.routes) || [], upstreamID);
    if (sum.state === 'none' && (this.routes || []).some((r) => r.upstream_id === upstreamID)) {
      return { state: 'na', text: '—', counts: {}, detail: '健康看板未加载', routes: [] };
    }
    return sum;
  };
  shell.countTokensClass = countTokensClass;
}
