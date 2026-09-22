/* 交叉核对 index.html 里的 Alpine 绑定与 app()（含 boot 装配的 Probe 功能）的实际定义。
 *
 * 跑法：node internal/web/bindings.check.js
 */

const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const dir = path.join(__dirname, 'static');
const html = fs.readFileSync(path.join(dir, 'index.html'), 'utf8');
const js = fs.readFileSync(path.join(dir, 'app.js'), 'utf8');

// eslint-disable-next-line no-eval
eval(js);

async function main() {
  const { createApiClient } = await import(pathToFileURL(path.join(dir, 'js', 'api.mjs')).href);
  const { createProbeFeature, mergeProbeTabs } = await import(pathToFileURL(path.join(dir, 'js', 'probes.mjs')).href);
  const { createRecentErrorsFeature } = await import(pathToFileURL(path.join(dir, 'js', 'errors.mjs')).href);

  const inst = app();
  const api = createApiClient({ onUnauthorized() {} });
  createProbeFeature(inst, api);
  mergeProbeTabs(inst);
  createRecentErrorsFeature(inst, api);
  const known = new Set(Object.keys(inst));

  const builtins = new Set([
    '$watch', '$el', '$refs', '$store', '$dispatch', '$nextTick', '$root', '$data', '$id',
    'true', 'false', 'null', 'undefined', 'JSON', 'Object', 'Math', 'Date', 'String',
    'Number', 'Array', 'confirm', 'window', 'console',
    'r', 'u', 'm', 's', 't', 'rc', 'uc', 'c', 'e', 'i', 'v', 'n', 'x', 'p', 'k', 'd',
    'g', 'l', 'row', 'ep', 'ex', 'run', 'cand', 'idx',
  ]);

  const exprs = [];
  const directive = /(?:x-(?:text|show|if|for|model(?:\.\w+)*|html|init|bind)?|@[\w.]+|:[\w-]+)\s*=\s*"([^"]*)"/g;
  let mm;
  while ((mm = directive.exec(html)) !== null) exprs.push(mm[1]);

  const missing = new Map();
  for (const raw of exprs) {
    const e = raw
      .replace(/'[^']*'/g, "''")
      .replace(/`[^`]*`/g, '``')
      .replace(/"[^"]*"/g, '""');
    const idRe = /(\.\s*)?\b([A-Za-z_$][\w$]*)\b/g;
    let m;
    while ((m = idRe.exec(e)) !== null) {
      if (m[1]) continue;
      const name = m[2];
      if (builtins.has(name) || known.has(name)) continue;
      if (['in', 'of', 'let', 'const', 'typeof', 'new', 'return', 'if', 'else'].includes(name)) continue;
      const after = e.slice(m.index + (m[0].length));
      if (/^\s*:/.test(after)) continue;
      if (!missing.has(name)) missing.set(name, raw.slice(0, 70));
    }
  }

  const modelRe = /x-model(?:\.\w+)*\s*=\s*"([A-Za-z_$][\w$]*)\.([\w$]+)"/g;
  const badProps = [];
  while ((mm = modelRe.exec(html)) !== null) {
    const [, obj, prop] = mm;
    const target = inst[obj];
    if (Object.prototype.toString.call(target) !== '[object Object]') continue;
    const keys = Object.keys(target);
    if (keys.length === 0) continue;
    if (prop in target) continue;
    badProps.push({ obj, prop, keys });
  }

  if (badProps.length > 0) {
    console.log(`发现 ${badProps.length} 个 x-model 写向了不存在的属性：\n`);
    for (const { obj, prop, keys } of badProps) {
      console.log(`  ${obj}.${prop}  —— ${obj} 上没有这个字段`);
      console.log(`      它有的是: ${keys.join(', ')}`);
    }
    process.exit(1);
  }

  if (missing.size === 0) {
    console.log(`核对 ${exprs.length} 个绑定表达式（含 Probe 模块）：全部有定义`);
    process.exit(0);
  }

  console.log(`核对 ${exprs.length} 个绑定表达式，发现 ${missing.size} 个未定义的标识符：\n`);
  for (const [name, ctx] of missing) {
    console.log(`  ${name}\n      出现在: ${ctx}`);
  }
  process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
