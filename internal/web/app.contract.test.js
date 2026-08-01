/* 前端逻辑的契约测试。
 *
 * 为什么需要它：app.js 里 run() 的返回形状（{ok, data}）被 15 个调用点
 * 依赖，而漏改一处不会报错 —— 那个调用点会拿到一个**永远为真**的对象，
 * 于是失败的操作看起来成功了。JS 没有编译器帮忙查这个。
 *
 * 跑法：node internal/web/app.contract.test.js
 * 不进 CI（CI 里没有 node，且这几条断言的价值主要在改动 app.js 时）。
 * 但它比「在浏览器里点一遍」可靠得多，也快得多。
 *
 * 放在 web/ 而不是 web/static/：那个目录被 go:embed 整个打进二进制，
 * 测试文件不该跟着进去（web_test.go 的 TestEmbed_OnlyShipsWhatTheBrowserNeeds
 * 盯着这条边界）。
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

// 把 app.js 当文本读进来求值 —— 它只定义一个全局函数 app()，没有副作用。
const src = fs.readFileSync(path.join(__dirname, 'static', 'app.js'), 'utf8');
// eslint-disable-next-line no-eval
eval(src);

/* 测试登记 + 顺序执行。
 *
 * 必须 await 每个用例，两个理由 —— 都是这份骨架第一版踩过的坑：
 *
 *   1. 不 await 的话，try/catch 包不住 async 函数（拿到的是一个 pending
 *      promise，catch 永远不触发），于是**所有断言都无条件打印 ok**。
 *      第一版就是这样：跑变异验证时，失败的用例先报 ok，然后整个进程
 *      以未处理的 rejection 崩掉 —— 能发现问题纯属侥幸。
 *   2. mkApp 会覆写 global.fetch。并发跑的话，后一个用例会在前一个
 *      还在等响应时改掉它，用例之间互相干扰。
 */
const cases = [];
function t(name, fn) { cases.push([name, fn]); }

let failed = 0;
async function runAll() {
  for (const [name, fn] of cases) {
    if (name === null) { console.log(fn); continue; } // 分组标题
    try {
      await fn();
      console.log(`  ok  ${name}`);
    } catch (e) {
      failed++;
      console.log(`FAIL  ${name}\n      ${e.message}`);
    }
  }
}

// group 把标题也排进队列，否则标题会在用例之前一次性全打完。
function group(title) { cases.push([null, '\n' + title]); }

// mkApp 造一个可测的组件实例：桩掉 fetch 与 Alpine 的 $watch。
function mkApp(fetchImpl) {
  const a = app();
  a.$watch = () => {};
  global.fetch = fetchImpl;
  return a;
}

function jsonResp(status, obj) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(obj === undefined ? '' : JSON.stringify(obj)),
  });
}

group('run() 的返回契约');

t('成功时 ok 为 true，data 是 fn 的返回值', async () => {
  const a = mkApp(() => jsonResp(200, { x: 1 }));
  const r = await a.run(() => Promise.resolve('payload'));
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.data, 'payload');
});

t('失败时 ok 为 false 且错误进 err', async () => {
  const a = mkApp(() => jsonResp(400, { error: '后端说的原话' }));
  const r = await a.run(() => a.api('POST', '/x', {}));
  assert.strictEqual(r.ok, false);
  // 后端错误原文必须原样透出 —— model/validate.go 里那些话是写给人看的
  assert.strictEqual(a.err, '后端说的原话');
});

t('204 空响应算成功而不是失败', async () => {
  // 这是引入 {ok, data} 的直接原因：DELETE 回 204、api() 给 null，
  // 用「结果是否为空」当判据的话，成功的删除会被当成失败。
  const a = mkApp(() => Promise.resolve({ ok: true, status: 204, text: () => Promise.resolve('') }));
  const r = await a.run(() => a.api('DELETE', '/upstreams/1'));
  assert.strictEqual(r.ok, true, '204 应算成功');
  assert.strictEqual(r.data, null);
});

t('busy 在失败路径上也会归位', async () => {
  const a = mkApp(() => jsonResp(500, { error: 'boom' }));
  await a.run(() => a.api('GET', '/x'));
  assert.strictEqual(a.busy, false, 'busy 卡住会让界面永久禁用按钮');
});

group('api() 的错误处理');

t('401 触发 reset 并清空数据', async () => {
  const a = mkApp(() => jsonResp(401, { error: '未授权' }));
  a.authed = true;
  a.upstreams = [{ id: 1, name: 'x' }];
  a.samples = [{ id: 9 }];
  await a.run(() => a.api('GET', '/upstreams'));
  assert.strictEqual(a.authed, false, '401 应回登录页');
  // 关键：样本里有完整对话原文与代码，登出/掉线后不能留在内存里
  assert.deepStrictEqual(a.upstreams, [], '401 后应清空上游列表');
  assert.deepStrictEqual(a.samples, [], '401 后应清空样本');
});

t('错误对象带 status，供按码判断', async () => {
  const a = mkApp(() => jsonResp(503, { error: '探活未启用' }));
  try {
    await a.api('GET', '/probe-cost');
    assert.fail('应该抛错');
  } catch (e) {
    assert.strictEqual(e.status, 503, '没有 status 就只能去猜错误文案');
  }
});

t('503 不被当成真错误弹给用户', async () => {
  // 探活未启用时 /health 与 /probe-cost 回 503，那是「功能没接」
  // 不是「出错了」。早先这里按中文子串匹配，后端改一次文案就会误报。
  const a = mkApp(() => jsonResp(503, { error: '任何措辞都不该影响判断' }));
  await a.loadCost();
  assert.strictEqual(a.err, '', '503 不该弹错误');
  await a.loadHealth();
  assert.strictEqual(a.err, '', '503 不该弹错误');
});

t('非 503 的错误照常弹出', async () => {
  const a = mkApp(() => jsonResp(500, { error: '内部错误' }));
  await a.loadCost();
  assert.strictEqual(a.err, '内部错误', '真错误必须让用户看到');
});

group('reset() 的完整性');

t('reset 清掉所有数据与编辑态', async () => {
  const a = mkApp(() => jsonResp(200, {}));
  Object.assign(a, {
    authed: true, autoRefresh: true, tab: 'samples',
    upstreams: [1], modelNames: [1], routes: [1], samples: [1],
    settings: { x: 1 }, health: { routes: [1] }, cost: { cost: {} },
    upForm: {}, mnForm: {}, rtForm: {}, sample: {}, hdrExport: {}, probeResult: {},
  });
  a.reset();
  for (const k of ['upstreams', 'modelNames', 'routes', 'samples']) {
    assert.deepStrictEqual(a[k], [], `${k} 应清空`);
  }
  for (const k of ['upForm', 'mnForm', 'rtForm', 'sample', 'hdrExport', 'probeResult', 'settings']) {
    assert.strictEqual(a[k], null, `${k} 应为 null`);
  }
  assert.strictEqual(a.authed, false);
  assert.strictEqual(a.autoRefresh, false, '不关自动刷新的话，登录页会一直在后台轮询');
  assert.strictEqual(a.tab, 'health', '应回到默认页');
});

group('显示辅助');

t('unknown 不被渲染成错误色', () => {
  const a = app();
  // unknown 是乐观状态（视为可用、正常参与选路，§2.4）。
  // 标红会让人以为服务坏了 —— 而重启后所有 Route 都是 unknown。
  assert.strictEqual(a.stateClass('unknown'), 'unknown');
  assert.strictEqual(a.stateClass('alive'), 'ok');
  assert.strictEqual(a.stateClass('dead'), 'err');
});

t('client_abort 不算上游的账', () => {
  const a = app();
  assert.strictEqual(a.outcomeClass('client_abort'), 'unknown');
  assert.strictEqual(a.outcomeClass('ok'), 'ok');
  assert.strictEqual(a.outcomeClass('upstream_error'), 'err');
});

t('未执行的 L2 判据：verdictClass 对空值给中性色', () => {
  const a = app();
  assert.strictEqual(a.verdictClass(undefined), 'unknown');
  assert.strictEqual(a.verdictClass('ok'), 'ok');
  assert.strictEqual(a.verdictClass('rate_limited'), 'warn');
  assert.strictEqual(a.verdictClass('fatal'), 'err');
});

t('truncated 位标记逐位解释', () => {
  const a = app();
  assert.ok(a.truncNote(1).includes('入站'));
  assert.ok(a.truncNote(2).includes('出站'));
  assert.ok(a.truncNote(4).includes('响应'));
  const all = a.truncNote(7);
  assert.ok(all.includes('入站') && all.includes('出站') && all.includes('响应'));
  // 必须说清转发的是完整的，只有留档副本被截
  assert.ok(all.includes('完整'));
});

t('base64 body 解码', () => {
  const a = app();
  assert.strictEqual(a.b64(''), '（空）');
  const b64 = Buffer.from('{"a":1}').toString('base64');
  assert.strictEqual(a.b64(b64), '{\n  "a": 1\n}');   // JSON 会被格式化
  const plain = Buffer.from('event: ping\ndata: {}').toString('base64');
  assert.ok(a.b64(plain).includes('event: ping'));    // 非 JSON 原样
});

t('非法 UTF-8 不抛错', () => {
  // 样本 body 可能含非法 UTF-8（二进制片段、被截断的多字节字符），
  // 那正是要看的东西。解码失败是预期内的，不能让详情页整个崩掉。
  const a = app();
  const bad = Buffer.from([0xff, 0xfe, 0x00, 0x41]).toString('base64');
  const out = a.b64(bad);
  assert.strictEqual(typeof out, 'string');
  assert.ok(out.length > 0);
});

runAll().then(() => {
  console.log(failed ? `\n${failed} 条失败` : '\n全部通过');
  process.exit(failed ? 1 : 0);
});
