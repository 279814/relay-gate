/* 交叉核对 index.html 里的 Alpine 绑定与 app.js 的实际定义。
 *
 * 为什么需要：Alpine 对不存在的属性是**静默渲染空白**的，对不存在的
 * 方法则是在点击时才抛错到控制台。拼错一个名字（sampleFilter → sampleFiter）
 * 不会有任何编译期或加载期的提示 —— 界面上就是一处空白或一个不响应的按钮。
 *
 * 864 行 HTML 靠肉眼比对不现实，这个脚本把它变成一次运行。
 *
 * ── 它检查什么，不检查什么 ──
 *
 * 查得到：顶层标识符拼错（sampleFilter → sampleFiter）、调用不存在的
 * 方法（probe → probeRoute）。这两类会让整块内容空白或按钮不响应。
 *
 * **查不到：属性访问拼错**（upForm.api_key_masked → upForm.api_key_maskd）。
 * 那需要知道每个对象在运行时的形状，而 upForm 之类是动态构造的。
 * 这类错误的表现是「某一个字段显示为空」，比整块空白隐蔽，但影响也小。
 * 靠端到端过一遍界面覆盖它。
 *
 * 跑法：node internal/web/bindings.check.js
 */

const fs = require('fs');
const path = require('path');

const dir = path.join(__dirname, 'static');
const html = fs.readFileSync(path.join(dir, 'index.html'), 'utf8');
const js = fs.readFileSync(path.join(dir, 'app.js'), 'utf8');

// eslint-disable-next-line no-eval
eval(js);
const inst = app();
const known = new Set(Object.keys(inst));

// Alpine 自己提供的魔法属性与全局，不该算作缺失。
const builtins = new Set([
  '$watch', '$el', '$refs', '$store', '$dispatch', '$nextTick', '$root', '$data', '$id',
  'true', 'false', 'null', 'undefined', 'JSON', 'Object', 'Math', 'Date', 'String',
  'Number', 'Array', 'confirm', 'window', 'console',
  // x-for 引入的循环变量
  'r', 'u', 'm', 's', 't', 'rc', 'uc', 'c', 'e', 'i', 'v', 'n', 'x', 'p', 'k', 'd',
]);

/* 抽出所有 Alpine 指令的表达式。
 *
 * 只取指令属性的值，不去解析整份 HTML —— 那需要一个真的解析器，
 * 而这里要的只是「表达式里出现过哪些顶层标识符」。
 */
const exprs = [];
const directive = /(?:x-(?:text|show|if|for|model(?:\.\w+)*|html|init|bind)?|@[\w.]+|:[\w-]+)\s*=\s*"([^"]*)"/g;
let mm;
while ((mm = directive.exec(html)) !== null) exprs.push(mm[1]);

/* 从表达式里取顶层标识符。
 *
 * 规则：一个标识符若紧跟在 `.` 后面，它是属性访问（obj.field），不是
 * 组件的顶层名字，跳过。字符串字面量先剔掉，免得把内容当成标识符。
 */
const missing = new Map();
for (const raw of exprs) {
  const e = raw
    .replace(/'[^']*'/g, "''")
    .replace(/`[^`]*`/g, '``')
    .replace(/"[^"]*"/g, '""');
  const idRe = /(\.\s*)?\b([A-Za-z_$][\w$]*)\b/g;
  let m;
  while ((m = idRe.exec(e)) !== null) {
    if (m[1]) continue;                    // 属性访问
    const name = m[2];
    if (builtins.has(name) || known.has(name)) continue;
    // x-for 的 `in` / 对象字面量的 key 之类的关键字
    if (['in', 'of', 'let', 'const', 'typeof', 'new', 'return', 'if', 'else'].includes(name)) continue;
    // 形如 `{on: tab === t.id}` 里的 on / 类名对象的 key：后面紧跟冒号
    const after = e.slice(m.index + (m[0].length));
    if (/^\s*:/.test(after)) continue;
    if (!missing.has(name)) missing.set(name, raw.slice(0, 70));
  }
}

if (missing.size === 0) {
  console.log(`核对 ${exprs.length} 个绑定表达式：全部标识符在 app() 里有定义`);
  process.exit(0);
}

console.log(`核对 ${exprs.length} 个绑定表达式，发现 ${missing.size} 个未定义的标识符：\n`);
for (const [name, ctx] of missing) {
  console.log(`  ${name}\n      出现在: ${ctx}`);
}
console.log('\nAlpine 对这些是静默渲染空白 —— 界面上看不出错，只是那处没内容。');
process.exit(1);
