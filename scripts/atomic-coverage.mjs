import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const evaluationRoot = resolve(repositoryRoot, "evaluation");
const inventory = JSON.parse(await readFile(
  resolve(evaluationRoot, "atomic-red-team/inventory.json"),
  "utf8",
));
const manifest = JSON.parse(await readFile(
  resolve(evaluationRoot, "corpus/manifest.json"),
  "utf8",
));
const expectedCommit = "1ba1dd8d9ce6f74700f7aec2e60de5632f667f03";
if (inventory.source?.commit !== expectedCommit) {
  throw new Error(`Unexpected Atomic inventory commit: ${inventory.source?.commit}`);
}
if (inventory.tests.length !== inventory.testCount || inventory.testCount !== 1817) {
  throw new Error(`Unexpected Atomic inventory size: ${inventory.tests.length}`);
}

const textualExecutors = new Set(["bash", "sh", "powershell", "command_prompt"]);
const importedSamples = manifest.samples.filter(
  (sample) => sample.provenance?.repository === "redcanaryco/atomic-red-team",
);
const declaredUpstreamIds = new Set(
  importedSamples.map((sample) => sample.provenance?.upstreamId).filter(Boolean),
);
const importedGuids = new Set(
  [...declaredUpstreamIds].filter((value) =>
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value),
  ),
);
const inventoryGuids = new Set(inventory.tests.map((test) => test.guid));
const unmatchedImportedIds = [...declaredUpstreamIds]
  .filter((identifier) => !inventoryGuids.has(identifier))
  .sort();
const targets = inventory.tests.filter(
  (test) =>
    textualExecutors.has(test.executor)
    && test.platforms.some((platform) => platform === "windows" || platform === "macos"),
);
const coveredTargets = targets.filter((test) => importedGuids.has(test.guid));
const gaps = targets.filter((test) => !importedGuids.has(test.guid));

function platformStats(platform) {
  const all = inventory.tests.filter((test) => test.platforms.includes(platform));
  const textual = all.filter((test) => textualExecutors.has(test.executor));
  const covered = textual.filter((test) => importedGuids.has(test.guid));
  return {
    allTests: all.length,
    commandTests: textual.length,
    coveredTests: covered.length,
    gapTests: textual.length - covered.length,
    corpusCoverage: textual.length === 0 ? 0 : covered.length / textual.length,
  };
}

function executorStats(executor) {
  const tests = targets.filter((test) => test.executor === executor);
  const covered = tests.filter((test) => importedGuids.has(test.guid));
  return {
    targetTests: tests.length,
    coveredTests: covered.length,
    gapTests: tests.length - covered.length,
    corpusCoverage: tests.length === 0 ? 0 : covered.length / tests.length,
  };
}

const report = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  source: inventory.source,
  scope: {
    platforms: ["windows", "macos"],
    executors: [...textualExecutors],
    note: "Coverage means the Atomic GUID is represented in the labeled corpus; it is not detection recall.",
  },
  inventory: {
    tests: inventory.testCount,
    techniques: new Set(inventory.tests.map((test) => test.technique)).size,
    importedSamples: importedSamples.length,
    importedUniqueGuids: importedGuids.size,
    unmatchedImportedIds,
  },
  target: {
    tests: targets.length,
    coveredTests: coveredTargets.length,
    gapTests: gaps.length,
    corpusCoverage: coveredTargets.length / targets.length,
  },
  platforms: {
    macos: platformStats("macos"),
    windows: platformStats("windows"),
  },
  executors: Object.fromEntries(
    [...textualExecutors].map((executor) => [executor, executorStats(executor)]),
  ),
  covered: coveredTargets,
  gaps,
};

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function percent(value) {
  return `${(value * 100).toFixed(1)}%`;
}

function statRow(name, stats) {
  return `<tr><td>${escapeHtml(name)}</td><td>${stats.allTests ?? stats.targetTests}</td>
<td>${stats.commandTests ?? stats.targetTests}</td><td>${stats.coveredTests}</td>
<td>${stats.gapTests}</td><td>${percent(stats.corpusCoverage)}</td></tr>`;
}

const html = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Atomic Red Team 覆盖矩阵</title><style>
body{max-width:1280px;margin:32px auto;padding:0 16px;font:15px/1.55 system-ui;color:#18212b}
h1,h2{line-height:1.25}.cards{display:flex;gap:12px;flex-wrap:wrap}.card{border:1px solid #d7dee5;
border-radius:10px;padding:14px;min-width:160px}.big{font-size:26px;font-weight:750}
table{width:100%;border-collapse:collapse;margin:14px 0}th,td{border:1px solid #d7dee5;
padding:8px;text-align:left}th{background:#edf3f7}code{background:#edf1f4;padding:2px 4px;
border-radius:3px}.muted{color:#607080}.warning{border-left:4px solid #d9822b;padding-left:12px}
</style></head><body>
<h1>Atomic Red Team Windows / macOS 语料覆盖</h1>
<p class="warning"><strong>口径：</strong>覆盖表示 Atomic GUID 已进入人工标注语料，
不是扫描器对未标注测试的检出率。</p>
<div class="cards">
<div class="card"><div class="big">${report.inventory.tests}</div>Atomic 全部测试</div>
<div class="card"><div class="big">${report.target.tests}</div>Windows/macOS 命令型目标</div>
<div class="card"><div class="big">${report.target.coveredTests}</div>已纳入目标 GUID</div>
<div class="card"><div class="big">${percent(report.target.corpusCoverage)}</div>目标语料覆盖率</div>
<div class="card"><div class="big">${report.target.gapTests}</div>待纳入目标</div>
</div>
<h2>按平台</h2>
<table><thead><tr><th>平台</th><th>全部测试</th><th>命令型目标</th><th>已纳入</th><th>缺口</th><th>语料覆盖率</th></tr></thead><tbody>
${statRow("macOS", report.platforms.macos)}
${statRow("Windows", report.platforms.windows)}
</tbody></table>
<h2>按执行器</h2>
<table><thead><tr><th>执行器</th><th>目标测试</th><th>命令型目标</th><th>已纳入</th><th>缺口</th><th>语料覆盖率</th></tr></thead><tbody>
${Object.entries(report.executors).map(([name, stats]) => statRow(name, stats)).join("\n")}
</tbody></table>
<h2>当前已纳入的目标 GUID</h2>
<table><thead><tr><th>GUID</th><th>Technique</th><th>平台</th><th>执行器</th><th>名称</th></tr></thead><tbody>
${report.covered.map((test) => `<tr><td><code>${escapeHtml(test.guid)}</code></td><td>${escapeHtml(test.technique)}</td><td>${escapeHtml(test.platforms.join(", "))}</td><td>${escapeHtml(test.executor)}</td><td>${escapeHtml(test.name)}</td></tr>`).join("\n")}
</tbody></table>
<h2>待纳入目标</h2>
<table><thead><tr><th>GUID</th><th>Technique</th><th>平台</th><th>执行器</th><th>名称</th></tr></thead><tbody>
${report.gaps.map((test) => `<tr><td><code>${escapeHtml(test.guid)}</code></td><td>${escapeHtml(test.technique)}</td><td>${escapeHtml(test.platforms.join(", "))}</td><td>${escapeHtml(test.executor)}</td><td>${escapeHtml(test.name)}</td></tr>`).join("\n")}
</tbody></table>
<p class="muted">固定上游 commit：<code>${escapeHtml(report.source.commit)}</code>；
生成时间：${escapeHtml(report.generatedAt)}。</p>
</body></html>`;

await mkdir(resolve(evaluationRoot, "results"), { recursive: true });
await mkdir(resolve(repositoryRoot, "reports"), { recursive: true });
await writeFile(
  resolve(evaluationRoot, "results/atomic-coverage.json"),
  `${JSON.stringify(report, null, 2)}\n`,
);
await writeFile(resolve(repositoryRoot, "reports/atomic-coverage.html"), html);

console.log(`Atomic tests: ${report.inventory.tests}`);
console.log(`Windows/macOS command targets: ${report.target.tests}`);
console.log(`Covered target GUIDs: ${report.target.coveredTests}`);
console.log(`Corpus coverage: ${percent(report.target.corpusCoverage)}`);
console.log(`macOS: ${report.platforms.macos.coveredTests}/${report.platforms.macos.commandTests}`);
console.log(`Windows: ${report.platforms.windows.coveredTests}/${report.platforms.windows.commandTests}`);
