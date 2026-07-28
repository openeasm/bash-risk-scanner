import { mkdir, readFile, writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { dirname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { scan } from "../dist/index.js";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const evaluationRoot = resolve(repositoryRoot, "evaluation");
const corpusRoot = resolve(evaluationRoot, "corpus");
const resultsRoot = resolve(evaluationRoot, "results");
const reportsRoot = resolve(repositoryRoot, "reports");

const manifest = JSON.parse(await readFile(resolve(corpusRoot, "manifest.json"), "utf8"));
const config = JSON.parse(await readFile(resolve(evaluationRoot, "config.json"), "utf8"));

function safeSamplePath(relativePath) {
  const absolutePath = resolve(corpusRoot, relativePath);
  if (!absolutePath.startsWith(`${corpusRoot}${sep}`)) {
    throw new Error(`Sample path escapes corpus root: ${relativePath}`);
  }
  return absolutePath;
}

function ratio(numerator, denominator) {
  return denominator === 0 ? 1 : numerator / denominator;
}

function percentile(values, value) {
  if (values.length === 0) return 0;
  const ordered = [...values].sort((a, b) => a - b);
  return ordered[Math.min(ordered.length - 1, Math.ceil(value * ordered.length) - 1)];
}

function metricFromCounts(counts) {
  const precision = ratio(counts.tp, counts.tp + counts.fp);
  const recall = ratio(counts.tp, counts.tp + counts.fn);
  return {
    ...counts,
    precision,
    recall,
    f1: precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall),
  };
}

function emptyCounts() {
  return { tp: 0, fp: 0, fn: 0 };
}

const sampleResults = [];
for (const sample of manifest.samples) {
  const source = await readFile(safeSamplePath(sample.sourceFile), "utf8");
  const started = performance.now();
  const result = scan(source, { language: sample.language });
  const durationMilliseconds = performance.now() - started;
  const actual = [...new Set(result.findings.map((finding) => finding.category))].sort();
  const expected = [...new Set(sample.expectedCategories)].sort();
  const truePositives = expected.filter((category) => actual.includes(category));
  const falseNegatives = expected.filter((category) => !actual.includes(category));
  const falsePositives = actual.filter((category) => !expected.includes(category));

  sampleResults.push({
    id: sample.id,
    language: sample.language,
    kind: sample.kind,
    sourceFile: sample.sourceFile,
    expectedCategories: expected,
    actualCategories: actual,
    truePositives,
    falsePositives,
    falseNegatives,
    findingCount: result.findings.length,
    parseErrorCount: result.parseErrors.length,
    durationMilliseconds,
    passed: falsePositives.length === 0 && falseNegatives.length === 0
      && result.parseErrors.length === 0,
  });
}

function aggregate(results) {
  const counts = emptyCounts();
  for (const result of results) {
    counts.tp += result.truePositives.length;
    counts.fp += result.falsePositives.length;
    counts.fn += result.falseNegatives.length;
  }
  return metricFromCounts(counts);
}

const languages = {};
for (const language of ["bash", "python", "node"]) {
  languages[language] = aggregate(sampleResults.filter((sample) => sample.language === language));
}

const allCategories = [...new Set(sampleResults.flatMap((sample) => [
  ...sample.expectedCategories,
  ...sample.actualCategories,
]))].sort();
const categories = {};
for (const category of allCategories) {
  const counts = emptyCounts();
  for (const sample of sampleResults) {
    const expected = sample.expectedCategories.includes(category);
    const actual = sample.actualCategories.includes(category);
    if (expected && actual) counts.tp++;
    if (!expected && actual) counts.fp++;
    if (expected && !actual) counts.fn++;
  }
  categories[category] = metricFromCounts(counts);
}

const durations = sampleResults.map((sample) => sample.durationMilliseconds);
const parseErrorSamples = sampleResults.filter((sample) => sample.parseErrorCount > 0).length;
const overall = aggregate(sampleResults);
const summary = {
  sampleCount: sampleResults.length,
  passedSamples: sampleResults.filter((sample) => sample.passed).length,
  failedSamples: sampleResults.filter((sample) => !sample.passed).length,
  ...overall,
  parseErrorRate: ratio(parseErrorSamples, sampleResults.length),
  performance: {
    p50Milliseconds: percentile(durations, 0.5),
    p95Milliseconds: percentile(durations, 0.95),
    maximumMilliseconds: Math.max(...durations, 0),
  },
};

const gates = {
  precision: summary.precision >= config.minimum.precision,
  recall: summary.recall >= config.minimum.recall,
  parseErrorRate: summary.parseErrorRate <= config.maximum.parseErrorRate,
  p95Milliseconds: summary.performance.p95Milliseconds <= config.maximum.p95Milliseconds,
  samples: summary.failedSamples === 0,
};
const passed = Object.values(gates).every(Boolean);
const report = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  corpus: {
    manifest: "evaluation/corpus/manifest.json",
    schemaVersion: manifest.schemaVersion,
    description: manifest.description,
    provenance: manifest.provenance,
  },
  thresholds: config,
  passed,
  gates,
  summary,
  languages,
  categories,
  samples: sampleResults,
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

function metricRows(entries) {
  return entries.map(([name, metric]) => `<tr>
    <td>${escapeHtml(name)}</td><td>${metric.tp}</td><td>${metric.fp}</td><td>${metric.fn}</td>
    <td>${percent(metric.precision)}</td><td>${percent(metric.recall)}</td><td>${percent(metric.f1)}</td>
  </tr>`).join("\n");
}

const failures = sampleResults.filter((sample) => !sample.passed);
const html = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>真实世界种子语料评测</title><style>
body{max-width:1180px;margin:32px auto;padding:0 16px;font:15px/1.55 system-ui;color:#18212b}
h1,h2{line-height:1.25}.pass{color:#08783e}.fail{color:#b42318}.cards{display:flex;gap:12px;flex-wrap:wrap}
.card{border:1px solid #d7dee5;border-radius:10px;padding:14px;min-width:150px}
.big{font-size:26px;font-weight:750}table{width:100%;border-collapse:collapse;margin:14px 0}
th,td{border:1px solid #d7dee5;padding:8px;text-align:left}th{background:#edf3f7}
code{background:#edf1f4;padding:2px 4px;border-radius:3px}.muted{color:#607080}
</style></head><body>
<h1>真实世界种子语料评测</h1>
<p class="${passed ? "pass" : "fail"}"><strong>${passed ? "门禁通过" : "门禁失败"}</strong></p>
<div class="cards">
<div class="card"><div class="big">${summary.passedSamples}/${summary.sampleCount}</div>样本通过</div>
<div class="card"><div class="big">${percent(summary.precision)}</div>Precision</div>
<div class="card"><div class="big">${percent(summary.recall)}</div>Recall</div>
<div class="card"><div class="big">${percent(summary.f1)}</div>F1</div>
<div class="card"><div class="big">${summary.performance.p95Milliseconds.toFixed(2)} ms</div>P95</div>
</div>
<h2>按语言</h2><table><thead><tr><th>语言</th><th>TP</th><th>FP</th><th>FN</th>
<th>Precision</th><th>Recall</th><th>F1</th></tr></thead><tbody>
${metricRows(Object.entries(languages))}</tbody></table>
<h2>按风险类别</h2><table><thead><tr><th>类别</th><th>TP</th><th>FP</th><th>FN</th>
<th>Precision</th><th>Recall</th><th>F1</th></tr></thead><tbody>
${metricRows(Object.entries(categories))}</tbody></table>
<h2>失败样本</h2>
${failures.length === 0 ? "<p class=\"pass\">无</p>" : `<table><thead><tr><th>ID</th><th>FP</th><th>FN</th><th>解析错误</th></tr></thead><tbody>
${failures.map((sample) => `<tr><td>${escapeHtml(sample.id)}</td><td>${escapeHtml(sample.falsePositives.join(", "))}</td>
<td>${escapeHtml(sample.falseNegatives.join(", "))}</td><td>${sample.parseErrorCount}</td></tr>`).join("\n")}</tbody></table>`}
<p class="muted">生成时间：${escapeHtml(report.generatedAt)}。样本只作为文本传给扫描器，评测器不执行样本。</p>
</body></html>`;

await mkdir(resultsRoot, { recursive: true });
await writeFile(resolve(resultsRoot, "latest.json"), `${JSON.stringify(report, null, 2)}\n`);
await writeFile(resolve(resultsRoot, "latest.html"), html);
await mkdir(reportsRoot, { recursive: true });
await writeFile(resolve(reportsRoot, "evaluation.html"), html);

console.log(`Corpus: ${summary.sampleCount} samples`);
console.log(`Passed: ${summary.passedSamples}/${summary.sampleCount}`);
console.log(`Precision: ${percent(summary.precision)}`);
console.log(`Recall: ${percent(summary.recall)}`);
console.log(`F1: ${percent(summary.f1)}`);
console.log(`P95: ${summary.performance.p95Milliseconds.toFixed(2)} ms`);
if (!passed) {
  console.error(`Evaluation gates failed: ${Object.entries(gates).filter(([, ok]) => !ok).map(([gate]) => gate).join(", ")}`);
  process.exitCode = 1;
}
