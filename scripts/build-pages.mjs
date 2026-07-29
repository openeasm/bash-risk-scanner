import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const reportsRoot = resolve(repositoryRoot, "reports");
const corpusRoot = resolve(repositoryRoot, "evaluation/corpus");
const manifest = JSON.parse(await readFile(resolve(corpusRoot, "manifest.json"), "utf8"));
const evaluation = JSON.parse(await readFile(
  resolve(repositoryRoot, "evaluation/results/latest.json"),
  "utf8",
));
const atomicCoverage = JSON.parse(await readFile(
  resolve(repositoryRoot, "evaluation/results/atomic-coverage.json"),
  "utf8",
));
const resultsById = new Map(evaluation.samples.map((sample) => [sample.id, sample]));

function safeCorpusPath(relativePath) {
  const absolutePath = resolve(corpusRoot, relativePath);
  if (!absolutePath.startsWith(`${corpusRoot}${sep}`)) {
    throw new Error(`Corpus path escapes root: ${relativePath}`);
  }
  return absolutePath;
}

const cases = [];
for (const sample of manifest.samples) {
  const result = resultsById.get(sample.id);
  if (!result) throw new Error(`Missing evaluation result for ${sample.id}`);
  cases.push({
    id: sample.id,
    split: result.split,
    language: sample.language,
    kind: sample.kind,
    sourceFile: sample.sourceFile,
    source: await readFile(safeCorpusPath(sample.sourceFile), "utf8"),
    provenance: result.provenance,
    passed: result.passed,
    expectedCategories: result.expectedCategories,
    actualCategories: result.actualCategories,
    falsePositives: result.falsePositives,
    falseNegatives: result.falseNegatives,
    expectedDecision: result.expectedDecision,
    actualDecision: result.actualDecision,
    decisionMatched: result.decisionMatched,
    parseErrorCount: result.parseErrorCount,
    actualFindings: result.actualFindings,
    missingExpectedFindings: result.missingExpectedFindings,
    forbiddenFindings: result.forbiddenFindings,
  });
}

await mkdir(resolve(reportsRoot, "data"), { recursive: true });
await writeFile(
  resolve(reportsRoot, "data/corpus-cases.json"),
  `${JSON.stringify({
    schemaVersion: 1,
    generatedAt: evaluation.generatedAt,
    count: cases.length,
    cases,
  })}\n`,
);
await writeFile(
  resolve(reportsRoot, "data/evaluation.json"),
  `${JSON.stringify(evaluation)}\n`,
);
await writeFile(
  resolve(reportsRoot, "data/atomic-coverage.json"),
  `${JSON.stringify(atomicCoverage)}\n`,
);
await writeFile(resolve(reportsRoot, ".nojekyll"), "");

console.log(`GitHub Pages data: ${cases.length} corpus cases`);
