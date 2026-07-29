import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outputPath = resolve(
  repositoryRoot,
  "evaluation/atomic-red-team/inventory.json",
);
const sourceRepository = "https://github.com/redcanaryco/atomic-red-team.git";
const sourceCommit = "1ba1dd8d9ce6f74700f7aec2e60de5632f667f03";
const temporaryRoot = await mkdtemp(join(tmpdir(), "atomic-inventory-"));
const checkoutRoot = join(temporaryRoot, "atomic-red-team");

function git(...args) {
  execFileSync("git", args, {
    cwd: checkoutRoot,
    stdio: ["ignore", "ignore", "inherit"],
  });
}

try {
  await mkdir(checkoutRoot);
  git("init", "--quiet");
  git("remote", "add", "origin", sourceRepository);
  git("config", "core.sparseCheckout", "true");
  await mkdir(join(checkoutRoot, ".git/info"), { recursive: true });
  await writeFile(
    join(checkoutRoot, ".git/info/sparse-checkout"),
    "atomics/T*/*.yaml\n",
  );
  git("fetch", "--quiet", "--depth=1", "origin", sourceCommit);
  git("checkout", "--quiet", "--detach", "FETCH_HEAD");

  const atomicsRoot = join(checkoutRoot, "atomics");
  const techniqueDirectories = (await readdir(atomicsRoot, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory() && /^T\d/.test(entry.name))
    .map((entry) => entry.name)
    .sort();
  const tests = [];

  for (const techniqueDirectory of techniqueDirectories) {
    const yamlPath = join(
      atomicsRoot,
      techniqueDirectory,
      `${techniqueDirectory}.yaml`,
    );
    const document = parse(await readFile(yamlPath, "utf8"));
    for (const test of document.atomic_tests ?? []) {
      tests.push({
        guid: test.auto_generated_guid,
        technique: document.attack_technique,
        name: test.name,
        platforms: [...(test.supported_platforms ?? [])].sort(),
        executor: test.executor?.name ?? "unknown",
      });
    }
  }

  tests.sort((left, right) =>
    left.technique.localeCompare(right.technique)
    || left.guid.localeCompare(right.guid),
  );
  const inventory = {
    schemaVersion: 1,
    source: {
      repository: "redcanaryco/atomic-red-team",
      commit: sourceCommit,
      url: `https://github.com/redcanaryco/atomic-red-team/tree/${sourceCommit}/atomics`,
      license: "MIT",
    },
    testCount: tests.length,
    tests,
  };
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(inventory, null, 2)}\n`);
  console.log(`Atomic inventory: ${tests.length} tests`);
  console.log(`Wrote: ${outputPath}`);
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
