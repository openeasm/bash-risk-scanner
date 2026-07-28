import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const publicCorpusRoot = resolve(repositoryRoot, "evaluation", "corpus", "public");

const snapshots = [
  {
    target: "nvm/install.sh.txt",
    url: "https://raw.githubusercontent.com/nvm-sh/nvm/65ded65d46c16481dbbe8e93f8ba9e6b35f20740/install.sh",
    sha256: "b5f8ba6dcc759c1c58c027f07e439bb18afb0a8f16525470364d401a9471eb54",
  },
  {
    target: "nvm/LICENSE.md",
    url: "https://raw.githubusercontent.com/nvm-sh/nvm/65ded65d46c16481dbbe8e93f8ba9e6b35f20740/LICENSE.md",
    sha256: "681a12d1a1367b5890be9bc71a70466633d28fd32397be9b72d69d9bfb243492",
  },
  {
    target: "homebrew-install/install.sh.txt",
    url: "https://raw.githubusercontent.com/Homebrew/install/ca0130bd52235f2fcb2bf23cfdda004bc5d250c1/install.sh",
    sha256: "8ff338091a5e10bb5fc040b38316648110f42feff057ecf9feaab51fd0a13ef9",
  },
  {
    target: "homebrew-install/LICENSE.txt",
    url: "https://raw.githubusercontent.com/Homebrew/install/ca0130bd52235f2fcb2bf23cfdda004bc5d250c1/LICENSE.txt",
    sha256: "f80329e58613ad669c0e73cb132d8060b9b2c55e339c73848068e4d1567f4627",
  },
];

for (const snapshot of snapshots) {
  const response = await fetch(snapshot.url, {
    headers: { "user-agent": "bash-risk-scanner-corpus-importer" },
  });
  if (!response.ok) throw new Error(`Failed to download ${snapshot.url}: HTTP ${response.status}`);
  const content = Buffer.from(await response.arrayBuffer());
  const actualSha256 = createHash("sha256").update(content).digest("hex");
  if (actualSha256 !== snapshot.sha256) {
    throw new Error(`SHA-256 mismatch for ${snapshot.target}: ${actualSha256}`);
  }
  const target = resolve(publicCorpusRoot, snapshot.target);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, content);
  console.log(`${snapshot.target} ${actualSha256}`);
}
