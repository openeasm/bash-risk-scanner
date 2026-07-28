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
  {
    target: "pipx/standalone_python.py.txt",
    url: "https://raw.githubusercontent.com/pypa/pipx/d57b062260b62dee083117c7b15c36d15450ed47/src/pipx/standalone_python.py",
    sha256: "68866dc10a2667777049eefcf5b9d5280ecfca436be6f233b26eac9e7df32028",
  },
  {
    target: "pipx/LICENSE",
    url: "https://raw.githubusercontent.com/pypa/pipx/d57b062260b62dee083117c7b15c36d15450ed47/LICENSE",
    sha256: "2e142cbef6acf436d47d8fe1412439c442eeb6c48d5ef73d6b91fffbbf1cdf89",
  },
  {
    target: "pnpm-self-installer/installTo.js.txt",
    url: "https://raw.githubusercontent.com/pnpm/self-installer/9c3348754cfd49b24df846bffb44a90244f1c2dd/src/installTo.js",
    sha256: "168c44087c82f6a76c34359f655a0887fd9d82ebdcccfdfbd5b8ea18cab04f7c",
  },
  {
    target: "pnpm-self-installer/LICENSE",
    url: "https://raw.githubusercontent.com/pnpm/self-installer/9c3348754cfd49b24df846bffb44a90244f1c2dd/LICENSE",
    sha256: "de1835a8b19015964f1ceeb31f66876eb0590fc8742816da3ba39171666d2859",
  },
  {
    target: "atomic-red-team/client.py.txt",
    url: "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/1ba1dd8d9ce6f74700f7aec2e60de5632f667f03/atomics/T1071/src/client.py",
    sha256: "432f729fe9111b2f2ac195332b7e77f76a0216948952c6deb459a0ff8d1d9c11",
  },
  {
    target: "atomic-red-team/LICENSE.txt",
    url: "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/1ba1dd8d9ce6f74700f7aec2e60de5632f667f03/LICENSE.txt",
    sha256: "65af6027045d23175366eab50e460ab3ee7790e591cb84cc32c78ac63a4c90e1",
  },
  {
    target: "node-gyp/install.js.txt",
    url: "https://raw.githubusercontent.com/nodejs/node-gyp/42367da5a2683115ff538b92caed5c32c322005f/lib/install.js",
    sha256: "f0a0017fec48692a8eb8922b6eaff8d12f4a4eb1af4e42f23efa3e8797dff2c3",
  },
  {
    target: "node-gyp/LICENSE",
    url: "https://raw.githubusercontent.com/nodejs/node-gyp/42367da5a2683115ff538b92caed5c32c322005f/LICENSE",
    sha256: "662a1b0115251cfb29c6aed0f221f8847bc49c6365d1c53a62c9f4bccc2489c3",
  },
  {
    target: "aiohttp/curl.py.txt",
    url: "https://raw.githubusercontent.com/aio-libs/aiohttp/c3f07fcf858bc1ac328345d717c2fa7e22b31801/examples/curl.py",
    sha256: "9edea06311c326eddad6ff86d4ce077c95945fba17404d44dfde613844514202",
  },
  {
    target: "aiohttp/LICENSE.txt",
    url: "https://raw.githubusercontent.com/aio-libs/aiohttp/c3f07fcf858bc1ac328345d717c2fa7e22b31801/LICENSE.txt",
    sha256: "2e4be5fc6c4c72a466fcb665d726e049a6891981fe536c4f04b6366749461d23",
  },
  {
    target: "pacote/remote.js.txt",
    url: "https://raw.githubusercontent.com/npm/pacote/c82bdcdd8010a9a87c95e1e09b0ba51322b4f93f/lib/remote.js",
    sha256: "d4843de4eec468b75632de2f431eb769a333dbd345b1b294f57a4a9eb077192c",
  },
  {
    target: "pacote/LICENSE",
    url: "https://raw.githubusercontent.com/npm/pacote/c82bdcdd8010a9a87c95e1e09b0ba51322b4f93f/LICENSE",
    sha256: "36ec394cd0f976603cfec687c19175a703c1c0d9db717a76915391e756522c8e",
  },
];

async function download(url) {
  let lastError;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const response = await fetch(url, {
        headers: { "user-agent": "bash-risk-scanner-corpus-importer" },
        signal: AbortSignal.timeout(15_000),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return Buffer.from(await response.arrayBuffer());
    } catch (error) {
      lastError = error;
      if (attempt < 3) await new Promise((resolveRetry) => setTimeout(resolveRetry, 500 * attempt));
    }
  }
  throw new Error(`Failed to download ${url}: ${lastError instanceof Error ? lastError.message : lastError}`);
}

for (const snapshot of snapshots) {
  const content = await download(snapshot.url);
  const actualSha256 = createHash("sha256").update(content).digest("hex");
  if (actualSha256 !== snapshot.sha256) {
    throw new Error(`SHA-256 mismatch for ${snapshot.target}: ${actualSha256}`);
  }
  const target = resolve(publicCorpusRoot, snapshot.target);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, content);
  console.log(`${snapshot.target} ${actualSha256}`);
}
