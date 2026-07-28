import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
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
  {
    target: "memo/_http.py.txt",
    url: "https://raw.githubusercontent.com/koaning/memo/6bd1155a5f1f9df5d3aeb3f13d6b09aeb295efc1/memo/_http.py",
    sha256: "80e01e971a33306cbf7a02561170a2daa58b09f6fa9f5b63542d1c82563deecd",
  },
  {
    target: "memo/LICENSE",
    url: "https://raw.githubusercontent.com/koaning/memo/6bd1155a5f1f9df5d3aeb3f13d6b09aeb295efc1/LICENSE",
    sha256: "2f6c90ce801765bf074f3edfe23c7439b52866c184cb0e9cffde069a7293dbd4",
  },
  {
    target: "mime-db/request.js.txt",
    url: "https://raw.githubusercontent.com/jshttp/mime-db/ba120a7f71bc8ab7d5299e88c0049063239029a7/scripts/lib/request.js",
    sha256: "eaabfded0c974d00f7a9312a23505121de5af28f7a2840a9a8bad048e0829b9c",
  },
  {
    target: "mime-db/LICENSE",
    url: "https://raw.githubusercontent.com/jshttp/mime-db/ba120a7f71bc8ab7d5299e88c0049063239029a7/LICENSE",
    sha256: "cc1dfd4dafa27271e8212cd3b274eeb3f262e40a6fdab36ddc3f9696f706f58b",
  },
  {
    target: "twine/auth.py.txt",
    url: "https://raw.githubusercontent.com/pypa/twine/e72703b10f5e97b0b87c436500527ba8369cfa52/twine/auth.py",
    sha256: "638a8beb059a8e0328567d73dd2bd918b9da15a6ad77281b2f354a01fd0a7ccb",
  },
  {
    target: "twine/LICENSE",
    url: "https://raw.githubusercontent.com/pypa/twine/e72703b10f5e97b0b87c436500527ba8369cfa52/LICENSE",
    sha256: "14ed54990120efea26042269885df36e1b53db858bf04b40c8cfc8c5e12f6fb1",
  },
  {
    target: "mqtt/esbuild.js.txt",
    url: "https://raw.githubusercontent.com/mqttjs/MQTT.js/6e3a676630a68e6355a94d99a82d1433b486c300/esbuild.js",
    sha256: "9d3b836c96a89e1cdf983275f21889d7768f30fdcb27c3d10c98dfa9326cc4a1",
  },
  {
    target: "mqtt/LICENSE.md",
    url: "https://raw.githubusercontent.com/mqttjs/MQTT.js/6e3a676630a68e6355a94d99a82d1433b486c300/LICENSE.md",
    sha256: "81b51ef8ac2a8ac8f111ed34ab1a32d63e7f4f7de586bd65f5510fb1ba3a89eb",
  },
  {
    target: "adafruit-retrogame/retrogame.py.txt",
    url: "https://raw.githubusercontent.com/adafruit/Raspberry-Pi-Installer-Scripts/85c3e7697fc970275215a8a27953b36c16f9b074/retrogame.py",
    sha256: "dad3a969b9df0eab2b3f401f8eb6b00c77d929749f32ee29c333e15f64377925",
  },
  {
    target: "adafruit-retrogame/LICENSE.txt",
    url: "https://raw.githubusercontent.com/adafruit/Raspberry-Pi-Installer-Scripts/85c3e7697fc970275215a8a27953b36c16f9b074/LICENSES/MIT.txt",
    sha256: "e710bb4810f36a853ff7cb28de520e23fd7991720f6b1770cc936f6c8135ff0a",
  },
  {
    target: "anaconda/anaconda.py.txt",
    url: "https://raw.githubusercontent.com/rhinstaller/anaconda/43a7fc4c561566fa16003752ed79db96ba3cee4e/anaconda.py",
    sha256: "d726cca651d791df8a33c6f2b739f954b20ced42e814e1df4d8a6ab8f631caec",
  },
  {
    target: "anaconda/COPYING",
    url: "https://raw.githubusercontent.com/rhinstaller/anaconda/43a7fc4c561566fa16003752ed79db96ba3cee4e/COPYING",
    sha256: "4e5c6316d44ccbdc1260ab522076aecf51b8b4acd8bc073f60039e23b1852b72",
  },
  {
    target: "electorrent/after-pack.js.txt",
    url: "https://raw.githubusercontent.com/tympanix/Electorrent/89eb958ece9cf5eaacec529bb75c4c2ab619210f/util/after-pack.js",
    sha256: "7d37dc6ab8d29e16ff131afbab4e4f94c4f7d2cf68635dcc64da627d2772dcbd",
  },
  {
    target: "electorrent/LICENSE",
    url: "https://raw.githubusercontent.com/tympanix/Electorrent/89eb958ece9cf5eaacec529bb75c4c2ab619210f/LICENSE",
    sha256: "07f4a2a6d6daeb7769bfa8d3f390f661ec320d6ef84cfe2b4e2207c0af3a5b0e",
  },
  {
    target: "whad-client/setup.py.txt",
    url: "https://raw.githubusercontent.com/whad-team/whad-client/57f7370e58cc9d0d318f3986ac3808335251cea7/setup.py",
    sha256: "ae4aca4ba3ec7acd9950216164322679e92cd40600fe0d9cd7953389b189c100",
  },
  {
    target: "whad-client/LICENSE",
    url: "https://raw.githubusercontent.com/whad-team/whad-client/57f7370e58cc9d0d318f3986ac3808335251cea7/LICENSE",
    sha256: "376a52eab9ed060dd46ff77d74923de04e16a7b5e210128746f4f30673fe0296",
  },
  {
    target: "gajira-todo/index.js.txt",
    url: "https://raw.githubusercontent.com/atlassian/gajira-todo/fe2531caa6b1bedfaea48faac8c3b418a9b8c909/index.js",
    sha256: "f22b6e2aba59b4e7ab6c718ff59b56b3898aa259d370f3caf1a31394a07ab8a5",
  },
  {
    target: "gajira-todo/LICENSE",
    url: "https://raw.githubusercontent.com/atlassian/gajira-todo/fe2531caa6b1bedfaea48faac8c3b418a9b8c909/LICENSE",
    sha256: "1831160311ccf945e9084f1157be7474dd8cf9ce3e1f33d52b56d7d3f9540da3",
  },
  {
    target: "apt-transport-s3/s3.py.txt",
    url: "https://raw.githubusercontent.com/MayaraCloud/apt-transport-s3/55c0f04d19164662c5eb0e499a46572375b34744/s3",
    sha256: "62d6f93072ae66a878ad69ae3fcd35e024d63a57d94e5bd48f7b2434a812fb35",
  },
  {
    target: "epicshop/update-workshops.js.txt",
    url: "https://raw.githubusercontent.com/epicweb-dev/epicshop/82256e67a6991136375a55f1228853371bd8995d/other/update-workshops/index.js",
    sha256: "c8d75f24dbf3b06f0c8f004f13248930083d95a59b91b8cca382c9165066695b",
  },
  {
    target: "epicshop/LICENSE.md",
    url: "https://raw.githubusercontent.com/epicweb-dev/epicshop/82256e67a6991136375a55f1228853371bd8995d/LICENSE.md",
    sha256: "c8fc0b6bcd94aa397f7c83826019804e33466d42b794b2af8d2facd57cf86d4a",
  },
  {
    target: "cpython/smtplib.py.txt",
    url: "https://raw.githubusercontent.com/python/cpython/2ffab083782968a4d732738f4f1dff6bbd69d2b0/Lib/smtplib.py",
    sha256: "fc846e9b3154d39593a25de7c5815de50c7ab22f5dd04a8ad65d5da99a7f25ef",
  },
  {
    target: "cpython/LICENSE",
    url: "https://raw.githubusercontent.com/python/cpython/2ffab083782968a4d732738f4f1dff6bbd69d2b0/LICENSE",
    sha256: "b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231",
  },
  {
    target: "tailscale/installer.sh.txt",
    url: "https://raw.githubusercontent.com/tailscale/tailscale/c0c453334a5fa421134767de995c816d7db21811/scripts/installer.sh",
    sha256: "805e85ed6f6f81a7ea2e70d52d47e7d5290863299e5c922b2787d71aa312f22e",
  },
  {
    target: "tailscale/LICENSE",
    url: "https://raw.githubusercontent.com/tailscale/tailscale/c0c453334a5fa421134767de995c816d7db21811/LICENSE",
    sha256: "a7ca6186a7963a0a60740f6047760eecd7a0234e8c38bd7e1e0bbcb324bda45b",
  },
  {
    target: "semantic-release-npm/publish.js.txt",
    url: "https://raw.githubusercontent.com/semantic-release/npm/43332788f38a2e0fef69d9cf230b10639fbb457e/lib/publish.js",
    sha256: "45b83787edffc472f0372f0855c7793e7722a0db1ab5dd1dbb2b7875e5b5f6db",
  },
  {
    target: "semantic-release-npm/LICENSE",
    url: "https://raw.githubusercontent.com/semantic-release/npm/43332788f38a2e0fef69d9cf230b10639fbb457e/LICENSE",
    sha256: "6c39086c72df12ce153282a6dc26cecde9f57f69635389a31e04e2001db147dd",
  },
  {
    target: "docker-install/install.sh.txt",
    url: "https://raw.githubusercontent.com/docker/docker-install/5ce20f2eef3615d08fea941eda5a109e949e8ebf/install.sh",
    sha256: "b991f2806186f7287bb9e53362060c382e906d154599b2fb0982f34246bacfd4",
  },
  {
    target: "docker-install/LICENSE",
    url: "https://raw.githubusercontent.com/docker/docker-install/5ce20f2eef3615d08fea941eda5a109e949e8ebf/LICENSE",
    sha256: "b8a5ad153a7153e713c20537d64adfb737b31c026553678fddd917d295d0a6ac",
  },
  {
    target: "npm-cli/publish.js.txt",
    url: "https://raw.githubusercontent.com/npm/cli/834408e8f0f2295d02205d8ff5d011c859835225/lib/commands/publish.js",
    sha256: "a1b91f9172fd17527865a16381bebddf0aa8b9a61feb545f951118a8a69bd138",
  },
  {
    target: "npm-cli/LICENSE",
    url: "https://raw.githubusercontent.com/npm/cli/834408e8f0f2295d02205d8ff5d011c859835225/LICENSE",
    sha256: "7610d223851f421d315df5e77974f1c68a04b97e02060e5bbbcf13d95e3ca257",
  },
  {
    target: "rustup/rustup-init.sh.txt",
    url: "https://raw.githubusercontent.com/rust-lang/rustup/720e6b862df1309c0a5b2aea7f81be1f975af41f/rustup-init.sh",
    sha256: "9a47c3dd4d35d36397cf8e3c8dd9319741393e81476f5d6f0c650590635ace77",
  },
  {
    target: "rustup/LICENSE-APACHE",
    url: "https://raw.githubusercontent.com/rust-lang/rustup/720e6b862df1309c0a5b2aea7f81be1f975af41f/LICENSE-APACHE",
    sha256: "8173d5c29b4f956d532781d2b86e4e30f83e6b7878dce18c919451d6ba707c90",
  },
  {
    target: "rustup/LICENSE-MIT",
    url: "https://raw.githubusercontent.com/rust-lang/rustup/720e6b862df1309c0a5b2aea7f81be1f975af41f/LICENSE-MIT",
    sha256: "c9a75f18b9ab2927829a208fc6aa2cf4e63b8420887ba29cdb265d6619ae82d5",
  },
  {
    target: "semantic-release-github/publish.js.txt",
    url: "https://raw.githubusercontent.com/semantic-release/github/33e8734811bd66937809f9fe884cb283fef238b4/lib/publish.js",
    sha256: "423e316e0ac5bab0c0d81fc195375aa4c1f6b4dbc946606b51b63f302815c305",
  },
  {
    target: "semantic-release-github/LICENSE",
    url: "https://raw.githubusercontent.com/semantic-release/github/33e8734811bd66937809f9fe884cb283fef238b4/LICENSE",
    sha256: "6c39086c72df12ce153282a6dc26cecde9f57f69635389a31e04e2001db147dd",
  },
];

function githubContentsFallback(url) {
  const parsed = new URL(url);
  if (parsed.hostname !== "raw.githubusercontent.com") return undefined;
  const [owner, repository, ref, ...path] = parsed.pathname.split("/").filter(Boolean);
  if (!owner || !repository || !ref || path.length === 0) return undefined;
  return `https://api.github.com/repos/${owner}/${repository}/contents/${path.join("/")}?ref=${ref}`;
}

async function download(url) {
  let lastError;
  const fallback = githubContentsFallback(url);
  const candidates = [
    ...(
      fallback
        ? [{
            url: fallback,
            accept: "application/vnd.github.raw+json",
          }]
        : []
    ),
    {
      url,
      accept: "application/octet-stream",
    },
  ];
  for (const candidate of candidates) {
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const response = await fetch(candidate.url, {
          headers: {
            accept: candidate.accept,
            "user-agent": "bash-risk-scanner-corpus-importer",
          },
          signal: AbortSignal.timeout(15_000),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return Buffer.from(await response.arrayBuffer());
      } catch (error) {
        lastError = error;
        if (attempt < 3) {
          await new Promise((resolveRetry) => setTimeout(resolveRetry, 500 * attempt));
        }
      }
    }
  }
  throw new Error(`Failed to download ${url}: ${lastError instanceof Error ? lastError.message : lastError}`);
}

const forceRefresh = process.argv.includes("--refresh");

for (const snapshot of snapshots) {
  const target = resolve(publicCorpusRoot, snapshot.target);
  if (!forceRefresh) {
    try {
      const cached = await readFile(target);
      const cachedSha256 = createHash("sha256").update(cached).digest("hex");
      if (cachedSha256 === snapshot.sha256) {
        console.log(`${snapshot.target} ${cachedSha256} cached`);
        continue;
      }
    } catch {
      // Missing or unreadable snapshots are downloaded below.
    }
  }

  const content = await download(snapshot.url);
  const actualSha256 = createHash("sha256").update(content).digest("hex");
  if (actualSha256 !== snapshot.sha256) {
    throw new Error(`SHA-256 mismatch for ${snapshot.target}: ${actualSha256}`);
  }
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, content);
  console.log(`${snapshot.target} ${actualSha256}`);
}
