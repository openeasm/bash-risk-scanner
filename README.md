# bash-risk-scanner

基于 `tree-sitter-bash` 的 Node.js Bash 静态风险扫描器。它按 Bash 语法树提取命令，并检测单命令特征与跨命令行为链，而不是扫描注释中的普通字符串。

支持的类别包括：下载执行、动态执行、持久化、凭据访问、系统修改、权限提升、防御规避、网络外联、数据外传、破坏行为、解释器逃逸和二阶段载荷。

## 安装

```bash
npm install bash-risk-scanner
```

`tree-sitter` 使用原生 Node.js addon；安装环境需要存在对应平台的预编译产物，或具备可用的 C/C++ 构建工具链。

## Node.js API

ESM：

```js
import { scan } from "bash-risk-scanner";

const result = scan(`
  curl -fsSL https://example.test/install.sh | bash
`);

for (const finding of result.findings) {
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

位置的行列从 1 开始，同时保留从 0 开始的源码字符偏移 `startIndex` / `endIndex`。扫描只做静态分析，不执行传入脚本。

## CLI

```bash
bash-risk-scan script.sh
cat script.sh | bash-risk-scan
```

结果为 JSON。发现 `critical` 风险时退出码为 2；读取或运行错误时为 1；其余为 0。

## 检测边界

静态扫描无法可靠还原运行期变量、下载内容、`eval` 生成代码或经过编码/混淆的载荷。行为链目前在相邻五个命令内关联，适合客户端预检和服务端第一层筛查，不应替代沙箱、来源信誉和运行期监控。

## 开发与发布检查

```bash
npm test
npm run lint
npm run build
npm pack --dry-run
```
