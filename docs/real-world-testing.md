# 真实世界评测与规则提升方案

## 目标

用可重复、不可执行的离线语料衡量 Bash、Python、Node.js 扫描器的真实检出率、
误报率、解析稳定性和性能。测试语料中的代码一律作为文本传给扫描器，不调用
Shell、Python、Node.js，也不访问样本中的 URL。

## 数据集

建议维护三个互不重叠的数据集：

- `train`：规则开发和定位缺口，可频繁查看。
- `validation`：调整严重度、置信度和启发式窗口。
- `test`：冻结发布门禁；开发规则时不查看具体失败样本。

每个集合都必须包含：

- 经授权、脱敏并确认许可证允许保存的恶意或攻防样本。
- 真实 benign 样本：安装脚本、CI、运维、包管理、开发环境配置和云初始化脚本。
- hard negatives：调用相似 API 但行为安全的代码。
- 等价变体：引号、换行、别名、变量、包装函数、管道、heredoc 和有限编码。

禁止把秘密、有效 token、可访问的恶意基础设施地址或无法确认来源的代码提交到仓库。

仓库当前包含一组 `synthetic-realistic` 种子语料，用于验证评测器和固定已知回归。
它覆盖真实代码中常见的导入别名、CommonJS 解构、ESM 重命名、pathlib 调用链、
命令参数歧义和文档字符串，但并非从生产流量随机抽样，因此不能用其分数宣称真实
世界准确率。

公开来源语料还包括固定 commit 的完整 nvm、Homebrew、pipx、pnpm self-installer、
node-gyp、aiohttp、pacote、memo、mime-db、Twine、MQTT.js、Adafruit installer
和 Anaconda 代码，以及 Atomic Red Team 的 Bash 命令和 Python telnet client。
每个样本记录来源 URL、commit、许可证、本地 SHA-256；派生样本额外记录上游 YAML
哈希、Atomic GUID 和占位符替换说明。
公开快照可通过以下命令复核：

```bash
npm run evaluate:import-public
```

导入器在写入前验证 SHA-256。CI 只读取已提交的 `.txt` 快照，不访问网络、不执行
样本。Homebrew 当前有一个 tree-sitter-bash 已知解析错误，manifest 明确允许该
样本最多一个解析错误，同时总体解析错误样本率门禁仍为 5%。

运行方式：

```bash
npm run evaluate
```

结果位于 `evaluation/results/latest.json` 和 `evaluation/results/latest.html`；
CI 会执行门禁并上传这两个文件。

## 建议的样本清单格式

```json
{
  "id": "python-exfil-001",
  "language": "python",
  "sourceFile": "samples/python/exfil-001.py.txt",
  "provenance": {
    "type": "synthetic",
    "license": "repository-test-data"
  },
  "expected": [
    {
      "category": "data_exfiltration",
      "ruleId": "python.chain.read-upload",
      "minSeverity": "high"
    }
  ],
  "forbiddenCategories": ["privilege_escalation"],
  "allowAdditionalFindings": true
}
```

样本代码使用 `.txt` 后缀并放在专用目录，避免编辑器、CI 或操作系统误执行。

## 指标

按语言、风险类别和规则分别计算：

- `TP`：期望 finding 被正确检出。
- `FP`：benign 样本中不应出现的 finding。
- `FN`：期望 finding 未检出。
- `precision = TP / (TP + FP)`。
- `recall = TP / (TP + FN)`。
- `F1 = 2 × precision × recall / (precision + recall)`。

另行记录：

- 每千行代码 findings 数。
- AST 解析失败率。
- P50、P95、P99 扫描时间。
- 峰值内存。
- 超过内嵌代码大小或深度限制的样本数量。

不能只汇总一个总分。critical/high 规则应有独立门槛，三种语言和每个风险类别也应
分别展示，防止大量容易样本掩盖某一类别的退化。

## 推荐发布门禁

- 冻结测试集中已有 TP 不允许退化。
- critical/high 规则 precision 建议不低于 95%。
- recall 目标根据产品容忍度制定，并按类别单独约束。
- 新规则必须至少包含一个 TP、一个相似安全样本和一个混淆/变体样本。
- 修复 FP 时必须保留原始 TP，避免通过删除规则“修复”误报。
- P95 扫描耗时和内存不得超过既定预算。

当前基线为 38 条离线语料：36 条完全匹配，precision 100%、recall 90.9%、
F1 95.2%。前四轮冻结集暴露的缺口均已转为带具体 rule/evidence 约束的
validation 回归：

- Atomic Python telnet client：现在识别 `telnetlib3.open_connection`、
  `asyncio.create_subprocess_shell` 以及命名远端 writer 的写入。
- node-gyp installer：现在识别解压、递归清理和带 URL 参数的相对
  `download()` 包装函数。
- aiohttp 官方示例：现在根据 `aiohttp.ClientSession()` 的 AST 绑定识别
  `session.request()`，不会把任意同名本地 session 当成网络客户端。
- npm pacote：现在根据 `require("npm-registry-fetch")` 的导入来源识别别名，
  并处理本地变量遮蔽的 `fetch`。
- memo：httpx `Client`/`AsyncClient` 构造绑定现在会传播到实例请求和 POST 外传。
- mime-db：undici 的 `request`/`fetch` 解构导入现在按模块来源识别。
- Twine：`twine.utils.make_requests_session()` 被有限摘要为 requests-compatible
  session；普通同名本地工厂不会命中。
- MQTT.js：rimraf 只在模块导入来源成立时识别为递归删除。

本轮重新冻结的两个独立公开样本尚未用于调参：

- Adafruit Retrogame installer：自定义 `Shell` wrapper 内的下载执行、网络外联、
  systemd 持久化、系统路径修改和删除行为均未传播。
- Anaconda installer：`util.execWithRedirect("auditctl", ["-e", "0"])` 关闭审计
  尚未识别为防御规避。

这些数字只用于版本间回归对比。门槛应随着更多授权真实语料持续校准，不能从
77 个单元测试或当前小规模公开语料外推生产环境准确率。

## 提升闭环

1. 在冻结集上运行扫描并生成逐规则混淆矩阵。
2. 对 FP/FN 按数量、严重度和客户影响排序。
3. 为最高优先级问题提取最小复现，并增加回归测试。
4. 优先增加 AST callee、参数、重定向和父子节点约束。
5. 再增加常量传播、别名解析和有限的同函数污点跟踪。
6. 最后处理包装函数、跨函数和跨语言数据流。
7. 在 train/validation 上迭代，最终只运行冻结 test 判断是否发布。
8. 将误报放行限制在精确规则、精确域名或明确源码范围，记录原因和到期时间。

## 重点变体

### Bash

- 短参数/长参数、参数顺序、反斜杠换行。
- 管道、重定向、命令替换、进程替换和 heredoc。
- 变量赋值、数组、函数包装和 `env command`。
- `curl`/`wget` 不同输出选项及下载后多阶段执行。

### Python

- `import x as y`、`from x import y as z`。
- pathlib 与内置文件 API 的等价行为。
- requests、urllib、httpx、socket 及云 SDK。
- subprocess 的字符串、数组、`shell=True` 和包装函数。

### Node.js

- CommonJS、ESM、解构导入和重命名。
- callback、Promise、async/await 和 stream。
- `fetch`、http/https、axios、net、云 SDK。
- `child_process`、`fs` 及其 promises API。

## 安全执行要求

- 语料扫描运行在无网络、只读文件系统和非特权用户环境。
- 不安装样本声明的依赖。
- 不执行、导入、编译或格式化样本。
- 设置单样本源码大小、AST 节点数、扫描耗时和内存上限。
- 对压缩或编码数据只做有长度和递归限制的纯内存解码。
