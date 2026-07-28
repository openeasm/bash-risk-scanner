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
node-gyp、aiohttp、pacote、memo、mime-db、Twine、MQTT.js、Adafruit installer、
Anaconda、Electorrent、WHAD client、Gajira TODO、apt-transport-s3、Epicshop、
CPython smtplib、Tailscale installer 和 semantic-release/npm 代码，以及
Docker installer、npm CLI publish、Atomic Red Team 的 Bash 命令和 Python telnet
client，以及 Rustup installer 和 semantic-release/github release publisher。
最新冻结集还包括 Bun installer 与 AWS CLI GameLift uploader。
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

当前基线为 68 条离线语料：67 条完全匹配，precision 100%、recall 99.3%、
F1 99.6%。前二十四轮冻结集暴露的缺口均已转为带具体
rule/evidence 约束的
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
- Adafruit Retrogame：只有 `adafruit_shell.Shell` 来源绑定成立时，才摘要 wrapper
  内的下载、systemctl、系统路径写入/移动和删除行为。
- Anaconda：`auditctl -e 0` 会检出防御规避，`auditctl -l/-s` 查询不会告警。
- Electorrent：`promisify(child_process.exec)` 会传播执行器来源，`chmod 4755`
  检出 SUID；普通 `0755` 不报权限提升。
- WHAD client：复制到 `/usr/lib/udev/rules.d` 识别为系统配置修改。
- Gajira TODO：`process.env.GITHUB_TOKEN` 识别为具名环境凭据访问。
- apt-transport-s3：`os.environ.get("AWS_SECRET_ACCESS_KEY")` 识别为凭据访问；
  本地 APT method 的 `self.send(...)` 不再误报外传，而确认来源的 socket send
  仍保持检出。
- Epicshop：确认来源的 `execa(...)` 识别为动态执行，静态 `git push` 参数识别为
  数据外传；本地同名函数不会命中。
- CPython smtplib：返回 socket 的类方法会传播到 `self.sock.sendall()`；行为链
  只在同一函数内消费已经通过来源校验的 finding，避免跨函数碰撞。
- Tailscale installer：静态赋值为 `sudo`/`doas` 的命令变量会传播到包装命令，
  同时识别提权和 `systemctl enable` 持久化；任意变量不会被信任。
- semantic-release/npm：确认来源的 `execa("npm", ["publish", ...])` 同时识别
  动态执行、网络外联和数据外传。
- Docker installer：静态复合 wrapper（`sh -c`、`sudo -E sh -c`、`su -c`）
  会有限展开，识别动态执行、网络、提权和 systemctl 持久化；`echo` wrapper
  不会展开。
- npm CLI：`libnpmpublish.publish` 的 CommonJS 来源绑定识别网络与外传；
  `this.exec(args)` 不再被任意 `.exec()` 规则误报。`node:` 内建模块先去引号再
  规范化，保留 `node:child_process` 回归。
- Rustup：摘要实际调用 `"$@"` 的透明 wrapper 和包含 curl/wget 的下载 wrapper，
  在同一函数、有限距离内关联同一目标变量的下载、`chmod u+x` 和执行。
- semantic-release/github：`new Octokit()` 实例的 GitHub REST route 识别网络；
  只有带 `data: readFile(...)` 的上传对象识别外传。额外 AST 遍历已合并，连续
  两次 P95 保持在 100 ms 门槛内。
- Bun：同一作用域内追踪 `curl --output "$exe.zip"`、解压、`chmod` 和变量执行；
  shell rc 数组传播到循环变量和复合重定向目标。
- AWS CLI：只有来源绑定为 `s3transfer.S3Transfer` 的 `upload_file()` 才增加
  网络语义；单文件临时清理和写模式 ZipFile 不再误报破坏或二阶段行为。
- Deno：只有归档下载、解压和 chmod 已证明变量是下载运行时时，后续
  `$exe eval/run` 才识别动态执行与解释器逃逸。
- Oh My Zsh：识别 shell rc 目标替换、`chsh -s` 和 `exec zsh`；`command -v "$@"`
  这类命令发现 wrapper 不再被摘要为实际解释器执行。
- Hugging Face Hub：支持括号包裹的 Python 多行 import，并仅在
  `.utils._http.http_stream_backoff` 来源成立时识别网络。
- node-pre-gyp：`require("node-fetch")` 返回的模块本身作为 callable 使用时识别
  网络；本地同名函数不命中。
- Ansible：只有来源为 `ansible.module_utils.urls.fetch_url` 的 wrapper 才识别网络。
- Google Cloud Storage：支持以 `@` 开头的 scoped npm package 导入；只有确认来自
  `@google-cloud/storage` 的 `Storage` 实例，其 `bucket().upload()` 才识别网络
  和本地文件外传。
- Atomic Red Team DNS 外传：在同一 Bash 作用域内关联
  `xxd -p input > encoded`、`for value in $(cat encoded)` 和
  `dig "$value.static.domain"`；中间文件不一致、普通循环、静态查询和缺少静态
  域名后缀均不命中数据外传。
- Atomic Red Team timestomp：`touch -t` 的 POSIX 显式时间戳和
  `touch -r/--reference` 的时间复制识别为防御规避；普通创建、更新为当前时间、
  `-c` 以及仅出现在 `echo` 文本中的命令均不命中。
- Atomic Red Team `.netrc`：直接读取与 `find` 结果在同一 `for` AST 内进入
  `cat/head/tail/less/more` 分开识别；只查找、只打印、读取普通隐藏文件、读取
  不同变量和仅在文本中提及命令均不命中。
- Atomic Red Team crontab：只有文件、标准输入或指定用户的任务表替换识别为
  持久化；`crontab -l/-e/-r`、组合删除选项和无参数调用均不命中。
- Atomic Red Team SUID/SGID：组合符号模式 `u+xs/g+xs/u+x,g+s`、`a+rsx`
  与数值模式均命中；普通执行位、移除 `s`、SUID 查询和单独 `chown root`
  均不命中。
- Atomic Red Team UFW：`ufw disable`、停止/禁用已知防火墙服务与 `pfctl -d`
  同时识别系统修改和防御规避；关闭 UFW 日志仅识别防御规避。状态查询、启用、
  添加拒绝规则、帮助命令和普通服务停止均不命中。
- Atomic Red Team GCS 删除：确认的 `gcloud storage` 远端操作识别网络外联，
  只有 bucket/object `delete` 或 `rm` 识别破坏行为；list、describe、create 和
  cp 不会被误判为删除，帮助与文本内容不命中。
- Atomic Red Team Python：只传播命令替换中全部为 `which/command -v python*`
  的变量，并把其 `-c` 调用识别为解释器逃逸和动态执行。混入其他解释器、普通
  字符串赋值、版本查询、脚本文件执行和文本内容均不命中该变量规则。
- 静态 `python -c`、`perl/ruby -e`、`node --eval`、`php -r`、AppleScript 与
  PowerShell 内联参数识别动态执行；因此 Homebrew 的真实 `ruby -e` 同步补全了
  validation 标签和具体 finding。
- Atomic Red Team Keychain：`security dump-keychain` 和带 `-w` 的
  generic/internet password 提取识别凭据访问；证书查询/导入、Keychain 列表、
  只查密码元数据、帮助命令和文本内容均不命中。

本轮重新冻结的公开恶意样本尚未用于调参：

- Atomic Red Team T1543.001 将 plist 复制到 `/etc/emond.d/rules`，再创建
  `/private/var/db/emondClients` 触发文件。系统修改和提权已命中，
  `persistence` 尚未命中，作为下一轮待修复 FN。
- 派生样本固定上游 YAML、GUID、commit 和 SHA-256，只把目标文件替换为
  惰性参数或只复制单条 executor 命令，评测器不会执行命令。

新 test 分层有三个预期类别，其中系统修改和提权命中、持久化漏报，因此 recall
基线为 66.7%；整体门槛仍保持 precision 95%、recall 90%，
`maximum.forbiddenFindingCount` 保持 0。下一轮应识别 emond 规则目录和触发文件
写入，同时用读取规则、普通 `/tmp` plist、删除触发文件和路径仅出现在文本中作为
hard-negative。

这些数字只用于版本间回归对比。门槛应随着更多授权真实语料持续校准，不能从
112 个单元测试或当前小规模公开语料外推生产环境准确率。

加入 87 KB Hugging Face 样本后，首次 P95 从 96.62 ms 升至 116.19 ms。扫描器将
Python 对象绑定合并进主遍历，并仅对候选环境访问节点读取 `node.text`，复测 P95
降至 82–94 ms；门槛仍保持 100 ms。

加入第 63 条样本后，最近邻 P95 一度落到 Rustup 样本的 99.24 ms。将 `.netrc`
与 DNS 的两个 Bash `for` 全树遍历合并后，连续两次复测降至 83.75/84.82 ms，
没有通过放宽性能门槛掩盖退化。

规则继续增加后，第 66 条样本首次复测 P95 达到 109.52/101.89 ms。根因是每条
Bash 语句曾为每一条规则重复计算 wrapper/alias 变体；改为每条语句只计算一次并
与链路规则共享后，连续两次复测降至 83.06/79.90 ms。

类别集合之外，manifest 现在可声明 `forbiddenFindings`，按 category、ruleId 和
evidencePattern 禁止具体 finding。禁止 finding 数量进入 JSON/HTML 和显式 gate，
避免同一类别的一条正确 finding 掩盖另一条错误 finding。Oh My Zsh 的
`command_exists zsh` 已作为首个真实回归约束。

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
