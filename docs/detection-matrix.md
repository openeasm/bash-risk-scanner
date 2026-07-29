# 检测能力矩阵

本文档描述 `bash-risk-scanner` 当前已经实现并由测试覆盖的能力，不把规划中的能力
计为已支持。

标记说明：

- ✅：有对应 AST/行为链规则和测试。
- ◐：只有入口或部分变体检测，不能视为完整覆盖。
- —：当前没有专用语义检测。

## 风险类别矩阵

| 风险类别 | Bash | Python | Node.js | macOS 专项 | Windows 专项 | 默认决策 | 典型检出 |
|---|---:|---:|---:|---:|---:|---|---|
| 下载执行 | ✅ | ✅ | ✅ | ✅ 通用链 | ◐ PowerShell 入口 | `block` | `curl/wget … \| bash`、远程响应进入 `eval/exec`、下载→赋权→执行 |
| 动态执行 | ✅ | ✅ | ✅ | ✅ `osascript -e` | ◐ `powershell/pwsh -Command/-EncodedCommand` | `ask` | `eval`、`bash/sh -c`、`source <(...)`、内联解释器代码 |
| 持久化 | ✅ | ✅ | ✅ | ✅ LaunchAgent、emond、shell rc | ◐ `schtasks` 命令入口 | `block` | crontab、systemd、LaunchAgent、启动脚本、计划任务 |
| 凭据访问 | ✅ | ✅ | ✅ | ✅ Keychain、Safari Cookie、Chrome Login Data | ◐ 通用环境变量/跨平台路径 | `ask` | `.ssh`、云凭据、环境变量、浏览器数据库、Keychain |
| 系统修改 | ✅ | ✅ | ✅ | ✅ Time Machine、证书信任、系统路径 | ◐ 通用脚本调用 | `ask` | `/etc`、sudoers、防火墙、DNS、代理、证书和账号配置 |
| 权限提升 | ✅ | ✅ | ✅ | ✅ `sudo`/SUID 等通用规则 | ◐ PowerShell 入口，不解析 Windows token/UAC | `block` | sudo、su、SUID/SGID、capability、setuid/setgid |
| 防御规避 | ✅ | ✅ | ✅ | ✅ 历史、Time Machine 等 | ◐ 不解析 Defender/AMSI PowerShell 语义 | `block` | 删除日志、关闭审计/防火墙、安全进程、timestomp |
| 网络外联 | ✅ | ✅ | ✅ | ✅ 通用网络工具/API | ◐ Bash/语言层网络调用 | `ask` | curl、wget、SSH、SCP/SFTP、socket、HTTP、DNS、对象存储 |
| 数据外传 | ✅ | ✅ | ✅ | ✅ 通用上传链 | ◐ Bash/语言层上传调用 | `block` | 文件读取→POST/上传、SCP/SFTP/rsync push、DNS 外传、反向连接 |
| 破坏行为 | ✅ | ✅ | ✅ | ✅ Time Machine 禁用 | ◐ 不解析原生 PowerShell 删除语义 | `block` | `rm -rf`、磁盘写入、批量加密、云资源删除、强制重启 |
| 解释器逃逸 | ✅ | ✅ | ✅ | ✅ AppleScript/Python/Node 等 | ◐ PowerShell 入口 | `ask` | Python、Perl、Ruby、Node、PHP、AppleScript、PowerShell |
| 二阶段载荷 | ✅ | ✅ | ✅ | ✅ 通用链 | ◐ Bash/语言入口 | `ask` | Bash：下载→解压→运行；Python/Node.js：同一外层执行作用域内下载→解压。单独下载或单独解压不命中 |

决策合并优先级为 `block > ask > allow`。没有命中已知风险且源码可可靠解析时，
默认决策为 `allow`；解析错误默认 `block`。

## macOS 专项矩阵

| 行为 | 状态 | 代表规则 |
|---|---:|---|
| Keychain 明文密码/数据库访问 | ✅ | `credential.macos-keychain`、`credential.keychain-file-stage` |
| Safari Cookie 搜索 | ✅ | `credential.browser-cookie-search` |
| Chrome Login Data 暂存 | ✅ | `credential.chrome-login-data-stage` |
| LaunchAgent 安装并加载 | ✅ | `persistence.launchagent-install-load` |
| emond 持久化 | ✅ | `persistence.emond` |
| shell rc 持久化 | ✅ | `persistence.shell-rc`、`persistence.shell-rc-replace` |
| Time Machine 禁用 | ✅ | `system.backup-disable`、`destructive.backup-disable` |
| 系统根证书安装 | ✅ | `system.trust-root-install` |
| AppleScript 内联执行 | ✅ | `dynamic.interpreter-inline-code`、`escape.interpreter` |
| TCC 数据库/隐私授权修改 | — | 尚无专用规则 |
| `profiles`/MDM 配置修改 | — | 尚无专用规则 |
| `xattr` 隔离属性移除、Gatekeeper 绕过 | — | 尚无专用规则 |

## Windows 专项矩阵

| 行为 | 状态 | 当前边界 |
|---|---:|---|
| Bash 中调用 `powershell`/`pwsh` | ◐ | 识别解释器入口 |
| `-Command`/`-EncodedCommand` | ◐ | 识别动态执行入口，不解码或解析 PowerShell 载荷 |
| `schtasks` | ◐ | 识别持久化命令入口，尚无参数级任务语义 |
| 原生 `.ps1` AST | — | 当前不支持 |
| Defender/AMSI 配置修改 | — | 需 PowerShell AST/Windows 专用规则 |
| 注册表 Run Keys/Services | — | 需 Windows 专用规则 |
| `cmd.exe /c` | — | 尚无专用解释器入口规则 |
| `certutil`、BITS、`mshta`、`rundll32` | — | 尚无 LOLBin 专用规则 |
| Windows Credential Manager/DPAPI | — | 尚无专用凭据规则 |

因此，当前 Windows 能力应描述为“检测 Bash 中的部分 Windows 命令入口”，不能描述
为“完整扫描 PowerShell 或 Windows 脚本”。

## 内嵌与行为链

| 能力 | Bash | Python | Node.js |
|---|---:|---:|---:|
| 单调用语义 | ✅ | ✅ | ✅ |
| 同一作用域行为链 | ✅ | ✅ | ✅ |
| Bash `python -c` / heredoc / 静态管道递归扫描 | ✅ | — | — |
| Bash `node -e` / heredoc / 静态管道递归扫描 | ✅ | — | — |
| 生成 Python 文件后执行 | ✅ | — | — |
| 编译 Python 后执行 | ✅ | — | — |
| 运行期动态变量还原 | — | — | — |
| 任意混淆/加密载荷解码 | — | — | — |
| 跨进程运行时数据流 | — | — | — |

## 策略与误报度量

| 能力 | 状态 |
|---|---:|
| `allow / ask / block` 内置决策 | ✅ |
| 中文/英文说明切换 | ✅ |
| 稳定 `policyId` 与动作覆盖 | ✅ |
| `ai-agent` / `audit` profile | ✅ |
| False Block 指标 | ✅ |
| Unnecessary Ask 指标 | ✅ |
| Unsafe Allow 指标 | ✅ |
| 当前人工决策基线 | 20/20 匹配 |
| 当前检测语料 | 120/121 严格匹配 |
| Atomic 全量 inventory | 1,817 tests / 340 techniques |
| Windows/macOS 命令型目标 | 1,455 |
| 已纳入目标 GUID | 33（2.3%） |
| macOS 命令型语料覆盖 | 33/242（13.6%） |
| Windows 命令型语料覆盖 | 0/1,216 |

当前评测结果仅代表仓库内已标注语料，不能外推为生产环境总体准确率。详情见
[`reports/evaluation.html`](../reports/evaluation.html) 和
[`reports/atomic-coverage.html`](../reports/atomic-coverage.html)，评测方法见
[`docs/real-world-testing.md`](./real-world-testing.md)。
