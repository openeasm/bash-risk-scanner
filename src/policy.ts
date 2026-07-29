import type {
  DecisionAction,
  Finding,
  PolicyLocale,
  PolicyMatch,
  PolicyOptions,
  RiskCategory,
  ScanDecision,
  SourceRange,
} from "./types.js";

interface LocalizedText {
  "zh-CN": { title: string; reason: string };
  en: { title: string; reason: string };
}

interface PolicyDefinition {
  policyId: string;
  action: DecisionAction;
  score: number;
  categories?: RiskCategory[];
  text: LocalizedText;
}

const POLICIES: PolicyDefinition[] = [
  {
    policyId: "block.download-execution",
    action: "block",
    score: 95,
    categories: ["download_execution"],
    text: {
      "zh-CN": { title: "阻止下载后执行", reason: "命令会下载远程内容并交给解释器或作为程序执行。" },
      en: { title: "Block downloaded code execution", reason: "The command downloads remote content and passes it to an interpreter or executes it as a program." },
    },
  },
  {
    policyId: "block.data-exfiltration",
    action: "block",
    score: 100,
    categories: ["data_exfiltration"],
    text: {
      "zh-CN": { title: "阻止数据外传", reason: "命令会把本地数据、凭据或环境信息发送到外部目标。" },
      en: { title: "Block data exfiltration", reason: "The command sends local data, credentials, or environment information to an external destination." },
    },
  },
  {
    policyId: "block.destructive-behavior",
    action: "block",
    score: 100,
    categories: ["destructive_behavior"],
    text: {
      "zh-CN": { title: "阻止破坏性操作", reason: "命令包含批量删除、磁盘破坏、资源删除或文件加密行为。" },
      en: { title: "Block destructive behavior", reason: "The command performs bulk deletion, disk damage, resource deletion, or file encryption." },
    },
  },
  {
    policyId: "block.persistence",
    action: "block",
    score: 95,
    categories: ["persistence"],
    text: {
      "zh-CN": { title: "阻止持久化修改", reason: "命令会建立计划任务、启动项、LaunchAgent、服务或 shell 启动持久化。" },
      en: { title: "Block persistence changes", reason: "The command establishes scheduled-task, startup, LaunchAgent, service, or shell-startup persistence." },
    },
  },
  {
    policyId: "block.privilege-escalation",
    action: "block",
    score: 95,
    categories: ["privilege_escalation"],
    text: {
      "zh-CN": { title: "阻止权限提升", reason: "命令请求或配置更高权限，包括 sudo、SUID 或 capability。" },
      en: { title: "Block privilege escalation", reason: "The command requests or configures elevated privileges, including sudo, SUID, or capabilities." },
    },
  },
  {
    policyId: "block.defense-evasion",
    action: "block",
    score: 100,
    categories: ["defense_evasion"],
    text: {
      "zh-CN": { title: "阻止防御规避", reason: "命令会关闭、削弱或绕过日志、审计、防火墙或安全控制。" },
      en: { title: "Block defense evasion", reason: "The command disables, weakens, or bypasses logging, auditing, firewall, or security controls." },
    },
  },
  {
    policyId: "ask.credential-access",
    action: "ask",
    score: 80,
    categories: ["credential_access"],
    text: {
      "zh-CN": { title: "确认凭据访问", reason: "命令会读取或暂存密钥、令牌、浏览器数据、Keychain 或其他凭据。" },
      en: { title: "Confirm credential access", reason: "The command reads or stages keys, tokens, browser data, Keychain data, or other credentials." },
    },
  },
  {
    policyId: "ask.system-modification",
    action: "ask",
    score: 75,
    categories: ["system_modification"],
    text: {
      "zh-CN": { title: "确认系统修改", reason: "命令会修改系统配置、网络设置、证书或受保护路径。" },
      en: { title: "Confirm system modification", reason: "The command modifies system configuration, network settings, certificates, or protected paths." },
    },
  },
  {
    policyId: "ask.dynamic-execution",
    action: "ask",
    score: 70,
    categories: ["dynamic_execution"],
    text: {
      "zh-CN": { title: "确认动态执行", reason: "命令使用 eval、内联代码或其他运行时动态执行机制。" },
      en: { title: "Confirm dynamic execution", reason: "The command uses eval, inline code, or another runtime dynamic-execution mechanism." },
    },
  },
  {
    policyId: "ask.interpreter-escape",
    action: "ask",
    score: 70,
    categories: ["interpreter_escape"],
    text: {
      "zh-CN": { title: "确认解释器调用", reason: "命令会调用另一个解释器或进程执行环境。" },
      en: { title: "Confirm interpreter invocation", reason: "The command invokes another interpreter or process execution environment." },
    },
  },
  {
    policyId: "ask.second-stage-payload",
    action: "ask",
    score: 85,
    categories: ["second_stage_payload"],
    text: {
      "zh-CN": { title: "确认二阶段载荷", reason: "代码形成了下载后解压，或下载、解压后执行脚本或二进制文件的行为链。" },
      en: { title: "Confirm second-stage payload", reason: "The code forms a download-and-extract chain, or downloads, extracts, and executes a later script or binary." },
    },
  },
  {
    policyId: "ask.network-egress",
    action: "ask",
    score: 50,
    categories: ["network_egress"],
    text: {
      "zh-CN": { title: "确认网络外联", reason: "命令会连接外部或远程网络目标。" },
      en: { title: "Confirm network egress", reason: "The command connects to an external or remote network destination." },
    },
  },
];

const actionRank: Record<DecisionAction, number> = {
  allow: 0,
  ask: 1,
  block: 2,
};

function localized(
  locale: PolicyLocale,
  zh: { title: string; reason: string },
  en: { title: string; reason: string },
): { title: string; reason: string } {
  return locale === "en" ? en : zh;
}

export function decide(
  findings: Finding[],
  parseErrors: SourceRange[],
  options: PolicyOptions = {},
): ScanDecision {
  const locale: PolicyLocale = options.locale === "en" ? "en" : "zh-CN";
  const profile = options.profile === "audit" ? "audit" : "ai-agent";
  const matches: Array<PolicyMatch & { score: number }> = [];

  if (parseErrors.length > 0) {
    const text = localized(
      locale,
      { title: "阻止无法可靠解析的代码", reason: "源码包含语法错误，静态分析无法可靠判断实际执行行为。" },
      { title: "Block code that cannot be parsed reliably", reason: "The source contains syntax errors, so static analysis cannot reliably determine its execution behavior." },
    );
    matches.push({
      policyId: "block.parse-error",
      action: options.overrides?.["block.parse-error"] ?? "block",
      score: 90,
      findingRuleIds: [],
      ...text,
    });
  }

  for (const policy of POLICIES) {
    const related = findings.filter((finding) => policy.categories?.includes(finding.category));
    if (related.length === 0) continue;
    matches.push({
      policyId: policy.policyId,
      action: options.overrides?.[policy.policyId] ?? policy.action,
      score: policy.score,
      findingRuleIds: [...new Set(related.map((finding) => finding.ruleId))],
      ...policy.text[locale],
    });
  }

  if (matches.length === 0) {
    const text = localized(
      locale,
      { title: "允许执行", reason: "未发现需要确认或阻止的已知风险行为。" },
      { title: "Allow execution", reason: "No known behavior requiring confirmation or blocking was detected." },
    );
    return {
      action: "allow",
      riskScore: 0,
      approvalRequired: false,
      profile,
      locale,
      matchedPolicies: [],
      ...text,
    };
  }

  let action = matches.reduce<DecisionAction>(
    (highest, match) => actionRank[match.action] > actionRank[highest] ? match.action : highest,
    "allow",
  );
  if (profile === "audit" && action === "block") action = "ask";
  const decisive = matches
    .filter((match) => profile !== "audit" ? match.action === action : true)
    .sort((left, right) => right.score - left.score)[0]!;
  const summary = localized(
    locale,
    {
      title: action === "block"
        ? "阻止执行"
        : action === "ask"
          ? "执行前需要确认"
          : "允许执行",
      reason: decisive.reason,
    },
    {
      title: action === "block"
        ? "Block execution"
        : action === "ask"
          ? "Confirmation required"
          : "Allow execution",
      reason: decisive.reason,
    },
  );

  return {
    action,
    riskScore: Math.max(...matches.map((match) => match.score)),
    approvalRequired: action === "ask",
    profile,
    locale,
    title: summary.title,
    reason: summary.reason,
    matchedPolicies: matches.map(({ score: _score, ...match }) => match),
  };
}
