export type RiskCategory =
  | "download_execution"
  | "dynamic_execution"
  | "persistence"
  | "credential_access"
  | "system_modification"
  | "privilege_escalation"
  | "defense_evasion"
  | "network_egress"
  | "data_exfiltration"
  | "destructive_behavior"
  | "interpreter_escape"
  | "second_stage_payload";

export type Severity = "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type SupportedLanguage = "bash" | "python" | "javascript" | "node";
export type DecisionAction = "allow" | "ask" | "block";
export type PolicyLocale = "zh-CN" | "en";
export type PolicyProfile = "ai-agent" | "audit";

export interface PolicyMatch {
  policyId: string;
  action: DecisionAction;
  title: string;
  reason: string;
  findingRuleIds: string[];
}

export interface ScanDecision {
  action: DecisionAction;
  riskScore: number;
  approvalRequired: boolean;
  profile: PolicyProfile;
  locale: PolicyLocale;
  title: string;
  reason: string;
  matchedPolicies: PolicyMatch[];
}

export interface PolicyOptions {
  /** Built-in decision profile. Default: `ai-agent`. */
  profile?: PolicyProfile;
  /** Language used by decision titles and reasons. Default: `zh-CN`. */
  locale?: PolicyLocale;
  /** Override the action of a stable policy ID. */
  overrides?: Record<string, DecisionAction>;
}

export interface Position {
  row: number;
  column: number;
}

export interface SourceRange {
  start: Position;
  end: Position;
  startIndex: number;
  endIndex: number;
}

export interface Finding {
  ruleId: string;
  category: RiskCategory;
  title: string;
  severity: Severity;
  confidence: Confidence;
  message: string;
  evidence: string;
  range: SourceRange;
  relatedRanges?: SourceRange[];
  /** Language in which the risky behavior was found. */
  language?: Exclude<SupportedLanguage, "node">;
  /** Location inside an embedded `python -c` / `node -e` payload. */
  innerRange?: SourceRange;
  /** Bash construct which introduced an embedded payload. */
  origin?: {
    language: "bash";
    interpreter: "python" | "node";
    kind: "argument" | "heredoc" | "pipeline" | "generated-file" | "compiled-file";
  };
}

export interface ScanResult {
  findings: Finding[];
  summary: {
    total: number;
    byCategory: Partial<Record<RiskCategory, number>>;
    bySeverity: Partial<Record<Severity, number>>;
  };
  parseErrors: SourceRange[];
  /** Deterministic built-in execution decision. */
  decision: ScanDecision;
}

export interface ScanOptions {
  /** Source language. `node` is an alias for `javascript`. Default: `bash`. */
  language?: SupportedLanguage;
  /** Include low confidence heuristic findings. Default: true. */
  includeLowConfidence?: boolean;
  /** Maximum source characters retained in evidence. Default: 240. */
  maxEvidenceLength?: number;
  /**
   * Hosts allowed as sources for download-and-execute chains.
   *
   * Exact hosts (`artifacts.corp.example`) and left-most wildcard suffixes
   * (`*.corp.example`) are supported. A wildcard does not match the suffix
   * itself. This only suppresses `download_execution`; other categories such
   * as `network_egress` are evaluated independently.
   */
  allowedDownloadHosts?: string[];
  /**
   * Allow literal loopback, link-local and RFC1918 IPv4 download hosts.
   * Default: false. Hostnames are never resolved through DNS.
   */
  allowPrivateDownloadIps?: boolean;
  /** Recursion limit for statically embedded interpreter payloads. Default: 2. */
  maxEmbeddedDepth?: number;
  /** Maximum embedded payload size in UTF-16 code units. Default: 100000. */
  maxEmbeddedCodeLength?: number;
  /** Built-in allow/ask/block decision policy. Enabled by default. */
  policy?: PolicyOptions;
}
