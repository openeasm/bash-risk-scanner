import Parser from "tree-sitter";
import Bash from "tree-sitter-bash";
import {
  ARCHIVE_DOWNLOAD,
  COMMAND_RULES,
  DOWNLOAD,
  EXECUTE,
  EXTRACT,
  FILE_READ,
  INSTALL_OR_BINARY,
  UPLOAD,
} from "./rules.js";
import type { Finding, ScanOptions, ScanResult, SourceRange } from "./types.js";

type SyntaxNode = Parser.SyntaxNode;

interface Statement {
  node: SyntaxNode;
  text: string;
  range: SourceRange;
}

const parser = new Parser();
parser.setLanguage(Bash as unknown as Parser.Language);

function rangeOf(node: SyntaxNode): SourceRange {
  return {
    start: { row: node.startPosition.row + 1, column: node.startPosition.column + 1 },
    end: { row: node.endPosition.row + 1, column: node.endPosition.column + 1 },
    startIndex: node.startIndex,
    endIndex: node.endIndex,
  };
}

function walk(node: SyntaxNode, visit: (node: SyntaxNode) => void): void {
  visit(node);
  for (const child of node.namedChildren) walk(child, visit);
}

function statements(root: SyntaxNode, source: string): Statement[] {
  const result: Statement[] = [];
  walk(root, (node) => {
    if (node.type !== "command") return;
    const container = node.parent?.type === "redirected_statement" ? node.parent : node;
    // Nested commands are retained; tree-sitter boundaries prevent matching comments
    // and unrelated quoted prose as if they were commands.
    result.push({
      node,
      text: source.slice(container.startIndex, container.endIndex),
      range: rangeOf(container),
    });
  });
  return result.sort((a, b) => a.range.startIndex - b.range.startIndex);
}

function evidence(text: string, max: number): string {
  const compact = text.replace(/\s+/g, " ").trim();
  return compact.length <= max ? compact : `${compact.slice(0, max - 1)}…`;
}

function addChainFinding(
  findings: Finding[],
  first: Statement,
  last: Statement,
  data: Omit<Finding, "evidence" | "range" | "relatedRanges">,
  maxEvidence: number,
): void {
  findings.push({
    ...data,
    evidence: evidence(`${first.text} … ${last.text}`, maxEvidence),
    range: first.range,
    relatedRanges: first === last ? undefined : [last.range],
  });
}

function sharedPipeline(a: SyntaxNode, b: SyntaxNode): boolean {
  const pipelines = new Set<number>();
  for (let node: SyntaxNode | null = a; node; node = node.parent) {
    if (node.type === "pipeline") pipelines.add(node.id);
  }
  for (let node: SyntaxNode | null = b; node; node = node.parent) {
    if (node.type === "pipeline" && pipelines.has(node.id)) return true;
  }
  return false;
}

const URL_PATTERN = /\bhttps?:\/\/[^\s"'<>|;&)]+/gi;

function downloadHosts(text: string): string[] {
  const hosts: string[] = [];
  for (const match of text.matchAll(URL_PATTERN)) {
    try {
      hosts.push(new URL(match[0]).hostname.toLowerCase().replace(/\.$/, ""));
    } catch {
      // An invalid/static-incomplete URL cannot be trusted.
    }
  }
  return hosts;
}

function isPrivateIpv4(host: string): boolean {
  const parts = host.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }
  const [a, b] = parts as [number, number, number, number];
  return a === 10
    || a === 127
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168);
}

function hostMatches(host: string, allowedPattern: string): boolean {
  const pattern = allowedPattern.trim().toLowerCase().replace(/\.$/, "");
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(2);
    return suffix.length > 0 && host.endsWith(`.${suffix}`) && host !== suffix;
  }
  return host === pattern;
}

function isAllowedDownload(text: string, options: ScanOptions): boolean {
  const hosts = downloadHosts(text);
  // Unknown, variable-built, relative, or malformed URLs fail closed.
  if (hosts.length === 0) return false;
  const patterns = options.allowedDownloadHosts ?? [];
  return hosts.every((host) =>
    patterns.some((pattern) => hostMatches(host, pattern))
    || (options.allowPrivateDownloadIps === true && isPrivateIpv4(host)),
  );
}

export function scan(source: string, options: ScanOptions = {}): ScanResult {
  const maxEvidence = Math.max(40, options.maxEvidenceLength ?? 240);
  const tree = parser.parse(source);
  const commands = statements(tree.rootNode, source);
  const findings: Finding[] = [];
  const parseErrors: SourceRange[] = [];

  walk(tree.rootNode, (node) => {
    if (node.isError || node.isMissing) parseErrors.push(rangeOf(node));
  });

  for (const statement of commands) {
    for (const rule of COMMAND_RULES) {
      rule.pattern.lastIndex = 0;
      if (!rule.pattern.test(statement.text)) continue;
      if (rule.confidence === "low" && options.includeLowConfidence === false) continue;
      findings.push({
        ruleId: rule.id,
        category: rule.category,
        title: rule.title,
        severity: rule.severity,
        confidence: rule.confidence,
        message: rule.message,
        evidence: evidence(statement.text, maxEvidence),
        range: statement.range,
      });
    }
  }

  // Same command/pipeline, e.g. curl URL | bash.
  walk(tree.rootNode, (node) => {
    if (!["pipeline", "list", "redirected_statement", "command"].includes(node.type)) return;
    const text = source.slice(node.startIndex, node.endIndex);
    if (DOWNLOAD.test(text) && EXECUTE.test(text) && !isAllowedDownload(text, options)) {
      addChainFinding(findings, { node, text, range: rangeOf(node) }, { node, text, range: rangeOf(node) }, {
        ruleId: "chain.download-execute",
        category: "download_execution",
        title: "Downloads and executes content",
        severity: "critical",
        confidence: "high",
        message: "Remote content flows into a shell or is made executable.",
      }, maxEvidence);
    }
  });

  // Nearby statements catch staged scripts while limiting unrelated correlations.
  for (let i = 0; i < commands.length; i++) {
    const first = commands[i]!;
    const window = commands.slice(i, i + 5);
    const exec = window.find((item, offset) => offset > 0 && EXECUTE.test(item.text));
    if (
      DOWNLOAD.test(first.text)
      && exec
      && !sharedPipeline(first.node, exec.node)
      && !isAllowedDownload(first.text, options)
    ) {
      addChainFinding(findings, first, exec, {
        ruleId: "chain.download-execute",
        category: "download_execution",
        title: "Downloads then executes content",
        severity: "critical",
        confidence: "medium",
        message: "A download is followed shortly by shell execution or an executable permission change.",
      }, maxEvidence);
    }

    const upload = window.find((item, offset) => offset > 0 && UPLOAD.test(item.text));
    if (FILE_READ.test(first.text) && upload) {
      addChainFinding(findings, first, upload, {
        ruleId: "chain.read-upload",
        category: "data_exfiltration",
        title: "Reads then uploads data",
        severity: "high",
        confidence: "medium",
        message: "Local data access is followed shortly by an upload command.",
      }, maxEvidence);
    }

    if (ARCHIVE_DOWNLOAD.test(first.text)) {
      const extract = window.find((item, offset) => offset > 0 && EXTRACT.test(item.text));
      const run = window.find((item, offset) => offset > 0 && INSTALL_OR_BINARY.test(item.text));
      if (extract && run) {
        addChainFinding(findings, first, run, {
          ruleId: "chain.second-stage-archive",
          category: "second_stage_payload",
          title: "Downloads, extracts, and runs a second-stage payload",
          severity: "critical",
          confidence: "high",
          message: "An archive download is followed by extraction and installer or binary execution.",
        }, maxEvidence);
      }
    }
  }

  const unique = [...new Map(findings.map((item) => [
    `${item.ruleId}:${item.range.startIndex}:${item.relatedRanges?.[0]?.startIndex ?? ""}`,
    item,
  ])).values()].sort((a, b) => a.range.startIndex - b.range.startIndex);

  const byCategory: ScanResult["summary"]["byCategory"] = {};
  const bySeverity: ScanResult["summary"]["bySeverity"] = {};
  for (const item of unique) {
    byCategory[item.category] = (byCategory[item.category] ?? 0) + 1;
    bySeverity[item.severity] = (bySeverity[item.severity] ?? 0) + 1;
  }

  return {
    findings: unique,
    summary: { total: unique.length, byCategory, bySeverity },
    parseErrors,
  };
}
