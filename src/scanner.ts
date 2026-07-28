import Parser from "tree-sitter";
import Bash from "tree-sitter-bash";
import Python from "tree-sitter-python";
import JavaScript from "tree-sitter-javascript";
import { extractEmbeddedPayloads } from "./embedded.js";
import { JAVASCRIPT_RULES, PYTHON_RULES, type LanguageRule } from "./language-rules.js";
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
import type { Finding, ScanOptions, ScanResult, SourceRange, SupportedLanguage } from "./types.js";

type SyntaxNode = Parser.SyntaxNode;

interface Statement {
  node: SyntaxNode;
  text: string;
  range: SourceRange;
}

function createParser(language: Parser.Language): Parser {
  const instance = new Parser();
  instance.setLanguage(language);
  return instance;
}

const bashParser = createParser(Bash as unknown as Parser.Language);
const pythonParser = createParser(Python as unknown as Parser.Language);
const javascriptParser = createParser(JavaScript as unknown as Parser.Language);

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

function bashCommandVariants(text: string): string[] {
  const variants = [text];
  let current = text;
  for (let depth = 0; depth < 4; depth++) {
    let next = current;
    next = next.replace(
      /^\s*(?:command|builtin)\s+(?:(?:-p|--)\s+)*/i,
      "",
    );
    next = next.replace(
      /^\s*env\s+(?:(?:-[A-Za-z]+|--[\w-]+(?:=\S+)?|[A-Za-z_]\w*=\S+)\s+)*/i,
      "",
    );
    next = next.replace(
      /^\s*(?:nohup|sudo|\/usr\/bin\/sudo|execute_sudo|execute|retry)\s+/i,
      "",
    );
    next = next.replace(/^\s*(["'])([^"']+)\1/, "$2");
    if (next === current) break;
    variants.push(next);
    current = next;
  }
  return [...new Set(variants)];
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

function emptySummary(findings: Finding[]): ScanResult["summary"] {
  const byCategory: ScanResult["summary"]["byCategory"] = {};
  const bySeverity: ScanResult["summary"]["bySeverity"] = {};
  for (const item of findings) {
    byCategory[item.category] = (byCategory[item.category] ?? 0) + 1;
    bySeverity[item.severity] = (bySeverity[item.severity] ?? 0) + 1;
  }
  return { total: findings.length, byCategory, bySeverity };
}

const CALLEE_BY_CATEGORY: Record<
  "python" | "javascript",
  Partial<Record<Finding["category"], RegExp>>
> = {
  python: {
    download_execution: /^(?:exec|eval|os\.system|os\.popen|subprocess\.\w+)$/,
    dynamic_execution: /^(?:eval|exec|compile|os\.(?:system|popen)|subprocess\.\w+|asyncio\.create_subprocess_(?:shell|exec))$/,
    persistence: /(?:^|\.)(?:open|Path|write_text|write_bytes|copy|copy2|copyfile)$/,
    credential_access: /(?:^|\.)(?:open|Path|read_text|read_bytes|getenv|items|copy|keys|values|\w*password\w*|\w*credential\w*)$/i,
    system_modification: /(?:^|\.)(?:open|Path|write_text|write_bytes|copy|copy2|copyfile|move)$/,
    privilege_escalation: /(?:^|\.)(?:setuid|seteuid|setgid|setegid|chmod|chown|run|call|Popen|check_call)$/,
    defense_evasion: /(?:^|\.)(?:remove|unlink|kill|rmtree|run|call|Popen)$/,
    network_egress: /(?:^|\.)(?:get|post|put|patch|request|urlopen|urlretrieve|socket|create_connection|open_connection|connect)$/,
    data_exfiltration: /(?:^|\.)(?:post|put|patch|upload_file|put_object|send|sendall|write)$/,
    destructive_behavior: /(?:^|\.)(?:rmtree|remove|unlink|removedirs|open)$/,
    interpreter_escape: /(?:^|\.)(?:system|popen|run|call|Popen|check_call|check_output|create_subprocess_shell)$/,
    second_stage_payload: /(?:^|\.)(?:get|urlretrieve|unpack_archive|open|ZipFile)$/,
  },
  javascript: {
    download_execution: /(?:^|\.)(?:eval|Function|exec|execSync|spawn|spawnSync)$/,
    dynamic_execution: /(?:^|\.)(?:eval|Function|runIn\w+|compileFunction|exec|execSync|spawn|spawnSync)$/,
    persistence: /(?:^|\.)(?:writeFile|writeFileSync|appendFile|appendFileSync|copyFile|copyFileSync|rename|renameSync)$/,
    credential_access: /(?:^|\.)(?:readFile|readFileSync|readdir|readdirSync|stat|statSync|access|accessSync|keys|values|entries|stringify)$/,
    system_modification: /(?:^|\.)(?:writeFile|writeFileSync|appendFile|appendFileSync|copyFile|copyFileSync|rename|renameSync)$/,
    privilege_escalation: /(?:^|\.)(?:setuid|setgid|chmod|chmodSync|chown|chownSync|exec|execSync)$/,
    defense_evasion: /(?:^|\.)(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync|kill|exec|execSync|spawn|spawnSync)$/,
    network_egress: /^(?:(?:.*\.)?(?:fetch|get|request|connect|createConnection)|got\.stream)$/,
    data_exfiltration: /(?:^|\.)(?:fetch|post|put|patch|send|write|upload|putObject|sendCommand)$/,
    destructive_behavior: /(?:^|\.)(?:rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync|writeFile|writeFileSync|open|openSync)$/,
    interpreter_escape: /(?:^|\.)(?:exec|execSync|spawn|spawnSync)$/,
    second_stage_payload: /^(?:(?:.*\.)?(?:fetch|get|extract|unzip|tar)|unpack-stream\.remote)$/,
  },
};

function calleeOf(node: SyntaxNode): string {
  return node.childForFieldName("function")?.text
    ?? node.childForFieldName("constructor")?.text
    ?? "";
}

function moduleName(value: string): string {
  return value.replace(/^node:/, "").replace(/^["']|["']$/g, "");
}

function collectAliases(source: string, language: "python" | "javascript"): Map<string, string> {
  const aliases = new Map<string, string>();
  if (language === "python") {
    for (const match of source.matchAll(/^\s*import\s+([\w.]+)\s+as\s+(\w+)/gm)) {
      aliases.set(match[2]!, match[1]!);
    }
    for (const match of source.matchAll(/^\s*from\s+([\w.]+)\s+import\s+(\w+)(?:\s+as\s+(\w+))?/gm)) {
      aliases.set(match[3] ?? match[2]!, `${match[1]}.${match[2]}`);
    }
    return aliases;
  }

  for (const match of source.matchAll(
    /(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*(["'](?:node:)?[\w./-]+["'])\s*\)/g,
  )) {
    aliases.set(match[1]!, moduleName(match[2]!));
  }
  for (const match of source.matchAll(
    /(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*(["'](?:node:)?[\w./-]+["'])\s*\)\.(\w+)/g,
  )) {
    aliases.set(match[1]!, `${moduleName(match[2]!)}.${match[3]}`);
  }
  for (const match of source.matchAll(
    /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*(["'](?:node:)?[\w./-]+["'])\s*\)/g,
  )) {
    const module = moduleName(match[2]!);
    for (const binding of match[1]!.split(",")) {
      const [imported, local] = binding.trim().split(/\s*:\s*/);
      if (imported) aliases.set(local ?? imported, `${module}.${imported}`);
    }
  }
  for (const match of source.matchAll(
    /import\s+\*\s+as\s+(\w+)\s+from\s+(["'](?:node:)?[\w./-]+["'])/g,
  )) {
    aliases.set(match[1]!, moduleName(match[2]!));
  }
  for (const match of source.matchAll(
    /import\s+(\w+)\s+from\s+(["'](?:node:)?[\w./-]+["'])/g,
  )) {
    aliases.set(match[1]!, moduleName(match[2]!));
  }
  for (const match of source.matchAll(
    /import\s*\{([^}]+)\}\s*from\s*(["'](?:node:)?[\w./-]+["'])/g,
  )) {
    const module = moduleName(match[2]!);
    for (const binding of match[1]!.split(",")) {
      const parts = binding.trim().split(/\s+as\s+/);
      if (parts[0]) aliases.set(parts[1] ?? parts[0], `${module}.${parts[0]}`);
    }
  }
  return aliases;
}

function canonicalizeCallee(callee: string, aliases: Map<string, string>): string {
  const identifier = callee.match(/^[A-Za-z_$][\w$]*/)?.[0];
  if (!identifier) return callee;
  const replacement = aliases.get(identifier);
  return replacement ? `${replacement}${callee.slice(identifier.length)}` : callee;
}

function scanAstLanguage(
  source: string,
  language: "python" | "javascript",
  options: ScanOptions,
): ScanResult {
  const parser = language === "python" ? pythonParser : javascriptParser;
  const rules = language === "python" ? PYTHON_RULES : JAVASCRIPT_RULES;
  const maxEvidence = Math.max(40, options.maxEvidenceLength ?? 240);
  const tree = parser.parse(source);
  const findings: Finding[] = [];
  const parseErrors: SourceRange[] = [];
  const interestingNodes: SyntaxNode[] = [];
  const aliases = collectAliases(source, language);

  walk(tree.rootNode, (node) => {
    if (node.isError || node.isMissing) parseErrors.push(rangeOf(node));
    if ((language === "python" && node.type === "call")
      || (language === "javascript" && ["call_expression", "new_expression"].includes(node.type))) {
      interestingNodes.push(node);
    }
  });

  for (const node of interestingNodes) {
    const text = source.slice(node.startIndex, node.endIndex);
    const originalCallee = calleeOf(node);
    const callee = canonicalizeCallee(originalCallee, aliases);
    const analysisText = text.startsWith(originalCallee)
      ? `${callee}${text.slice(originalCallee.length)}`
      : text;
    if (
      language === "javascript"
      && /(?:^|\/)download\.download$/.test(callee)
      && /(?:url|uri|href)/i.test(
        node.childForFieldName("arguments")?.text ?? "",
      )
    ) {
      findings.push({
        ruleId: "javascript.network.download-wrapper",
        category: "network_egress",
        title: "Calls an imported URL download wrapper",
        severity: "medium",
        confidence: "medium",
        message: "A relative module named download is called with a URL-like argument.",
        evidence: evidence(text, maxEvidence),
        range: rangeOf(node),
        language,
      });
    }
    for (const rule of rules as LanguageRule[]) {
      if (!rule.nodeTypes.includes(node.type)) continue;
      const calleePattern = CALLEE_BY_CATEGORY[language][rule.category];
      if (!calleePattern?.test(callee)) continue;
      rule.pattern.lastIndex = 0;
      if (!rule.pattern.test(analysisText)) continue;
      if (rule.category === "download_execution" && isAllowedDownload(analysisText, options)) continue;
      if (rule.confidence === "low" && options.includeLowConfidence === false) continue;
      findings.push({
        ruleId: rule.id,
        category: rule.category,
        title: rule.title,
        severity: rule.severity,
        confidence: rule.confidence,
        message: rule.message,
        evidence: evidence(text, maxEvidence),
        range: rangeOf(node),
        language,
      });
    }
  }

  const callText = interestingNodes.map((node) => source.slice(node.startIndex, node.endIndex)).join("\n");
  const callees = interestingNodes.map(calleeOf);
  const rootRange = rangeOf(tree.rootNode);
  const addWholeSourceChain = (finding: Omit<Finding, "range" | "evidence" | "language">): void => {
    findings.push({
      ...finding,
      evidence: evidence(callText, maxEvidence),
      range: rootRange,
      language,
    });
  };
  const readCallee = language === "python"
    ? /(?:^|\.)(?:open|read_text|read_bytes)$/
    : /(?:^|\.)(?:readFile|readFileSync)$/;
  if (
    callees.some((callee) => readCallee.test(callee))
    && findings.some((finding) => finding.category === "data_exfiltration")
  ) {
    addWholeSourceChain({
      ruleId: `${language}.chain.read-upload`,
      category: "data_exfiltration",
      title: "Reads then uploads data",
      severity: "high",
      confidence: "medium",
      message: "Local data access and an outbound data sink occur in the same payload.",
    });
  }
  const downloadCallee = language === "python"
    ? /(?:^|\.)(?:get|urlopen|urlretrieve)$/
    : /(?:^|\.)(?:fetch|get)$/;
  if (
    callees.some((callee) => downloadCallee.test(callee))
    && findings.some((finding) => finding.category === "dynamic_execution")
    && !isAllowedDownload(callText, options)
  ) {
    addWholeSourceChain({
      ruleId: `${language}.chain.download-execute`,
      category: "download_execution",
      title: "Downloads then executes content",
      severity: "critical",
      confidence: "medium",
      message: "A network download and dynamic execution occur in the same payload.",
    });
  }

  const unique = [...new Map(findings.map((item) => [
    `${item.ruleId}:${item.range.startIndex}`,
    item,
  ])).values()].sort((a, b) => a.range.startIndex - b.range.startIndex);
  return { findings: unique, summary: emptySummary(unique), parseErrors };
}

function scanBash(source: string, options: ScanOptions): ScanResult {
  const maxEvidence = Math.max(40, options.maxEvidenceLength ?? 240);
  const tree = bashParser.parse(source);
  const commands = statements(tree.rootNode, source);
  const findings: Finding[] = [];
  const parseErrors: SourceRange[] = [];

  walk(tree.rootNode, (node) => {
    if (node.isError || node.isMissing) parseErrors.push(rangeOf(node));
  });

  for (const statement of commands) {
    for (const rule of COMMAND_RULES) {
      const matched = bashCommandVariants(statement.text).some((variant) => {
        rule.pattern.lastIndex = 0;
        return rule.pattern.test(variant);
      });
      if (!matched) continue;
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
        language: "bash",
      });
    }
  }

  // Same command/pipeline, e.g. curl URL | bash.
  walk(tree.rootNode, (node) => {
    // Compound syntax nodes represent real shell control flow. Scanning a
    // single command's raw text here would treat pipes inside quoted
    // documentation as executable pipelines.
    if (!["pipeline", "list"].includes(node.type)) return;
    const text = source.slice(node.startIndex, node.endIndex);
    if (DOWNLOAD.test(text) && EXECUTE.test(text) && !isAllowedDownload(text, options)) {
      addChainFinding(findings, { node, text, range: rangeOf(node) }, { node, text, range: rangeOf(node) }, {
        ruleId: "chain.download-execute",
        category: "download_execution",
        title: "Downloads and executes content",
        severity: "critical",
        confidence: "high",
        message: "Remote content flows into a shell or is made executable.",
        language: "bash",
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
        language: "bash",
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
        language: "bash",
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
          language: "bash",
        }, maxEvidence);
      }
    }
  }

  if ((options.maxEmbeddedDepth ?? 2) > 0) {
    const maxLength = Math.max(1, options.maxEmbeddedCodeLength ?? 100_000);
    for (const payload of extractEmbeddedPayloads(tree.rootNode)) {
      if (payload.source.length > maxLength) continue;
      const nested = scanAstLanguage(payload.source, payload.language, {
        ...options,
        language: payload.language,
        maxEmbeddedDepth: (options.maxEmbeddedDepth ?? 2) - 1,
      });
      for (const nestedFinding of nested.findings) {
        findings.push({
          ...nestedFinding,
          innerRange: nestedFinding.range,
          range: payload.range,
          origin: {
            language: "bash",
            interpreter: payload.interpreter,
            kind: payload.kind,
          },
        });
      }
    }
  }

  const unique = [...new Map(findings.map((item) => [
    `${item.ruleId}:${item.range.startIndex}:${item.relatedRanges?.[0]?.startIndex ?? ""}`,
    item,
  ])).values()].sort((a, b) => a.range.startIndex - b.range.startIndex);

  return {
    findings: unique,
    summary: emptySummary(unique),
    parseErrors,
  };
}

export function scan(source: string, options: ScanOptions = {}): ScanResult {
  const language: SupportedLanguage = options.language ?? "bash";
  if (language === "python") return scanAstLanguage(source, "python", options);
  if (language === "javascript" || language === "node") {
    return scanAstLanguage(source, "javascript", options);
  }
  return scanBash(source, options);
}

export function scanPython(source: string, options: Omit<ScanOptions, "language"> = {}): ScanResult {
  return scanAstLanguage(source, "python", options);
}

export function scanJavaScript(source: string, options: Omit<ScanOptions, "language"> = {}): ScanResult {
  return scanAstLanguage(source, "javascript", options);
}
