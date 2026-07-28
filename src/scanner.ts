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
    network_egress: /(?:^|\.)(?:get|post|put|patch|delete|head|options|request|ws_connect|urlopen|urlretrieve|socket|create_connection|open_connection|connect)$/,
    data_exfiltration: /(?:^|\.)(?:post|put|patch|upload_file|put_object|send|sendall|write)$/,
    destructive_behavior: /(?:^|\.)(?:rmtree|remove|unlink|removedirs|open)$/,
    interpreter_escape: /(?:^|\.)(?:system|popen|run|call|Popen|check_call|check_output|create_subprocess_shell)$/,
    second_stage_payload: /(?:^|\.)(?:get|urlretrieve|unpack_archive|open|ZipFile)$/,
  },
  javascript: {
    download_execution: /(?:^|\.)(?:eval|Function|exec|execSync|spawn|spawnSync)$/,
    dynamic_execution: /(?:^|\.)(?:eval|Function|runIn\w+|compileFunction|exec|execSync|spawn|spawnSync|execa|execaCommand)$/,
    persistence: /(?:^|\.)(?:writeFile|writeFileSync|appendFile|appendFileSync|copyFile|copyFileSync|rename|renameSync)$/,
    credential_access: /(?:^|\.)(?:readFile|readFileSync|readdir|readdirSync|stat|statSync|access|accessSync|keys|values|entries|stringify)$/,
    system_modification: /(?:^|\.)(?:writeFile|writeFileSync|appendFile|appendFileSync|copyFile|copyFileSync|rename|renameSync)$/,
    privilege_escalation: /(?:^|\.)(?:setuid|setgid|chmod|chmodSync|chown|chownSync|exec|execSync)$/,
    defense_evasion: /(?:^|\.)(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync|kill|exec|execSync|spawn|spawnSync)$/,
    network_egress: /^(?:(?:.*\.)?(?:fetch|get|request|stream|pipeline|connect|createConnection)|got\.stream|npm-registry-fetch)$/,
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

function executionScopeId(
  node: SyntaxNode,
  language: "python" | "javascript",
): number {
  const scopeTypes = language === "python"
    ? new Set(["function_definition", "lambda"])
    : new Set([
      "function_declaration",
      "function_expression",
      "arrow_function",
      "generator_function",
      "generator_function_declaration",
      "method_definition",
    ]);
  for (let current = node.parent; current; current = current.parent) {
    if (scopeTypes.has(current.type)) return current.id;
  }
  return node.tree.rootNode.id;
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
    for (const match of source.matchAll(/^\s*from\s+([\w.]+)\s+import\s+([^\n#]+)/gm)) {
      for (const binding of match[2]!.replace(/[()]/g, "").split(",")) {
        const parts = binding.trim().split(/\s+as\s+/);
        if (parts[0] && /^\w+$/.test(parts[0])) {
          aliases.set(parts[1] ?? parts[0], `${match[1]}.${parts[0]}`);
        }
      }
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
  const exactReplacement = aliases.get(callee);
  if (exactReplacement) return exactReplacement;
  let matchedPrefix = "";
  let prefixReplacement: string | undefined;
  for (const [candidate, replacement] of aliases) {
    if (
      candidate.includes(".")
      && callee.startsWith(`${candidate}.`)
      && candidate.length > matchedPrefix.length
    ) {
      matchedPrefix = candidate;
      prefixReplacement = replacement;
    }
  }
  if (prefixReplacement) {
    return `${prefixReplacement}${callee.slice(matchedPrefix.length)}`;
  }
  const identifier = callee.match(/^[A-Za-z_$][\w$]*/)?.[0];
  if (!identifier) return callee;
  const replacement = aliases.get(identifier);
  return replacement ? `${replacement}${callee.slice(identifier.length)}` : callee;
}

function collectPythonObjectBindings(
  root: SyntaxNode,
  aliases: Map<string, string>,
): void {
  walk(root, (node) => {
    if (node.type !== "function_definition") return;
    const name = node.childForFieldName("name")?.text;
    const body = node.childForFieldName("body");
    if (!name || !body) return;
    let socketFactory = false;
    walk(body, (child) => {
      if (child.type !== "return_statement") return;
      const returnedCall = child.namedChildren.find((candidate) => candidate.type === "call");
      if (!returnedCall) return;
      const returnedCallee = canonicalizeCallee(calleeOf(returnedCall), aliases);
      if (/^socket\.(?:socket|create_connection)$/.test(returnedCallee)) {
        socketFactory = true;
      }
    });
    if (socketFactory) aliases.set(`self.${name}`, "socket.socket");
  });

  walk(root, (node) => {
    let localName = "";
    let value: SyntaxNode | null = null;
    if (node.type === "assignment") {
      localName = node.childForFieldName("left")?.text ?? "";
      value = node.childForFieldName("right");
    } else if (node.type === "as_pattern") {
      localName = node.childForFieldName("alias")?.text
        ?? node.namedChildren.find((child) => child.type === "as_pattern_target")?.text
        ?? "";
      value = node.childForFieldName("value")
        ?? node.namedChildren.find((child) => child.type === "call")
        ?? null;
    }
    if (!/^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$/.test(localName) || value?.type !== "call") return;
    const constructor = canonicalizeCallee(calleeOf(value), aliases);
    if (
      constructor === "aiohttp.ClientSession"
      || constructor === "httpx.Client"
      || constructor === "httpx.AsyncClient"
      || constructor === "requests.Session"
      || constructor === "requests.session"
      || constructor === "twine.utils.make_requests_session"
      || constructor === "adafruit_shell.Shell"
      || constructor === "socket.socket"
      || constructor === "socket.create_connection"
    ) {
      aliases.set(
        localName,
        constructor === "twine.utils.make_requests_session"
          ? "requests.Session"
          : constructor,
      );
    }
  });
}

const SENSITIVE_ENVIRONMENT_NAME = /(?:^|[_-])(?:TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIALS?)(?:$|[_-])/i;

function quotedValue(text: string): string | undefined {
  const match = text.match(/^\s*["']([^"']+)["']\s*$/s);
  return match?.[1];
}

function environmentCredentialFinding(
  node: SyntaxNode,
  language: "python" | "javascript",
  aliases: Map<string, string>,
  javascriptShadows: Set<string>,
  maxEvidence: number,
): Finding | undefined {
  const text = node.text;
  let variableName: string | undefined;

  if (language === "python") {
    if (node.type === "subscript") {
      const value = node.childForFieldName("value")?.text ?? "";
      const canonicalValue = canonicalizeCallee(value, aliases);
      if (canonicalValue !== "os.environ") return undefined;
      const index = node.childForFieldName("subscript")?.text
        ?? node.namedChildren.at(-1)?.text
        ?? "";
      variableName = quotedValue(index);
    }
  } else if (node.type === "member_expression") {
    if (javascriptShadows.has("process")) return undefined;
    const property = node.childForFieldName("property")?.text ?? "";
    if (/^process\.env\.[A-Za-z_$][\w$]*$/.test(text)) {
      variableName = property;
    } else if (/^process\.env\s*\[/.test(text)) {
      variableName = quotedValue(property);
    }
  } else if (node.type === "subscript_expression") {
    if (javascriptShadows.has("process")) return undefined;
    if ((node.childForFieldName("object")?.text ?? "") !== "process.env") return undefined;
    variableName = quotedValue(node.childForFieldName("index")?.text ?? "");
  }

  if (!variableName || !SENSITIVE_ENVIRONMENT_NAME.test(variableName)) return undefined;
  return {
    ruleId: `${language}.environment-secret`,
    category: "credential_access",
    title: "Reads a credential-like environment variable",
    severity: "high",
    confidence: "high",
    message: "Reads a specifically named environment variable commonly used for credentials.",
    evidence: evidence(text, maxEvidence),
    range: rangeOf(node),
    language,
  };
}

function collectJavaScriptShadows(root: SyntaxNode): Set<string> {
  const shadows = new Set<string>();
  walk(root, (node) => {
    if (node.type === "function_declaration") {
      const name = node.childForFieldName("name")?.text;
      if (name) shadows.add(name);
      return;
    }
    if (node.type !== "variable_declarator") return;
    const name = node.childForFieldName("name")?.text;
    const value = node.childForFieldName("value");
    if (
      name
      && /^[A-Za-z_$][\w$]*$/.test(name)
      && !value?.text.startsWith("require(")
    ) {
      shadows.add(name);
    }
  });
  return shadows;
}

function collectJavaScriptDerivedAliases(
  root: SyntaxNode,
  aliases: Map<string, string>,
): void {
  walk(root, (node) => {
    if (node.type !== "variable_declarator") return;
    const name = node.childForFieldName("name")?.text;
    const value = node.childForFieldName("value");
    if (!name || value?.type !== "call_expression") return;
    const wrapper = canonicalizeCallee(calleeOf(value), aliases);
    if (wrapper !== "util.promisify") return;
    const argument = value.childForFieldName("arguments")?.namedChildren[0]?.text;
    if (!argument) return;
    const wrapped = canonicalizeCallee(argument, aliases);
    if (/^child_process\.(?:exec|execFile)$/.test(wrapped)) {
      aliases.set(name, wrapped);
    }
  });
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
  if (language === "python") collectPythonObjectBindings(tree.rootNode, aliases);
  if (language === "javascript") collectJavaScriptDerivedAliases(tree.rootNode, aliases);
  const javascriptShadows = language === "javascript"
    ? collectJavaScriptShadows(tree.rootNode)
    : new Set<string>();

  walk(tree.rootNode, (node) => {
    if (node.isError || node.isMissing) parseErrors.push(rangeOf(node));
    const environmentFinding = environmentCredentialFinding(
      node,
      language,
      aliases,
      javascriptShadows,
      maxEvidence,
    );
    if (environmentFinding) findings.push(environmentFinding);
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
    if (language === "python" && callee === "adafruit_shell.Shell.run_command") {
      if (/\b(?:curl|wget)\b/i.test(text)) {
        findings.push({
          ruleId: "python.wrapper.adafruit-shell-network",
          category: "network_egress",
          title: "Downloads through Adafruit Shell",
          severity: "medium",
          confidence: "high",
          message: "An Adafruit Shell command wrapper invokes a download utility.",
          evidence: evidence(text, maxEvidence),
          range: rangeOf(node),
          language,
        });
      }
      if (/\bsystemctl\s+enable\b/i.test(text)) {
        findings.push({
          ruleId: "python.wrapper.adafruit-shell-persistence",
          category: "persistence",
          title: "Enables a systemd service through Adafruit Shell",
          severity: "high",
          confidence: "high",
          message: "An Adafruit Shell command wrapper enables a service at boot.",
          evidence: evidence(text, maxEvidence),
          range: rangeOf(node),
          language,
        });
      }
    }
    if (
      language === "python"
      && /^adafruit_shell\.Shell\.(?:write_text_file|move|pattern_replace|remove)$/.test(callee)
      && /(?:\/etc\/|\/usr\/local\/|\/boot\/)/.test(text)
    ) {
      findings.push({
        ruleId: "python.wrapper.adafruit-shell-system",
        category: "system_modification",
        title: "Modifies a system path through Adafruit Shell",
        severity: "high",
        confidence: "high",
        message: "An Adafruit Shell file helper targets a system configuration or installation path.",
        evidence: evidence(text, maxEvidence),
        range: rangeOf(node),
        language,
      });
    }
    if (
      language === "python"
      && callee === "adafruit_shell.Shell.remove"
    ) {
      findings.push({
        ruleId: "python.wrapper.adafruit-shell-remove",
        category: "destructive_behavior",
        title: "Removes a file through Adafruit Shell",
        severity: "high",
        confidence: "high",
        message: "An Adafruit Shell helper removes an installed or configuration file.",
        evidence: evidence(text, maxEvidence),
        range: rangeOf(node),
        language,
      });
    }
    if (
      language === "python"
      && callee === "pyanaconda.core.util.execWithRedirect"
      && /["']auditctl["']/.test(text)
      && /["']-e["']\s*,\s*["']0["']/.test(text)
    ) {
      findings.push({
        ruleId: "python.defense-evasion.audit-disable",
        category: "defense_evasion",
        title: "Disables Linux auditing",
        severity: "critical",
        confidence: "high",
        message: "Invokes auditctl with parameters that disable kernel auditing.",
        evidence: evidence(text, maxEvidence),
        range: rangeOf(node),
        language,
      });
    }
    if (
      language === "python"
      && callee === "os.environ.get"
    ) {
      const argument = node.childForFieldName("arguments")?.namedChildren[0]?.text ?? "";
      const variableName = quotedValue(argument);
      if (variableName && SENSITIVE_ENVIRONMENT_NAME.test(variableName)) {
        findings.push({
          ruleId: "python.environment-secret",
          category: "credential_access",
          title: "Reads a credential-like environment variable",
          severity: "high",
          confidence: "high",
          message: "Reads a specifically named environment variable commonly used for credentials.",
          evidence: evidence(text, maxEvidence),
          range: rangeOf(node),
          language,
        });
      }
    }
    if (
      language === "javascript"
      && /^execa\.(?:execa|execaCommand)$/.test(callee)
      && /^\s*[\w$]+\s*\(\s*["']git["']\s*,\s*\[\s*["']push["']/s.test(text)
    ) {
      findings.push({
        ruleId: "javascript.exfiltration.git-push",
        category: "data_exfiltration",
        title: "Pushes local repository data to a remote",
        severity: "high",
        confidence: "high",
        message: "A confirmed execa import invokes git push with static arguments.",
        evidence: evidence(text, maxEvidence),
        range: rangeOf(node),
        language,
      });
    }
    const javascriptRoot = originalCallee.match(/^[A-Za-z_$][\w$]*/)?.[0];
    const importedJavaScriptModule = javascriptRoot
      ? aliases.get(javascriptRoot)
      : undefined;
    if (
      language === "javascript"
      && (
        callee === "rimraf.rimraf"
        || callee === "rimraf.rimrafSync"
        || (
          importedJavaScriptModule === "rimraf"
          && /^(?:rimraf|rimraf\.sync)$/.test(originalCallee)
        )
      )
    ) {
      findings.push({
        ruleId: "javascript.destructive.rimraf",
        category: "destructive_behavior",
        title: "Recursively removes files with rimraf",
        severity: "high",
        confidence: "high",
        message: "A function imported from the rimraf package recursively removes a path.",
        evidence: evidence(text, maxEvidence),
        range: rangeOf(node),
        language,
      });
    }
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
      if (
        language === "javascript"
        && javascriptRoot
        && javascriptShadows.has(javascriptRoot)
        && !aliases.has(javascriptRoot)
        && [
          "download_execution",
          "dynamic_execution",
          "network_egress",
          "privilege_escalation",
          "interpreter_escape",
        ].includes(rule.category)
      ) continue;
      if (
        language === "javascript"
        && rule.category === "network_egress"
        && originalCallee === "fetch"
        && javascriptShadows.has("fetch")
      ) continue;
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
  const canonicalCalls = interestingNodes.map((node) => ({
    callee: canonicalizeCallee(calleeOf(node), aliases),
    text: source.slice(node.startIndex, node.endIndex),
    scopeId: executionScopeId(node, language),
    startIndex: node.startIndex,
  }));
  const scopesWithFinding = (category: Finding["category"]): Set<number> =>
    new Set(findings
      .filter((finding) => finding.category === category)
      .flatMap((finding) => {
        const call = canonicalCalls.find((candidate) =>
          candidate.startIndex === finding.range.startIndex,
        );
        return call ? [call.scopeId] : [];
      }));
  const rootRange = rangeOf(tree.rootNode);
  const addWholeSourceChain = (finding: Omit<Finding, "range" | "evidence" | "language">): void => {
    findings.push({
      ...finding,
      evidence: evidence(callText, maxEvidence),
      range: rootRange,
      language,
    });
  };
  if (
    language === "python"
    && canonicalCalls.some((call) =>
      call.callee === "adafruit_shell.Shell.run_command"
      && /\b(?:curl|wget)\b/i.test(call.text),
    )
    && canonicalCalls.some((call) =>
      (
        call.callee === "adafruit_shell.Shell.move"
        && /\/usr\/local\/bin\//.test(call.text)
      )
      || (
        call.callee === "os.chmod"
        && /\/usr\/local\/bin\//.test(call.text)
      ),
    )
  ) {
    addWholeSourceChain({
      ruleId: "python.chain.adafruit-download-install",
      category: "download_execution",
      title: "Downloads and installs an executable through Adafruit Shell",
      severity: "critical",
      confidence: "high",
      message: "A wrapped download is moved into an executable system path or made executable.",
    });
  }
  const readCallee = language === "python"
    ? /(?:^|\.)(?:open|read_text|read_bytes)$/
    : /(?:^|\.)(?:readFile|readFileSync)$/;
  const exfiltrationScopes = scopesWithFinding("data_exfiltration");
  if (
    canonicalCalls.some((readCall) =>
      readCallee.test(readCall.callee)
      && exfiltrationScopes.has(readCall.scopeId),
    )
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
  const dynamicExecutionScopes = scopesWithFinding("dynamic_execution");
  if (
    canonicalCalls.some((downloadCall) =>
      downloadCallee.test(downloadCall.callee)
      && dynamicExecutionScopes.has(downloadCall.scopeId),
    )
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
