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

function staticBashCommandWrappers(source: string): Map<string, Set<string>> {
  const wrappers = new Map<string, Set<string>>();
  for (const match of source.matchAll(
    /^\s*([A-Za-z_]\w*)\s*=\s*(?:(["'])([^"'$\r\n]+)\2|(sudo|doas))\s*$/gmi,
  )) {
    const name = match[1]!;
    const command = (match[3] ?? match[4])!.trim().replace(/\s+/g, " ").toLowerCase();
    if (
      !/^(?:(?:ba)?sh\s+-c|su\s+-c|(?:sudo|doas)(?:\s+(?:-[a-z]+|--[\w-]+(?:=\S+)?))*(?:\s+(?:ba)?sh\s+-c)?)$/i
        .test(command)
    ) continue;
    const commands = wrappers.get(name) ?? new Set<string>();
    commands.add(command);
    wrappers.set(name, commands);
  }
  return wrappers;
}

function bashFunctionSummaries(source: string): {
  transparent: Set<string>;
  downloaders: Set<string>;
} {
  const transparent = new Set<string>();
  const downloaders = new Set<string>();
  for (const match of source.matchAll(
    /^[ \t]*(?:function[ \t]+)?([A-Za-z_]\w*)[ \t]*(?:\(\s*\))?[ \t]*\{([\s\S]*?)^[ \t]*\}/gm,
  )) {
    const name = match[1]!;
    const body = match[2]!;
    if (
      /(?:^|\n)[ \t]*(?:(?:if|while|until)[ \t]+![ \t]+|![ \t]+)?["']?\$@["']?(?:[ \t;]|$)/m
        .test(body)
    ) {
      transparent.add(name);
    }
    if (/\b(?:curl|wget)\b/.test(body) && /\$1\b/.test(body) && /\$2\b/.test(body)) {
      downloaders.add(name);
    }
  }
  return { transparent, downloaders };
}

const SHELL_STARTUP_PATH = /(?:^|[/.])(?:bashrc|bash_profile|profile|zshrc|zprofile|config\.fish)(?:["'\s]|$)/i;

function bashShellStartupVariables(source: string): Set<string> {
  const variables = new Set<string>();
  for (const match of source.matchAll(
    /^[ \t]*([A-Za-z_]\w*)[ \t]*=[ \t]*([^\r\n]*)$/gm,
  )) {
    if (SHELL_STARTUP_PATH.test(match[2]!)) variables.add(match[1]!);
  }
  for (const match of source.matchAll(
    /^[ \t]*([A-Za-z_]\w*)[ \t]*\+?=[ \t]*\(([\s\S]*?)^[ \t]*\)/gm,
  )) {
    if (SHELL_STARTUP_PATH.test(match[2]!)) variables.add(match[1]!);
  }
  // Propagate an array of known startup paths into its loop variable.
  for (const match of source.matchAll(
    /\bfor[ \t]+([A-Za-z_]\w*)[ \t]+in[ \t]+["']?\$\{([A-Za-z_]\w*)\[@\]\}["']?/g,
  )) {
    if (variables.has(match[2]!)) variables.add(match[1]!);
  }
  return variables;
}

function bashArchiveOutputVariable(text: string): string | undefined {
  if (!/\b(?:curl|wget|fetch|aria2c)\b/i.test(text)) return undefined;
  const output = text.match(
    /(?:--output(?:=|\s+)|-o\s+|--output-document(?:=|\s+)|-O\s+)(["']?\$(?:\{)?([A-Za-z_]\w*)\}?(?:\.(?:zip|tar|tgz|gz|bz2|xz))?["']?)/i,
  );
  if (!output || !/\.(?:zip|tar|tgz|gz|bz2|xz)\b/i.test(output[1]!)) return undefined;
  return output[2];
}

function normalizedStaticBashPath(text: string): string | undefined {
  const value = text.trim().replace(/^(["'])(.*)\1$/, "$2");
  if (!value || /[$`;&|<>\s]/.test(value)) return undefined;
  return value.replace(/^\.\//, "");
}

function bashStaticDownloadOutput(text: string): string | undefined {
  if (!/^\s*(?:curl|wget)\b/i.test(text)) return undefined;
  const explicit = /^\s*curl\b/i.test(text)
    ? text.match(
      /(?:^|\s)(?:-o|--output(?:=|\s+))\s*(["']?[^"'$\s;|&<>]+["']?)/i,
    )
    : text.match(
      /(?:^|\s)(?:-O|--output-document(?:=|\s+))\s*(["']?[^"'$\s;|&<>]+["']?)/,
    );
  if (explicit) return normalizedStaticBashPath(explicit[1]!);

  if (/^\s*curl\b/i.test(text) && /(?:^|\s)-[A-Za-z]*O[A-Za-z]*(?:\s|$)/.test(text)) {
    const remote = text.match(/https?:\/\/[^"'$\s;|&<>]+/i)?.[0];
    if (!remote) return undefined;
    try {
      const pathname = new URL(remote).pathname.replace(/\/+$/, "");
      return normalizedStaticBashPath(pathname.slice(pathname.lastIndexOf("/") + 1));
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function bashCommandReferencesPath(text: string, path: string): boolean {
  const escaped = path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?:^|\\s)["']?(?:\\./)?${escaped}["']?(?:\\s|$)`).test(text);
}

function bashInvokesVariable(text: string, variable: string): boolean {
  const escaped = variable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(
    `^\\s*(?:(?:[A-Za-z_]\\w*=\\S+|env)\\s+)*["']?\\$(?:\\{)?${escaped}\\}?["']?(?:\\s|$)`,
  ).test(text);
}

function bashVariableSubcommand(
  text: string,
  variable: string,
): string | undefined {
  const escaped = variable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return text.match(
    new RegExp(
      `^\\s*(?:(?:[A-Za-z_]\\w*=\\S+|env)\\s+)*["']?\\$(?:\\{)?${escaped}\\}?["']?\\s+(eval|run)(?:\\s|$)`,
      "i",
    ),
  )?.[1]?.toLowerCase();
}

function staticBashPathArgument(text: string): string | undefined {
  const match = text.trim().match(/^(["']?)([^"'$\s;|&<>]+)\1$/);
  return match?.[2];
}

function staticBashWords(text: string): string[] {
  return [...text.matchAll(/"(?:\\.|[^"])*"|'[^']*'|[^\s]+/g)]
    .map((match) => match[0]!.replace(/^(["'])(.*)\1$/, "$2"));
}

function isRsyncRemoteOperand(value: string): boolean {
  if (
    !value
    || /[$`;&|<>]/.test(value)
    || /^(?:\.{0,2}\/|[A-Za-z]:[\\/])/.test(value)
  ) return false;
  if (/^rsync:\/\/[^/\s]+\/\S+/i.test(value)) return true;
  return /^(?:(?:[A-Za-z_][\w.-]*)@)?(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\]):{1,2}\S+$/
    .test(value);
}

function bashRsyncPushesLocalPath(text: string): boolean {
  const words = staticBashWords(text);
  if (words[0]?.toLowerCase() !== "rsync") return false;

  const operands: string[] = [];
  const longOptionsWithValue = new Set([
    "--backup-dir", "--bwlimit", "--chmod", "--compare-dest", "--contimeout",
    "--copy-dest", "--exclude", "--files-from", "--filter", "--groupmap",
    "--include", "--link-dest", "--log-file", "--max-size", "--min-size",
    "--password-file", "--partial-dir", "--port", "--rsync-path", "--rsh",
    "--temp-dir", "--timeout", "--usermap",
  ]);
  let optionsEnded = false;
  for (let index = 1; index < words.length; index += 1) {
    const word = words[index]!;
    if (!optionsEnded && word === "--") {
      optionsEnded = true;
      continue;
    }
    if (!optionsEnded && (word === "--dry-run" || /^-[A-Za-z]*n[A-Za-z]*$/.test(word))) {
      return false;
    }
    if (!optionsEnded && word.startsWith("--")) {
      const option = word.split("=", 1)[0]!;
      if (!word.includes("=") && longOptionsWithValue.has(option)) index += 1;
      continue;
    }
    if (!optionsEnded && /^-[^-]/.test(word)) {
      if (/^-(?:e|f)$/.test(word)) index += 1;
      continue;
    }
    operands.push(word);
  }

  if (operands.length < 2 || !isRsyncRemoteOperand(operands.at(-1)!)) return false;
  const sources = operands.slice(0, -1);
  return sources.every((source) => !isRsyncRemoteOperand(source))
    && sources.some((source) =>
      source.length > 0
      && !/[$`;&|<>]/.test(source)
      && !isRsyncRemoteOperand(source)
    );
}

function bashDiscoveredCommandVariables(
  root: SyntaxNode,
  commandPattern: RegExp,
): Set<string> {
  const assignments = new Map<string, boolean>();
  for (const assignment of root.descendantsOfType("variable_assignment")) {
    const name = assignment.childForFieldName("name")?.text;
    const value = assignment.childForFieldName("value");
    if (!name) continue;
    const commands = value?.type === "command_substitution"
      ? value.descendantsOfType("command")
      : [];
    const trusted = commands.length > 0
      && commands.every((command) => {
        commandPattern.lastIndex = 0;
        return commandPattern.test(command.text);
      });
    assignments.set(name, (assignments.get(name) ?? true) && trusted);
  }
  return new Set(
    [...assignments]
      .filter(([, trusted]) => trusted)
      .map(([name]) => name),
  );
}

function bashCommandVariants(
  text: string,
  commandWrappers: Map<string, Set<string>> = new Map(),
  transparentWrappers: Set<string> = new Set(),
): string[] {
  const initial = [text];
  const wrapped = text.match(/^\s*\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))\s+/);
  const wrapperName = wrapped?.[1] ?? wrapped?.[2];
  if (wrapperName) {
    const remainder = text.slice(wrapped![0].length);
    for (const command of commandWrappers.get(wrapperName) ?? []) {
      initial.push(`${command} ${remainder}`);
    }
  }

  const variants = new Set<string>(initial);
  for (const start of initial) {
    let current = start;
    for (let depth = 0; depth < 4; depth++) {
      let next = current;
      const firstCommand = next.match(/^\s*([A-Za-z_]\w*)\s+/)?.[1];
      if (firstCommand && transparentWrappers.has(firstCommand)) {
        next = next.replace(/^\s*[A-Za-z_]\w*\s+/, "");
      }
      next = next.replace(
        /^\s*(?:command|builtin)\s+(?:(?:-p|--)\s+)*/i,
        "",
      );
      next = next.replace(
        /^\s*env\s+(?:(?:-[A-Za-z]+|--[\w-]+(?:=\S+)?|[A-Za-z_]\w*=\S+)\s+)*/i,
        "",
      );
      next = next.replace(
        /^\s*(?:(?:sudo|doas|\/usr\/bin\/sudo)(?:\s+(?:-[A-Za-z]+|--[\w-]+(?:=\S+)?))*|su\s+-c|nohup|execute_sudo|execute|retry)\s+/i,
        "",
      );
      next = next.replace(/^\s*(?:ba)?sh\s+-c\s+/i, "");
      next = next.replace(/^\s*(["'])([^"']+)\1/, "$2");
      if (next === current) break;
      variants.add(next);
      current = next;
    }
  }
  return [...variants];
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
    network_egress: /(?:^|\.)(?:get|post|put|patch|delete|head|options|request|ws_connect|urlopen|urlretrieve|socket|create_connection|open_connection|connect|upload_file|http_stream_backoff|fetch_url)$/,
    data_exfiltration: /(?:^|\.)(?:post|put|patch|upload_file|put_object|send|sendall|write)$/,
    destructive_behavior: /(?:^|\.)(?:rmtree|removedirs|open)$/,
    interpreter_escape: /(?:^|\.)(?:system|popen|run|call|Popen|check_call|check_output|create_subprocess_shell)$/,
    second_stage_payload: /(?:^|\.)(?:get|urlretrieve|unpack_archive|open|ZipFile)$/,
  },
  javascript: {
    download_execution: /^(?:eval|Function|child_process\.(?:exec|execSync|spawn|spawnSync))$/,
    dynamic_execution: /^(?:eval|Function|vm\.(?:runIn\w+|compileFunction)|child_process\.(?:exec|execSync|spawn|spawnSync)|execa\.(?:execa|execaCommand))$/,
    persistence: /(?:^|\.)(?:writeFile|writeFileSync|appendFile|appendFileSync|copyFile|copyFileSync|rename|renameSync)$/,
    credential_access: /(?:^|\.)(?:readFile|readFileSync|readdir|readdirSync|stat|statSync|access|accessSync|keys|values|entries|stringify)$/,
    system_modification: /(?:^|\.)(?:writeFile|writeFileSync|appendFile|appendFileSync|copyFile|copyFileSync|rename|renameSync)$/,
    privilege_escalation: /(?:^|\.)(?:setuid|setgid|chmod|chmodSync|chown|chownSync|exec|execSync)$/,
    defense_evasion: /(?:^|\.)(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync|kill|exec|execSync|spawn|spawnSync)$/,
    network_egress: /^(?:(?:.*\.)?(?:fetch|get|request|stream|pipeline|connect|createConnection)|got\.stream|node-fetch|npm-registry-fetch)$/,
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

function bashExecutionScopeId(node: SyntaxNode): number {
  for (let current = node.parent; current; current = current.parent) {
    if (current.type === "function_definition") return current.id;
  }
  return node.tree.rootNode.id;
}

function moduleName(value: string): string {
  return value.replace(/^["']|["']$/g, "").replace(/^node:/, "");
}

function collectAliases(source: string, language: "python" | "javascript"): Map<string, string> {
  const aliases = new Map<string, string>();
  if (language === "python") {
    for (const match of source.matchAll(/^\s*import\s+([\w.]+)\s+as\s+(\w+)/gm)) {
      aliases.set(match[2]!, match[1]!);
    }
    for (const match of source.matchAll(
      /^\s*from\s+([\w.]+)\s+import\s+(?:\(([\s\S]*?)^\s*\)|([^\n#]+))/gm,
    )) {
      const importedBindings = (match[2] ?? match[3] ?? "").replace(/#[^\n]*/g, "");
      for (const binding of importedBindings.split(",")) {
        const parts = binding.trim().split(/\s+as\s+/);
        if (parts[0] && /^\w+$/.test(parts[0])) {
          aliases.set(parts[1] ?? parts[0], `${match[1]}.${parts[0]}`);
        }
      }
    }
    return aliases;
  }

  for (const match of source.matchAll(
    /(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*(["'](?:node:)?[@\w./-]+["'])\s*\)/g,
  )) {
    aliases.set(match[1]!, moduleName(match[2]!));
  }
  for (const match of source.matchAll(
    /(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*(["'](?:node:)?[@\w./-]+["'])\s*\)\.(\w+)/g,
  )) {
    aliases.set(match[1]!, `${moduleName(match[2]!)}.${match[3]}`);
  }
  for (const match of source.matchAll(
    /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*(["'](?:node:)?[@\w./-]+["'])\s*\)/g,
  )) {
    const module = moduleName(match[2]!);
    for (const binding of match[1]!.split(",")) {
      const [imported, local] = binding.trim().split(/\s*:\s*/);
      if (imported) aliases.set(local ?? imported, `${module}.${imported}`);
    }
  }
  for (const match of source.matchAll(
    /import\s+\*\s+as\s+(\w+)\s+from\s+(["'](?:node:)?[@\w./-]+["'])/g,
  )) {
    aliases.set(match[1]!, moduleName(match[2]!));
  }
  for (const match of source.matchAll(
    /import\s+(\w+)\s+from\s+(["'](?:node:)?[@\w./-]+["'])/g,
  )) {
    aliases.set(match[1]!, moduleName(match[2]!));
  }
  for (const match of source.matchAll(
    /import\s*\{([^}]+)\}\s*from\s*(["'](?:node:)?[@\w./-]+["'])/g,
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

function collectPythonObjectBindingNode(
  node: SyntaxNode,
  aliases: Map<string, string>,
): void {
  if (node.type === "return_statement") {
    const returnedCall = node.namedChildren.find((candidate) => candidate.type === "call");
    const returnedCallee = returnedCall
      ? canonicalizeCallee(calleeOf(returnedCall), aliases)
      : "";
    if (/^socket\.(?:socket|create_connection)$/.test(returnedCallee)) {
      for (let current = node.parent; current; current = current.parent) {
        if (current.type !== "function_definition") continue;
        const name = current.childForFieldName("name")?.text;
        if (name) aliases.set(`self.${name}`, "socket.socket");
        break;
      }
    }
    return;
  }

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
    || constructor === "s3transfer.S3Transfer"
  ) {
    aliases.set(
      localName,
      constructor === "twine.utils.make_requests_session"
        ? "requests.Session"
        : constructor,
    );
  }
}

function collectPythonSocketFactories(
  root: SyntaxNode,
  aliases: Map<string, string>,
): void {
  for (const node of root.descendantsOfType("return_statement")) {
    collectPythonObjectBindingNode(node, aliases);
  }
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
  let text = "";
  let variableName: string | undefined;

  if (language === "python") {
    if (node.type !== "subscript") return undefined;
    text = node.text;
    const value = node.childForFieldName("value")?.text ?? "";
    const canonicalValue = canonicalizeCallee(value, aliases);
    if (canonicalValue !== "os.environ") return undefined;
    const index = node.childForFieldName("subscript")?.text
      ?? node.namedChildren.at(-1)?.text
      ?? "";
    variableName = quotedValue(index);
  } else if (node.type === "member_expression") {
    text = node.text;
    if (javascriptShadows.has("process")) return undefined;
    const property = node.childForFieldName("property")?.text ?? "";
    if (/^process\.env\.[A-Za-z_$][\w$]*$/.test(text)) {
      variableName = property;
    } else if (/^process\.env\s*\[/.test(text)) {
      variableName = quotedValue(property);
    }
  } else if (node.type === "subscript_expression") {
    text = node.text;
    if (javascriptShadows.has("process")) return undefined;
    if ((node.childForFieldName("object")?.text ?? "") !== "process.env") return undefined;
    variableName = quotedValue(node.childForFieldName("index")?.text ?? "");
  } else {
    return undefined;
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

function collectJavaScriptDerivedAliases(
  root: SyntaxNode,
  aliases: Map<string, string>,
  uploads: Set<string>,
): Set<string> {
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
    if (
      name
      && /^[A-Za-z_$][\w$]*$/.test(name)
      && value?.type === "object"
      && /(?:method\s*:\s*["'](?:POST|PUT|PATCH)["'])/i.test(value.text)
      && /\bdata\s*:\s*(?:await\s+)?readFile\s*\(/s.test(value.text)
    ) {
      uploads.add(name);
    }
    if (
      name
      && /^[A-Za-z_$][\w$]*$/.test(name)
      && value?.type === "new_expression"
    ) {
      const constructor = canonicalizeCallee(calleeOf(value), aliases);
      if (constructor === "Octokit") {
        aliases.set(name, "octokit.Client");
        return;
      }
      if (constructor === "@google-cloud/storage.Storage") {
        aliases.set(name, constructor);
        return;
      }
    }
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
  return shadows;
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
  const javascriptUploadObjects = new Set<string>();
  let javascriptShadows = new Set<string>();
  if (language === "python") collectPythonSocketFactories(tree.rootNode, aliases);
  if (language === "javascript") {
    javascriptShadows = collectJavaScriptDerivedAliases(
      tree.rootNode,
      aliases,
      javascriptUploadObjects,
    );
  }

  walk(tree.rootNode, (node) => {
    if (language === "python") collectPythonObjectBindingNode(node, aliases);
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
    if (
      language === "javascript"
      && callee === "libnpmpublish.publish"
    ) {
      findings.push({
        ruleId: "javascript.network.libnpmpublish",
        category: "network_egress",
        title: "Publishes a package through libnpmpublish",
        severity: "medium",
        confidence: "high",
        message: "A function proven to come from libnpmpublish uploads to an npm registry.",
        evidence: evidence(text, maxEvidence),
        range: rangeOf(node),
        language,
      });
      findings.push({
        ruleId: "javascript.exfiltration.libnpmpublish",
        category: "data_exfiltration",
        title: "Uploads package data through libnpmpublish",
        severity: "high",
        confidence: "high",
        message: "A function proven to come from libnpmpublish uploads package data.",
        evidence: evidence(text, maxEvidence),
        range: rangeOf(node),
        language,
      });
    }
    if (
      language === "javascript"
      && callee === "octokit.Client.request"
    ) {
      const argumentsNode = node.childForFieldName("arguments");
      const firstArgument = argumentsNode?.namedChildren[0]?.text ?? "";
      const isGithubRoute = /["'](?:GET|POST|PUT|PATCH|DELETE) \/repos\//i.test(firstArgument);
      const isUpload = javascriptUploadObjects.has(firstArgument)
        || (
          argumentsNode?.namedChildren[0]?.type === "object"
          && /(?:method\s*:\s*["'](?:POST|PUT|PATCH)["'])/i.test(firstArgument)
          && /\bdata\s*:\s*(?:await\s+)?readFile\s*\(/s.test(firstArgument)
        );
      if (isGithubRoute || isUpload) {
        findings.push({
          ruleId: "javascript.network.octokit-request",
          category: "network_egress",
          title: "Calls the GitHub API through Octokit",
          severity: "medium",
          confidence: "high",
          message: "An Octokit instance sends a GitHub REST API request.",
          evidence: evidence(text, maxEvidence),
          range: rangeOf(node),
          language,
        });
      }
      if (isUpload) {
        findings.push({
          ruleId: "javascript.exfiltration.octokit-upload",
          category: "data_exfiltration",
          title: "Uploads file data through Octokit",
          severity: "high",
          confidence: "high",
          message: "An Octokit request uploads data read from a local file.",
          evidence: evidence(text, maxEvidence),
          range: rangeOf(node),
          language,
        });
      }
    }
    if (
      language === "javascript"
      && /^@google-cloud\/storage\.Storage\.bucket\([^)]*\)\.upload$/.test(callee)
    ) {
      findings.push({
        ruleId: "javascript.network.google-cloud-storage-upload",
        category: "network_egress",
        title: "Uploads to Google Cloud Storage",
        severity: "medium",
        confidence: "high",
        message: "A source-bound Google Cloud Storage client uploads an object.",
        evidence: evidence(text, maxEvidence),
        range: rangeOf(node),
        language,
      });
      findings.push({
        ruleId: "javascript.exfiltration.google-cloud-storage-upload",
        category: "data_exfiltration",
        title: "Uploads a local file to Google Cloud Storage",
        severity: "high",
        confidence: "high",
        message: "A source-bound Google Cloud Storage client uploads a local file path.",
        evidence: evidence(text, maxEvidence),
        range: rangeOf(node),
        language,
      });
    }
    if (
      language === "javascript"
      && /^execa\.(?:execa|execaCommand)$/.test(callee)
      && /^\s*[\w$]+\s*\(\s*["']npm["']\s*,\s*\[\s*["']publish["']/s.test(text)
    ) {
      findings.push({
        ruleId: "javascript.network.npm-publish",
        category: "network_egress",
        title: "Publishes a package to an npm registry",
        severity: "medium",
        confidence: "high",
        message: "A confirmed execa import invokes npm publish with static arguments.",
        evidence: evidence(text, maxEvidence),
        range: rangeOf(node),
        language,
      });
      findings.push({
        ruleId: "javascript.exfiltration.npm-publish",
        category: "data_exfiltration",
        title: "Uploads a package to an npm registry",
        severity: "high",
        confidence: "high",
        message: "A confirmed execa import invokes npm publish with static arguments.",
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
  const scopeByCallStart = new Map(
    canonicalCalls.map((call) => [call.startIndex, call.scopeId]),
  );
  const scopesWithFinding = (category: Finding["category"]): Set<number> =>
    new Set(findings
      .filter((finding) => finding.category === category)
      .flatMap((finding) => {
        const scopeId = scopeByCallStart.get(finding.range.startIndex);
        return scopeId === undefined ? [] : [scopeId];
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
  const commandWrappers = staticBashCommandWrappers(source);
  const functionSummaries = bashFunctionSummaries(source);
  const definedFunctions = new Set(
    tree.rootNode.descendantsOfType("function_definition")
      .map((node) => node.childForFieldName("name")?.text)
      .filter((name): name is string => name !== undefined),
  );
  const shellStartupVariables = bashShellStartupVariables(source);
  const discoveredPythonVariables = bashDiscoveredCommandVariables(
    tree.rootNode,
    /^(?:which|command\s+-v)\s+python(?:\d+(?:\.\d+)*)?\s*$/,
  );
  const discoveredGpgVariables = bashDiscoveredCommandVariables(
    tree.rootNode,
    /^(?:which|command\s+-v)\s+gpg2?\s*$/,
  );

  walk(tree.rootNode, (node) => {
    if (node.isError || node.isMissing) parseErrors.push(rangeOf(node));
    if (node.type !== "redirected_statement") return;
    const text = source.slice(node.startIndex, node.endIndex);
    const targetVariable = text.match(/>>?\s*["']?\$(?:\{)?([A-Za-z_]\w*)\}?["']?\s*$/)?.[1];
    const writesStartupPath = targetVariable !== undefined
      && shellStartupVariables.has(targetVariable);
    if (!writesStartupPath) return;
    findings.push({
      ruleId: "persistence.shell-rc-variable",
      category: "persistence",
      title: "Modifies a shell startup file",
      severity: "high",
      confidence: "high",
      message: "Redirects generated shell configuration into a variable proven to reference a startup file.",
      evidence: evidence(text, maxEvidence),
      range: rangeOf(node),
      language: "bash",
    });
  });

  const commandVariants = commands.map((statement) => ({
    statement,
    scopeId: bashExecutionScopeId(statement.node),
    variants: bashCommandVariants(
      statement.text,
      commandWrappers,
      functionSummaries.transparent,
    ),
  }));
  for (const { statement, variants } of commandVariants) {
    if (variants.some((variant) => bashRsyncPushesLocalPath(variant))) {
      findings.push({
        ruleId: "exfil.rsync-push",
        category: "data_exfiltration",
        title: "Uploads local data with rsync",
        severity: "high",
        confidence: "high",
        message: "Transfers one or more static local paths to a remote rsync destination.",
        evidence: evidence(statement.text, maxEvidence),
        range: statement.range,
        language: "bash",
      });
    }
    for (const rule of COMMAND_RULES) {
      if (
        (rule.id === "system.backup-disable" || rule.id === "destructive.backup-disable")
        && definedFunctions.has("tmutil")
        && /^\s*(?:tmutil\b|["']tmutil["'](?:\s|$))/.test(statement.text)
      ) continue;
      const matched = variants.some((variant) => {
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
    for (const variable of discoveredPythonVariables) {
      const escapedVariable = variable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      if (!variants.some((variant) =>
        new RegExp(
          `^\\s*["']?\\$(?:\\{)?${escapedVariable}\\}?["']?\\s+-c(?:\\s|$)`,
        ).test(variant),
      )) continue;
      findings.push({
        ruleId: "escape.discovered-python",
        category: "interpreter_escape",
        title: "Invokes a discovered Python interpreter",
        severity: "medium",
        confidence: "high",
        message: "Invokes a variable proven to select from Python interpreter executables.",
        evidence: evidence(statement.text, maxEvidence),
        range: statement.range,
        language: "bash",
      }, {
        ruleId: "dynamic.discovered-python-command",
        category: "dynamic_execution",
        title: "Executes inline Python code",
        severity: "high",
        confidence: "high",
        message: "Passes inline code to a variable proven to reference a Python interpreter.",
        evidence: evidence(statement.text, maxEvidence),
        range: statement.range,
        language: "bash",
      });
    }
    for (const variable of discoveredGpgVariables) {
      const escapedVariable = variable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const invokesSymmetricEncryption = variants.some((variant) =>
        new RegExp(
          `^\\s*["']?\\$(?:\\{)?${escapedVariable}\\}?["']?(?=[^;\\n]*(?:^|\\s)(?:-c|--symmetric)(?:\\s|$))(?=[^;\\n]*(?:^|\\s)(?:-o|--output)(?:=|\\s))`,
        ).test(variant),
      );
      if (!invokesSymmetricEncryption) continue;
      findings.push({
        ruleId: "destructive.discovered-gpg-encryption",
        category: "destructive_behavior",
        title: "Encrypts a file with a discovered GPG executable",
        severity: "critical",
        confidence: "high",
        message: "Invokes a variable proven to reference GPG with symmetric encryption and an explicit output file.",
        evidence: evidence(statement.text, maxEvidence),
        range: statement.range,
        language: "bash",
      });
    }
  }

  walk(tree.rootNode, (node) => {
    if (node.type !== "for_statement") return;
    const loopVariable = node.childForFieldName("variable")?.text;
    const substitution = node.childForFieldName("value");
    const body = node.childForFieldName("body");
    if (!loopVariable || substitution?.type !== "command_substitution" || !body) return;
    const escapedVariable = loopVariable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    const findsNetrc = substitution.descendantsOfType("command").some((command) =>
      /^\s*find(?:\s|$)/.test(command.text)
      && /(?:^|\s)-(?:i?name)\s+(["']?)\.netrc\1(?:\s|$)/.test(command.text),
    );
    if (findsNetrc) {
      const readsResult = body.descendantsOfType("command").some((command) =>
        new RegExp(
          `^\\s*(?:cat|head|tail|less|more)\\s+(?:--\\s+)?["']?\\$(?:\\{)?${escapedVariable}\\}?["']?\\s*$`,
        ).test(command.text),
      );
      if (readsResult) {
        findings.push({
          ruleId: "chain.find-read-netrc",
          category: "credential_access",
          title: "Finds and reads netrc credential files",
          severity: "high",
          confidence: "high",
          message: "Finds .netrc files and reads each result inside the same loop.",
          evidence: evidence(node.text, maxEvidence),
          range: rangeOf(node),
          language: "bash",
        });
      }
    }

    const readCommand = substitution.descendantsOfType("command").find((command) =>
      /^\s*cat(?:\s|$)/.test(command.text),
    );
    const readPath = readCommand
      ? staticBashPathArgument(readCommand.text.replace(/^\s*cat\s+/, ""))
      : undefined;
    if (!readPath) return;

    const digCommand = body.descendantsOfType("command").find((command) =>
      new RegExp(
        `^\\s*dig(?:\\s+[^\\s;]+)*\\s+["']?\\$(?:\\{)?${escapedVariable}\\}?(?:\\.[A-Za-z0-9_-]+){2,}["']?\\s*$`,
      ).test(command.text),
    );
    if (!digCommand) return;

    const encoded = commands.find((candidate) => {
      if (
        candidate.range.startIndex >= node.startIndex
        || bashExecutionScopeId(candidate.node) !== bashExecutionScopeId(node)
        || node.startIndex - candidate.range.startIndex > 5_000
      ) return false;
      const match = candidate.text.match(
        /^\s*xxd\s+(?:-[A-Za-z0-9]+\s+)*(["']?)([^"'$\s;|&<>]+)\1\s*>\s*(["']?)([^"'$\s;|&<>]+)\3\s*$/,
      );
      return match?.[4] === readPath && match[2] !== match[4];
    });
    if (!encoded) return;

    addChainFinding(findings, encoded, {
      node: digCommand,
      text: digCommand.text,
      range: rangeOf(digCommand),
    }, {
      ruleId: "chain.dns-file-exfiltration",
      category: "data_exfiltration",
      title: "Encodes and exfiltrates file data through DNS",
      severity: "critical",
      confidence: "high",
      message: "A file is encoded, read into a loop variable, and embedded in DNS query names.",
      language: "bash",
    }, maxEvidence);
  });
  for (const download of commandVariants) {
    const outputPath = download.variants
      .map((variant) => bashStaticDownloadOutput(variant))
      .find((path) => path !== undefined);
    if (!outputPath || isAllowedDownload(download.statement.text, options)) continue;
    const later = commandVariants.filter((candidate) =>
      candidate.scopeId === download.scopeId
      && candidate.statement.range.startIndex > download.statement.range.startIndex
      && candidate.statement.range.startIndex - download.statement.range.startIndex <= 5_000,
    );
    const chmod = later.find((candidate) => candidate.variants.some((variant) =>
      /^\s*chmod\b(?=[^;\n]*(?:[ugoa]*\+x|[0-7]*[1357][0-7]{2})(?:\s|$))/i.test(variant)
      && bashCommandReferencesPath(variant, outputPath),
    ));
    const escapedOutput = outputPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const execute = chmod && later.find((candidate) =>
      candidate.statement.range.startIndex > chmod.statement.range.startIndex
      && candidate.variants.some((variant) =>
        (
          /^\s*(?:bash|sh)\s+/i.test(variant)
          || new RegExp(`^\\s*(?:\\./)?${escapedOutput}(?:\\s|$)`).test(variant)
        )
        && bashCommandReferencesPath(variant, outputPath),
      ),
    );
    if (!chmod || !execute) continue;
    addChainFinding(findings, download.statement, execute.statement, {
      ruleId: "chain.second-stage-downloaded-script",
      category: "second_stage_payload",
      title: "Runs a downloaded script as a second-stage payload",
      severity: "critical",
      confidence: "high",
      message: "The same static path is downloaded, made executable, and passed to a shell or invoked.",
      language: "bash",
    }, maxEvidence);
  }
  for (const download of commandVariants) {
    const archiveVariable = download.variants
      .map((variant) => bashArchiveOutputVariable(variant))
      .find((variable) => variable !== undefined);
    if (!archiveVariable || isAllowedDownload(download.statement.text, options)) continue;
    const escaped = archiveVariable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const later = commandVariants.filter((candidate) =>
      candidate.scopeId === download.scopeId
      && candidate.statement.range.startIndex > download.statement.range.startIndex
      && candidate.statement.range.startIndex - download.statement.range.startIndex <= 5_000,
    );
    const extract = later.find((candidate) => candidate.variants.some((variant) =>
      EXTRACT.test(variant)
      && new RegExp(`\\$(?:\\{)?${escaped}\\}?(?:\\.(?:zip|tar|tgz|gz|bz2|xz))?\\b`).test(variant),
    ));
    const chmod = later.find((candidate) => candidate.variants.some((variant) =>
      new RegExp(
        `^\\s*chmod\\s+(?:[ugo]*\\+x|[0-7]*[1357][0-7]{2})\\s+["']?\\$(?:\\{)?${escaped}\\}?["']?(?:\\s|$)`,
      ).test(variant),
    ));
    const execute = later.find((candidate) =>
      (!chmod || candidate.statement.range.startIndex > chmod.statement.range.startIndex)
      && candidate.variants.some((variant) => bashInvokesVariable(variant, archiveVariable)),
    );
    if (extract && chmod && execute) {
      addChainFinding(findings, download.statement, execute.statement, {
        ruleId: "chain.archive-output-execute",
        category: "download_execution",
        title: "Downloads and executes an archive payload",
        severity: "critical",
        confidence: "high",
        message: "An archive written to a variable-derived path is extracted, installed, made executable, and invoked.",
        language: "bash",
      }, maxEvidence);
    }
    if (extract && execute) {
      addChainFinding(findings, download.statement, execute.statement, {
        ruleId: "chain.second-stage-variable-archive",
        category: "second_stage_payload",
        title: "Extracts and runs a downloaded archive payload",
        severity: "critical",
        confidence: "high",
        message: "A downloaded archive is extracted and its variable-derived executable is invoked.",
        language: "bash",
      }, maxEvidence);
    }
    const dynamicSubcommand = execute?.variants
      .map((variant) => bashVariableSubcommand(variant, archiveVariable))
      .find((subcommand) => subcommand !== undefined);
    if (extract && chmod && execute && dynamicSubcommand) {
      addChainFinding(findings, download.statement, execute.statement, {
        ruleId: "chain.downloaded-interpreter",
        category: "interpreter_escape",
        title: "Invokes a downloaded language runtime",
        severity: "high",
        confidence: "high",
        message: `A downloaded executable is invoked with its ${dynamicSubcommand} subcommand.`,
        language: "bash",
      }, maxEvidence);
      addChainFinding(findings, download.statement, execute.statement, {
        ruleId: "chain.downloaded-dynamic-code",
        category: "dynamic_execution",
        title: "Executes code through a downloaded runtime",
        severity: "high",
        confidence: "high",
        message: `A downloaded executable dynamically evaluates code with its ${dynamicSubcommand} subcommand.`,
        language: "bash",
      }, maxEvidence);
    }
  }
  for (const download of commandVariants) {
    let targetVariable: string | undefined;
    for (const variant of download.variants) {
      const match = variant.match(
        /^\s*([A-Za-z_]\w*)\s+\S+\s+["']?\$(?:\{)?([A-Za-z_]\w*)\}?["']?(?:\s|$)/,
      );
      if (match && functionSummaries.downloaders.has(match[1]!)) {
        targetVariable = match[2];
        break;
      }
    }
    if (!targetVariable) continue;
    const later = commandVariants.filter((candidate) =>
      candidate.scopeId === download.scopeId
      && candidate.statement.range.startIndex > download.statement.range.startIndex
      && candidate.statement.range.startIndex - download.statement.range.startIndex <= 5_000,
    );
    const variable = targetVariable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const chmod = later.find((candidate) => candidate.variants.some((variant) =>
      new RegExp(
        `^\\s*chmod\\s+(?:[ugo]*\\+x|[0-7]*[1357][0-7]{2})\\s+["']?\\$(?:\\{)?${variable}\\}?["']?(?:\\s|$)`,
      ).test(variant),
    ));
    const execute = later.find((candidate) => candidate.variants.some((variant) =>
      new RegExp(`^\\s*["']?\\$(?:\\{)?${variable}\\}?["']?(?:\\s|$)`).test(variant),
    ));
    if (chmod && execute) {
      addChainFinding(findings, download.statement, execute.statement, {
        ruleId: "chain.wrapper-download-execute",
        category: "download_execution",
        title: "Downloads and executes a wrapped binary",
        severity: "critical",
        confidence: "high",
        message: "A download wrapper writes a path that is made executable and invoked in the same function.",
        language: "bash",
      }, maxEvidence);
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
