import type Parser from "tree-sitter";
import type { SourceRange } from "./types.js";

type SyntaxNode = Parser.SyntaxNode;

export interface EmbeddedPayload {
  language: "python" | "javascript";
  interpreter: "python" | "node";
  kind: "argument" | "heredoc" | "pipeline" | "generated-file" | "compiled-file";
  source: string;
  range: SourceRange;
}

function rangeOf(node: SyntaxNode): SourceRange {
  return {
    start: { row: node.startPosition.row + 1, column: node.startPosition.column + 1 },
    end: { row: node.endPosition.row + 1, column: node.endPosition.column + 1 },
    startIndex: node.startIndex,
    endIndex: node.endIndex,
  };
}

function staticShellValue(node: SyntaxNode): string | undefined {
  if (node.type === "raw_string") return node.text.slice(1, -1);
  if (node.type === "string") {
    if (node.namedChildren.some((child) =>
      [
        "expansion",
        "simple_expansion",
        "command_substitution",
        "process_substitution",
      ].includes(child.type),
    )) return undefined;
    // Bash only treats these characters specially after a backslash in a
    // double-quoted string. Preserve other backslashes for the embedded parser.
    return node.text.slice(1, -1).replace(/\\([$`"\\\n])/g, "$1");
  }
  if (node.type === "word" && node.namedChildren.length === 0) return node.text;
  return undefined;
}

function commandName(node: SyntaxNode): string | undefined {
  return node.childForFieldName("name")?.text;
}

function commandArguments(node: SyntaxNode): SyntaxNode[] {
  return node.namedChildren.filter((child) => child.type !== "command_name");
}

function findHeredoc(command: SyntaxNode): SyntaxNode | undefined {
  const redirected = command.parent?.type === "redirected_statement" ? command.parent : undefined;
  if (!redirected) return undefined;
  const stack = [...redirected.namedChildren];
  while (stack.length) {
    const node = stack.shift()!;
    if (node.type === "heredoc_body") return node;
    stack.push(...node.namedChildren);
  }
  return undefined;
}

function pipelineInput(command: SyntaxNode): { source: string; range: SourceRange } | undefined {
  const pipeline = command.parent?.type === "pipeline" ? command.parent : undefined;
  if (!pipeline) return undefined;
  const commands = pipeline.namedChildren.filter((child) => child.type === "command");
  const index = commands.findIndex((item) => item.id === command.id);
  if (index <= 0) return undefined;
  const producer = commands[index - 1]!;
  if (!["echo", "printf"].includes(commandName(producer) ?? "")) return undefined;
  const values = commandArguments(producer).map(staticShellValue);
  if (values.some((value) => value === undefined)) return undefined;
  const args = values as string[];
  const source = commandName(producer) === "printf" && /^%[bs]$/.test(args[0] ?? "")
    ? args.slice(1).join("")
    : args.join(" ");
  return source ? { source, range: rangeOf(producer) } : undefined;
}

function bashScopeId(node: SyntaxNode): number {
  for (let current = node.parent; current; current = current.parent) {
    if (current.type === "function_definition") return current.id;
  }
  return node.tree.rootNode.id;
}

function combinedRange(first: SourceRange, last: SourceRange): SourceRange {
  return {
    start: first.start,
    end: last.end,
    startIndex: first.startIndex,
    endIndex: last.endIndex,
  };
}

function staticRedirectOutput(command: SyntaxNode): string | undefined {
  const name = commandName(command);
  const values = commandArguments(command).map(staticShellValue);
  if (values.some((value) => value === undefined)) return undefined;
  const args = values as string[];
  if (name === "echo") {
    const noNewline = args[0] === "-n";
    const content = args.slice(noNewline ? 1 : 0).join(" ");
    return `${content}${noNewline ? "" : "\n"}`;
  }
  if (name !== "printf") return undefined;
  const format = args[0];
  if (!format || /%(?!s)/.test(format)) return undefined;
  const replacements = args.slice(1);
  let replacementIndex = 0;
  const content = format.replace(/%s/g, () => replacements[replacementIndex++] ?? "");
  if (replacementIndex !== replacements.length) return undefined;
  return content.replace(/\\n/g, "\n").replace(/\\t/g, "\t");
}

function extractGeneratedPythonPayloads(
  root: SyntaxNode,
  trustedPythonVariables: ReadonlySet<string>,
  staticPythonCompilation?: (source: string) => {
    input: string;
    output: string;
  } | undefined,
): EmbeddedPayload[] {
  interface GeneratedFile {
    source?: string;
    range?: SourceRange;
    lastWriteEndIndex: number;
  }
  const files = new Map<string, GeneratedFile>();
  const compiledFiles = new Map<string, GeneratedFile>();
  const payloads: EmbeddedPayload[] = [];
  const commands = root.descendantsOfType("command")
    .sort((left, right) => left.startIndex - right.startIndex);

  for (const command of commands) {
    const scopeId = bashScopeId(command);
    const redirected = command.parent?.type === "redirected_statement"
      ? command.parent
      : undefined;
    const redirect = redirected?.namedChildren.find((child) => child.type === "file_redirect");
    if (redirect) {
      const destinationNode = redirect.childForFieldName("destination");
      const destination = destinationNode ? staticShellValue(destinationNode) : undefined;
      if (destination?.endsWith(".pyc")) {
        compiledFiles.delete(`${scopeId}:${destination}`);
        continue;
      }
      if (!destination?.endsWith(".py")) continue;
      const key = `${scopeId}:${destination}`;
      const previous = files.get(key);
      const append = /^\s*>>/.test(redirect.text);
      const output = staticRedirectOutput(command);
      if (!output || (append && previous?.source === undefined)) {
        files.set(key, { source: undefined, range: undefined, lastWriteEndIndex: redirect.endIndex });
        continue;
      }
      const statementRange = rangeOf(redirected!);
      files.set(key, {
        source: append ? `${previous!.source}${output}` : output,
        range: append && previous?.range
          ? combinedRange(previous.range, statementRange)
          : statementRange,
        lastWriteEndIndex: redirect.endIndex,
      });
      continue;
    }

    const variableName = command.childForFieldName("name")
      ?.descendantsOfType("variable_name")[0]?.text;
    if (!variableName || !trustedPythonVariables.has(variableName)) continue;
    const args = commandArguments(command);
    if (args[0]?.text === "-c" && args[1] && staticPythonCompilation) {
      const source = staticShellValue(args[1]);
      const compilation = source ? staticPythonCompilation(source) : undefined;
      if (!compilation || !compilation.output.endsWith(".pyc")) continue;
      const generated = files.get(`${scopeId}:${compilation.input}`);
      if (
        !generated?.source
        || !generated.range
        || generated.lastWriteEndIndex >= command.startIndex
      ) continue;
      compiledFiles.set(`${scopeId}:${compilation.output}`, {
        source: generated.source,
        range: combinedRange(generated.range, rangeOf(command)),
        lastWriteEndIndex: command.endIndex,
      });
      continue;
    }
    const script = args[0] ? staticShellValue(args[0]) : undefined;
    if (!script || (!script.endsWith(".py") && !script.endsWith(".pyc"))) continue;
    const compiled = script.endsWith(".pyc");
    const generated = compiled
      ? compiledFiles.get(`${scopeId}:${script}`)
      : files.get(`${scopeId}:${script}`);
    if (
      !generated?.source
      || !generated.range
      || generated.lastWriteEndIndex >= command.startIndex
    ) continue;
    payloads.push({
      language: "python",
      interpreter: "python",
      kind: compiled ? "compiled-file" : "generated-file",
      source: generated.source,
      range: combinedRange(generated.range, rangeOf(command)),
    });
  }
  return payloads;
}

export function extractEmbeddedPayloads(
  root: SyntaxNode,
  options: {
    trustedPythonVariables?: ReadonlySet<string>;
    staticPythonCompilation?: (source: string) => {
      input: string;
      output: string;
    } | undefined;
  } = {},
): EmbeddedPayload[] {
  const payloads: EmbeddedPayload[] = [];
  const visit = (node: SyntaxNode): void => {
    if (node.type === "command") {
      const name = commandName(node) ?? "";
      const variableName = node.childForFieldName("name")
        ?.descendantsOfType("variable_name")[0]?.text;
      const isPython = /^(?:python|python\d+(?:\.\d+)?)$/.test(name)
        || (
          variableName !== undefined
          && options.trustedPythonVariables?.has(variableName) === true
        );
      const isNode = /^(?:node|nodejs)$/.test(name);
      if (isPython || isNode) {
        const interpreter = isPython ? "python" : "node";
        const language = isPython ? "python" : "javascript";
        const args = commandArguments(node);
        const flagIndex = args.findIndex((arg) =>
          isPython ? arg.text === "-c" : ["-e", "--eval"].includes(arg.text),
        );
        if (flagIndex >= 0 && args[flagIndex + 1]) {
          const codeNode = args[flagIndex + 1]!;
          const source = staticShellValue(codeNode);
          if (source !== undefined) {
            payloads.push({ language, interpreter, kind: "argument", source, range: rangeOf(codeNode) });
          }
        } else {
          const heredoc = findHeredoc(node);
          if (heredoc) {
            payloads.push({
              language,
              interpreter,
              kind: "heredoc",
              source: heredoc.text,
              range: rangeOf(heredoc),
            });
          } else {
            const piped = pipelineInput(node);
            if (piped) payloads.push({ language, interpreter, kind: "pipeline", ...piped });
          }
        }
      }
    }
    for (const child of node.namedChildren) visit(child);
  };
  visit(root);
  if (options.trustedPythonVariables) {
    payloads.push(...extractGeneratedPythonPayloads(
      root,
      options.trustedPythonVariables,
      options.staticPythonCompilation,
    ));
  }
  return payloads;
}
