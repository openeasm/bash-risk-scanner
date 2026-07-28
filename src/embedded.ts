import type Parser from "tree-sitter";
import type { SourceRange } from "./types.js";

type SyntaxNode = Parser.SyntaxNode;

export interface EmbeddedPayload {
  language: "python" | "javascript";
  interpreter: "python" | "node";
  kind: "argument" | "heredoc" | "pipeline";
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
      ["expansion", "command_substitution", "process_substitution"].includes(child.type),
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

export function extractEmbeddedPayloads(root: SyntaxNode): EmbeddedPayload[] {
  const payloads: EmbeddedPayload[] = [];
  const visit = (node: SyntaxNode): void => {
    if (node.type === "command") {
      const name = commandName(node) ?? "";
      const isPython = /^(?:python|python\d+(?:\.\d+)?)$/.test(name);
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
  return payloads;
}
