#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { stdin as input } from "node:process";
import { scan } from "./scanner.js";
import type { SupportedLanguage } from "./types.js";

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of input) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const compact = args.includes("--compact");
  const languageArg = args.find((arg) => arg.startsWith("--language="));
  const language = languageArg?.slice("--language=".length) as SupportedLanguage | undefined;
  const supported = ["bash", "python", "javascript", "node"];
  if (language && !supported.includes(language)) {
    throw new Error(`Unsupported language "${language}". Use: ${supported.join(", ")}`);
  }
  const paths = args.filter((arg) => !arg.startsWith("-"));

  if (args.includes("--help")) {
    console.log("Usage: bash-risk-scan [--compact] [--language=bash|python|javascript|node] [file ...]\nReads stdin when no file is supplied.");
    return;
  }

  const inputs = paths.length
    ? await Promise.all(paths.map(async (path) => ({ path, source: await readFile(path, "utf8") })))
    : [{ path: "<stdin>", source: await readStdin() }];

  const output = inputs.map(({ path, source }) => ({ path, ...scan(source, { language }) }));
  console.log(JSON.stringify(paths.length === 1 ? output[0] : output, null, compact ? 0 : 2));
  if (output.some((item) => item.findings.some((finding) => finding.severity === "critical"))) {
    process.exitCode = 2;
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
