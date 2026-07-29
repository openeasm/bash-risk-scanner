#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { stdin as input } from "node:process";
import { scan } from "./scanner.js";
import type { PolicyLocale, PolicyProfile, SupportedLanguage } from "./types.js";

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
  const policyLocaleArg = args.find((arg) => arg.startsWith("--policy-locale="));
  const policyLocale =
    policyLocaleArg?.slice("--policy-locale=".length) as PolicyLocale | undefined;
  const policyProfileArg = args.find((arg) => arg.startsWith("--policy-profile="));
  const policyProfile =
    policyProfileArg?.slice("--policy-profile=".length) as PolicyProfile | undefined;
  const supported = ["bash", "python", "javascript", "node"];
  if (language && !supported.includes(language)) {
    throw new Error(`Unsupported language "${language}". Use: ${supported.join(", ")}`);
  }
  if (policyLocale && !["zh-CN", "en"].includes(policyLocale)) {
    throw new Error(`Unsupported policy locale "${policyLocale}". Use: zh-CN, en`);
  }
  if (policyProfile && !["ai-agent", "audit"].includes(policyProfile)) {
    throw new Error(`Unsupported policy profile "${policyProfile}". Use: ai-agent, audit`);
  }
  const paths = args.filter((arg) => !arg.startsWith("-"));

  if (args.includes("--help")) {
    console.log("Usage: agent-tool-scan [--compact] [--language=bash|python|javascript|node] [--policy-locale=zh-CN|en] [--policy-profile=ai-agent|audit] [file ...]\nReads stdin when no file is supplied.");
    return;
  }

  const inputs = paths.length
    ? await Promise.all(paths.map(async (path) => ({ path, source: await readFile(path, "utf8") })))
    : [{ path: "<stdin>", source: await readStdin() }];

  const output = inputs.map(({ path, source }) => ({
    path,
    ...scan(source, {
      language,
      policy: {
        locale: policyLocale,
        profile: policyProfile,
      },
    }),
  }));
  console.log(JSON.stringify(paths.length === 1 ? output[0] : output, null, compact ? 0 : 2));
  if (output.some((item) => item.decision.action === "block")) {
    process.exitCode = 2;
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
