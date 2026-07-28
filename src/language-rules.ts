import type { Confidence, RiskCategory, Severity } from "./types.js";

export interface LanguageRule {
  id: string;
  category: RiskCategory;
  title: string;
  severity: Severity;
  confidence: Confidence;
  message: string;
  nodeTypes: string[];
  pattern: RegExp;
}

type RuleData = Omit<LanguageRule, "nodeTypes">;

const call = (data: RuleData): LanguageRule => ({
  ...data,
  nodeTypes: ["call"],
});

const jsCall = (data: RuleData): LanguageRule => ({
  ...data,
  nodeTypes: ["call_expression", "new_expression"],
});

export const PYTHON_RULES: LanguageRule[] = [
  call({ id: "python.download-execute", category: "download_execution", title: "Downloads and executes Python code", severity: "critical", confidence: "high", message: "Remote response content is passed to a code or process execution sink.", pattern: /(?:exec|eval|os\.system|subprocess\.\w+)\s*\([^)]*(?:requests\.(?:get|post)|urllib\.request\.urlopen)/s }),
  call({ id: "python.dynamic-code", category: "dynamic_execution", title: "Executes dynamic Python or shell code", severity: "high", confidence: "high", message: "Uses a dynamic code or shell execution API.", pattern: /^(?:eval|exec|compile|os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_call|check_output)|asyncio\.create_subprocess_(?:shell|exec))\s*\(/s }),
  call({ id: "python.persistence", category: "persistence", title: "Modifies startup or scheduled execution", severity: "high", confidence: "medium", message: "Writes or installs a common persistence mechanism.", pattern: /(?:open|Path|write_text|write_bytes|shutil\.copy\w*)[\s\S]*(?:crontab|\/etc\/cron|systemd|LaunchAgents?|LaunchDaemons?|\.bashrc|\.profile|\.zshrc)/i }),
  call({ id: "python.credential-access", category: "credential_access", title: "Accesses credentials or secrets", severity: "high", confidence: "high", message: "Reads a common credential location, keychain, browser data, or environment secrets.", pattern: /(?:open|Path|read_text|read_bytes|os\.getenv|keyring\.\w+)[\s\S]*(?:\.ssh|\.aws[\/\\]credentials|\.config[\/\\]gcloud|Keychains?|Login Data|Cookies|TOKEN|SECRET|PASSWORD|KEY)/i }),
  call({ id: "python.environment-access", category: "credential_access", title: "Enumerates process environment", severity: "medium", confidence: "medium", message: "Accesses environment variables which may contain credentials.", pattern: /^(?:dict\s*\(\s*os\.environ|os\.environ\.(?:items|copy|keys|values))\s*\(/s }),
  call({ id: "python.system-modification", category: "system_modification", title: "Modifies sensitive system configuration", severity: "critical", confidence: "high", message: "Writes sensitive system, network, firewall, proxy, certificate, systemd, or udev configuration.", pattern: /(?:open|Path|write_text|write_bytes|shutil\.(?:copy|move))[\s\S]*(?:\/etc\/|\/usr\/lib\/(?:systemd|udev)\/|sudoers|resolv\.conf|iptables|nftables|certificates?|proxy)/i }),
  call({ id: "python.privilege", category: "privilege_escalation", title: "Changes privileges or privileged attributes", severity: "critical", confidence: "high", message: "Changes identity, file mode, ownership, or capabilities.", pattern: /^(?:os\.(?:setuid|seteuid|setgid|setegid)\s*\(\s*0|os\.(?:chmod|chown)\s*\([^)]*(?:0o[2467][0-7]{3}|[2467][0-7]{3})|subprocess\.\w+\s*\([^)]*(?:setcap|sudo|chmod\s+[ug+]*s))/s }),
  call({ id: "python.defense-evasion", category: "defense_evasion", title: "Impairs logging or security controls", severity: "critical", confidence: "medium", message: "Deletes logs or stops security/audit processes.", pattern: /(?:os\.(?:remove|unlink|kill)|Path\.unlink|shutil\.rmtree|subprocess\.\w+)\s*\([^)]*(?:\/var\/log|audit|history|defender|falcon|sentinel|edr|antivirus)/is }),
  call({ id: "python.network", category: "network_egress", title: "Creates an outbound network connection", severity: "medium", confidence: "medium", message: "Uses an HTTP, URL, socket, SSH, telnet, or FTP client.", pattern: /^(?:requests\.(?:Session\.)?(?:get|post|put|patch|delete|head|options|request)|aiohttp\.ClientSession\.(?:get|post|put|patch|delete|head|options|request|ws_connect)|httpx\.(?:(?:Async)?Client\.)?(?:get|post|put|patch|delete|head|options|request|stream)|urllib\.request\.(?:urlopen|urlretrieve)|socket\.(?:socket|create_connection)|paramiko\.\w+|telnetlib3\.open_connection|ftplib\.\w+)\s*\(/s }),
  call({ id: "python.exfiltration", category: "data_exfiltration", title: "Uploads or transmits data", severity: "high", confidence: "medium", message: "Uses an upload, POST, object-storage, socket send, or remote writer operation.", pattern: /^(?:requests\.(?:Session\.)?(?:post|put|patch)|httpx\.(?:(?:Async)?Client\.)?(?:post|put|patch)|boto3\.\w+|[\w.]+\.(?:upload_file|put_object|send|sendall)|(?:writer|stream_writer|remote_writer)\.write)\s*\(/s }),
  call({ id: "python.destructive", category: "destructive_behavior", title: "Deletes data or writes a disk device", severity: "critical", confidence: "medium", message: "Performs recursive deletion, bulk removal, or direct disk writes.", pattern: /^(?:shutil\.rmtree|os\.(?:remove|unlink|removedirs)|Path\.unlink)\s*\(|(?:open|os\.open)\s*\(\s*["']\/dev\//s }),
  call({ id: "python.interpreter-escape", category: "interpreter_escape", title: "Launches another interpreter", severity: "high", confidence: "medium", message: "Transfers execution to a shell or another general-purpose interpreter.", pattern: /^(?:(?:os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_call|check_output))\s*\([^)]*(?:bash|sh|python|perl|ruby|node|php|osascript|powershell|pwsh)|asyncio\.create_subprocess_shell\s*\()/is }),
  call({ id: "python.second-stage", category: "second_stage_payload", title: "Retrieves or unpacks a second-stage payload", severity: "high", confidence: "medium", message: "Downloads or extracts an archive that may contain another payload.", pattern: /^(?:(?:urllib\.request\.urlretrieve|requests\.get)\s*\([^)]*\.(?:zip|tar|tgz|gz|xz)\b|(?:shutil\.unpack_archive|tarfile\.open|zipfile\.ZipFile)\s*\()/is }),
];

export const JAVASCRIPT_RULES: LanguageRule[] = [
  jsCall({ id: "javascript.download-execute", category: "download_execution", title: "Downloads and executes JavaScript or shell code", severity: "critical", confidence: "high", message: "Remote content is passed to a code or process execution sink.", pattern: /(?:eval|Function|child_process\.\w+|exec|spawn)\s*\([^)]*(?:fetch|https?\.get|axios\.)/s }),
  jsCall({ id: "javascript.dynamic-code", category: "dynamic_execution", title: "Executes dynamic JavaScript or shell code", severity: "high", confidence: "high", message: "Uses dynamic code evaluation, VM, or process execution.", pattern: /(?:^|\.)(?:eval|Function|runIn\w+|compileFunction|exec|execSync|spawn|spawnSync)\s*\(/s }),
  jsCall({ id: "javascript.persistence", category: "persistence", title: "Modifies startup or scheduled execution", severity: "high", confidence: "medium", message: "Writes a common startup, scheduled task, or service location.", pattern: /(?:writeFileSync?|appendFileSync?|copyFileSync?|renameSync?)\s*\([^)]*(?:crontab|\/etc\/cron|systemd|LaunchAgents?|LaunchDaemons?|\.bashrc|\.profile|\.zshrc)/is }),
  jsCall({ id: "javascript.credential-access", category: "credential_access", title: "Accesses credentials or secrets", severity: "high", confidence: "high", message: "Reads a credential location, browser store, keychain, or secret.", pattern: /(?:readFileSync?|readdirSync?|statSync?|accessSync?)\s*\([^)]*(?:\.ssh|\.aws[\/\\]credentials|\.config[\/\\]gcloud|Keychains?|Login Data|Cookies|TOKEN|SECRET|PASSWORD|KEY)/is }),
  jsCall({ id: "javascript.environment-access", category: "credential_access", title: "Enumerates process environment", severity: "medium", confidence: "medium", message: "Enumerates environment variables which may contain credentials.", pattern: /^(?:Object\.(?:keys|values|entries)|JSON\.stringify)\s*\(\s*process\.env/s }),
  jsCall({ id: "javascript.system-modification", category: "system_modification", title: "Modifies sensitive system configuration", severity: "critical", confidence: "high", message: "Writes sensitive system, network, firewall, proxy, or certificate configuration.", pattern: /(?:writeFileSync?|appendFileSync?|copyFileSync?|renameSync?)\s*\([^)]*(?:\/etc\/|sudoers|resolv\.conf|iptables|nftables|certificates?|proxy)/is }),
  jsCall({ id: "javascript.privilege", category: "privilege_escalation", title: "Changes privileges or privileged attributes", severity: "critical", confidence: "high", message: "Changes process identity, ownership, file mode, or capabilities.", pattern: /(?:(?:^|\.)set(?:uid|gid)\s*\(\s*0|(?:^|\.)(?:chmod|chmodSync|chown|chownSync|exec|execSync)\s*\([^)]*(?:0o[2467][0-7]{3}|setcap|sudo|chmod\s+(?:[2467][0-7]{3}|[ug+]*s)))/s }),
  jsCall({ id: "javascript.defense-evasion", category: "defense_evasion", title: "Impairs logging or security controls", severity: "critical", confidence: "medium", message: "Deletes logs or stops security/audit processes.", pattern: /(?:rmSync?|unlinkSync?|rmdirSync?|kill|child_process\.\w+|execSync?)\s*\([^)]*(?:\/var\/log|audit|history|defender|falcon|sentinel|edr|antivirus)/is }),
  jsCall({ id: "javascript.network", category: "network_egress", title: "Creates an outbound network connection", severity: "medium", confidence: "medium", message: "Uses HTTP, fetch, socket, SSH, DNS, or FTP networking.", pattern: /^(?:fetch|npm-registry-fetch|undici\.(?:fetch|request|stream|pipeline|connect)|axios\.\w+|https?\.(?:get|request)|net\.(?:connect|createConnection)|tls\.connect|dns\.\w+|got\.stream|[\w.]+\.(?:connect))\s*\(/s }),
  jsCall({ id: "javascript.exfiltration", category: "data_exfiltration", title: "Uploads or transmits data", severity: "high", confidence: "medium", message: "Uses an upload, POST/PUT, object-storage, or socket write operation.", pattern: /^(?:(?:axios\.(?:post|put|patch)|[\w.]+\.(?:send|write|upload|putObject|sendCommand))\s*\(|fetch\s*\([^)]*(?:method\s*:\s*["'](?:POST|PUT|PATCH)|body\s*:))/is }),
  jsCall({ id: "javascript.destructive", category: "destructive_behavior", title: "Deletes data or writes a disk device", severity: "critical", confidence: "medium", message: "Performs recursive deletion, file removal, or direct disk writes.", pattern: /(?:^|\.)(?:rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync)\s*\(|(?:^|\.)(?:writeFile|writeFileSync|open|openSync)\s*\(\s*["']\/dev\//s }),
  jsCall({ id: "javascript.interpreter-escape", category: "interpreter_escape", title: "Launches another interpreter", severity: "high", confidence: "medium", message: "Transfers execution to a shell or another general-purpose interpreter.", pattern: /(?:^|\.)(?:exec|execSync|spawn|spawnSync)\s*\([^)]*(?:bash|sh|python|perl|ruby|node|php|osascript|powershell|pwsh)/is }),
  jsCall({ id: "javascript.second-stage", category: "second_stage_payload", title: "Retrieves or unpacks a second-stage payload", severity: "high", confidence: "medium", message: "Downloads or extracts an archive that may contain another payload.", pattern: /^(?:(?:fetch|https?\.get|axios\.get)\s*\([^)]*\.(?:zip|tar|tgz|gz|xz)\b|(?:extract|unzip|tar\.\w+|unpack-stream\.remote)\s*\()/is }),
];
