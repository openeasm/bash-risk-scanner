import type { Confidence, RiskCategory, Severity } from "./types.js";

export interface Rule {
  id: string;
  category: RiskCategory;
  title: string;
  severity: Severity;
  confidence: Confidence;
  message: string;
  pattern: RegExp;
}

const cmd = String.raw`^\s*`;
const arg = String.raw`(?:\s|$)`;

export const COMMAND_RULES: Rule[] = [
  {
    id: "dynamic.eval",
    category: "dynamic_execution",
    title: "Dynamic shell evaluation",
    severity: "high",
    confidence: "high",
    message: "Executes text as shell code, which can hide the actual behavior.",
    pattern: new RegExp(`${cmd}(?:eval|(?:ba)?sh\\s+-c)${arg}`, "i"),
  },
  {
    id: "dynamic.process-substitution-source",
    category: "dynamic_execution",
    title: "Sources process substitution",
    severity: "high",
    confidence: "high",
    message: "Sources dynamically generated content as shell code.",
    pattern: /^\s*(?:source|\.)\s+<\s*\(/i,
  },
  {
    id: "persistence.scheduler",
    category: "persistence",
    title: "Modifies a scheduled or startup task",
    severity: "high",
    confidence: "high",
    message: "May establish execution that survives the current session.",
    pattern: /^\s*(?:crontab|systemctl\s+(?:enable|daemon-reload)|launchctl\s+(?:load|bootstrap)|schtasks)\b|(?:>>?|tee|install|cp|mv)[^;\n]*\/(?:etc\/cron|Library\/LaunchAgents|Library\/LaunchDaemons)\b/i,
  },
  {
    id: "persistence.shell-rc",
    category: "persistence",
    title: "Writes a shell startup file",
    severity: "high",
    confidence: "medium",
    message: "Changes a shell startup file and may establish persistence.",
    pattern: /(?:>>?|tee(?:\s+-a)?)\s*(?:["']?\$HOME\/|~\/)?\.(?:bashrc|bash_profile|profile|zshrc|zprofile)\b/i,
  },
  {
    id: "credential.sensitive-path",
    category: "credential_access",
    title: "Accesses credential storage",
    severity: "high",
    confidence: "high",
    message: "Reads or enumerates a location commonly containing credentials.",
    pattern: /^\s*(?:cat|head|tail|less|more|cp|tar|zip|find|ls|grep)\b[^;\n]*(?:\/?\.ssh\b|\/?\.aws\/credentials\b|\/?\.config\/gcloud\b|\/Library\/Keychains\b|Login Data\b|Cookies\b|keychain)/i,
  },
  {
    id: "credential.environment",
    category: "credential_access",
    title: "Enumerates environment variables",
    severity: "medium",
    confidence: "medium",
    message: "Environment variables can contain tokens and credentials.",
    pattern: /^(?:\s*(?:env|printenv)(?:\s|$)|\s*set\s*$)/i,
  },
  {
    id: "system.sensitive-config",
    category: "system_modification",
    title: "Modifies sensitive system configuration",
    severity: "critical",
    confidence: "high",
    message: "Writes sensitive OS, network, proxy, firewall, or trust configuration.",
    pattern: /(?:>>?|tee|sed\s+-i|install|cp|mv)[^;\n]*(?:\/etc\/(?:sudoers|hosts|resolv\.conf|ssh|pam\.d)|\/etc\/|iptables|nftables|firewall|proxy|certificates?)/i,
  },
  {
    id: "privilege.sudo",
    category: "privilege_escalation",
    title: "Runs with elevated privileges",
    severity: "high",
    confidence: "high",
    message: "Invokes a command through sudo or su.",
    pattern: new RegExp(`${cmd}(?:sudo|su)(?:\\s|$)`, "i"),
  },
  {
    id: "privilege.suid-capability",
    category: "privilege_escalation",
    title: "Changes privileged executable attributes",
    severity: "critical",
    confidence: "high",
    message: "Sets SUID/SGID or Linux capabilities.",
    pattern: /^\s*(?:chmod\s+(?:[ug+]*s|[2467][0-7]{3})|setcap\s+)/i,
  },
  {
    id: "defense.logs",
    category: "defense_evasion",
    title: "Deletes or truncates logs",
    severity: "critical",
    confidence: "high",
    message: "Attempts to remove evidence from system or shell logs.",
    pattern: /^\s*(?:(?:rm|shred|truncate)\b[^;\n]*(?:\/var\/log\b|\.bash_history\b|\.zsh_history\b|audit\.log\b)|history\s+-c\b)/i,
  },
  {
    id: "defense.security-control",
    category: "defense_evasion",
    title: "Disables a security control",
    severity: "critical",
    confidence: "medium",
    message: "Stops, kills, or changes security monitoring/auditing.",
    pattern: /^\s*(?:systemctl\s+(?:stop|disable)|pkill|killall|service\s+\S+\s+stop|auditctl\s+-e\s+0)\b[^;\n]*(?:audit|edr|defender|falcon|sentinel|security|antivirus)?/i,
  },
  {
    id: "network.tool",
    category: "network_egress",
    title: "Uses an outbound network tool",
    severity: "medium",
    confidence: "medium",
    message: "Creates an outbound network connection.",
    pattern: new RegExp(`${cmd}(?:nc|ncat|netcat|socat|ssh|scp|sftp|curl|wget|dig|nslookup)${arg}`, "i"),
  },
  {
    id: "exfil.upload",
    category: "data_exfiltration",
    title: "Uploads local data",
    severity: "high",
    confidence: "medium",
    message: "Uses an upload or POST option that may transmit local data.",
    pattern: /^\s*(?:curl\b[^;\n]*(?:(?:^|\s)(?:-F|-T)(?:\s|$)|--(?:form|upload-file)(?:=|\s)|--data(?:-binary)?\s+@|-X\s*POST\b)|aws\s+s3\s+cp\b|gsutil\s+cp\b|rclone\s+(?:copy|sync)\b|scp\s+)/,
  },
  {
    id: "exfil.reverse-shell",
    category: "data_exfiltration",
    title: "Possible reverse shell",
    severity: "critical",
    confidence: "high",
    message: "Connects a shell or file descriptor to a remote endpoint.",
    pattern: /\/dev\/tcp\/|^\s*(?:(?:nc|ncat|socat)\b[^;\n]*(?:-e\s*(?:\/bin\/)?(?:ba)?sh|EXEC:(?:ba)?sh)|(?:ba)?sh\s+-i\s+.*(?:>&|0<&))/i,
  },
  {
    id: "destructive.rm-root",
    category: "destructive_behavior",
    title: "Recursive forced deletion",
    severity: "critical",
    confidence: "high",
    message: "Recursively and forcibly deletes a broad or sensitive path.",
    pattern: /^\s*rm\s+(?=[^;\n]*-[A-Za-z]*r)(?=[^;\n]*-[A-Za-z]*f)[^;\n]*(?:\/(?:\s|$)|\/\*|\$HOME|~|\/etc|\/var|\/usr)/i,
  },
  {
    id: "destructive.disk-write",
    category: "destructive_behavior",
    title: "Writes directly to a disk device",
    severity: "critical",
    confidence: "high",
    message: "Direct disk writes can destroy data or filesystems.",
    pattern: /^\s*(?:dd\b[^;\n]*\bof=\/dev\/|mkfs(?:\.\w+)?\s+\/dev\/|shred\b[^;\n]*\/dev\/)/i,
  },
  {
    id: "destructive.bulk-encryption",
    category: "destructive_behavior",
    title: "Possible bulk file encryption",
    severity: "critical",
    confidence: "medium",
    message: "Combines file enumeration with encryption tooling.",
    pattern: /^\s*find\b[^;\n]*(?:-exec|xargs)[^;\n]*(?:openssl\s+enc|gpg\s+(?:-c|--symmetric)|age\s+-r)/i,
  },
  {
    id: "escape.interpreter",
    category: "interpreter_escape",
    title: "Invokes another interpreter",
    severity: "medium",
    confidence: "medium",
    message: "Transfers execution to another general-purpose interpreter.",
    pattern: new RegExp(`${cmd}(?:python\\d*|perl|ruby|node|php|osascript|powershell|pwsh)(?:\\s|$)`, "i"),
  },
];

export const DOWNLOAD = /\b(?:curl|wget|fetch|aria2c)\b/i;
export const EXECUTE = /(?:^|[\s;|&()])(?:bash|sh|source|\.)(?:\s|$)|\bchmod\s+\+x\b|\bexec\b/i;
export const ARCHIVE_DOWNLOAD = /\b(?:curl|wget|fetch|aria2c)\b[^;\n]*(?:\.tar(?:\.\w+)?|\.tgz|\.zip|\.gz|\.bz2|\.xz)\b/i;
export const EXTRACT = /\b(?:tar|unzip|gunzip|7z)\b/i;
export const INSTALL_OR_BINARY = /\b(?:\.\/)?(?:install(?:\.sh)?|setup(?:\.sh)?|run(?:\.sh)?)\b|\bchmod\s+\+x\b/i;
export const FILE_READ = /\b(?:cat|head|tail|sed|awk|grep|tar|zip|find)\b/i;
export const UPLOAD = /\b(?:curl\b[^;\n]*(?:(?:^|\s)(?:-F|-T)(?=\s|$)|--(?:form|upload-file)(?:=|\s)|--data(?:-binary)?\s+@)|scp\b|sftp\b|aws\s+s3\s+cp\b|gsutil\s+cp\b|rclone\s+(?:copy|sync)\b)/;
