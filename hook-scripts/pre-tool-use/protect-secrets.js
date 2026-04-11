#!/usr/bin/env node
/**
 * Protect Secrets - PreToolUse Hook for Read|Edit|Write|Bash
 * Prevents reading, modifying, or exfiltrating sensitive files.
 * Logs to: ~/.claude/hooks-logs/
 *
 * SAFETY_LEVEL: 'critical' | 'high' | 'strict'
 *   critical - SSH keys, AWS creds, .env files only
 *   high     - + secrets files, env dumps, exfiltration attempts
 *   strict   - + database configs, any config that might contain secrets
 *
 * Setup in .claude/settings.json:
 * {
 *   "hooks": {
 *     "PreToolUse": [{
 *       "matcher": "Read|Edit|Write|Bash",
 *       "hooks": [{ "type": "command", "command": "node /path/to/protect-secrets.js" }]
 *     }]
 *   }
 * }
 */

const fs = require('fs');
const path = require('path');

const SAFETY_LEVEL = 'high';

// Files explicitly safe to access (templates, examples)
const ALLOWLIST = [
  /\.env\.example$/i, /\.env\.sample$/i, /\.env\.template$/i,
  /\.env\.schema$/i, /\.env\.defaults$/i, /env\.example$/i, /example\.env$/i,
];

// Sensitive file patterns for Read, Edit, Write tools
const SENSITIVE_FILES = [
  // CRITICAL
  // All path patterns use the `i` flag so that case-insensitive filesystems
  // (macOS HFS+, Windows NTFS) cannot bypass protection via .ENV or .Env etc.
  { level: 'critical', id: 'env-file',           regex: /(?:^|\/)\.env(?:\.[^/]*)?$/i,                    reason: '.env file contains secrets' },
  { level: 'critical', id: 'envrc',              regex: /(?:^|\/)\.envrc$/i,                              reason: '.envrc (direnv) contains secrets' },
  { level: 'critical', id: 'ssh-private-key',    regex: /(?:^|\/)\.ssh\/id_[^/]+$/i,                      reason: 'SSH private key' },
  { level: 'critical', id: 'ssh-private-key-2',  regex: /(?:^|\/)(id_rsa|id_ed25519|id_ecdsa|id_dsa)$/i,  reason: 'SSH private key' },
  { level: 'critical', id: 'ssh-authorized',     regex: /(?:^|\/)\.ssh\/authorized_keys$/i,               reason: 'SSH authorized_keys' },
  { level: 'critical', id: 'aws-credentials',    regex: /(?:^|\/)\.aws\/credentials$/i,                   reason: 'AWS credentials file' },
  { level: 'critical', id: 'aws-config',         regex: /(?:^|\/)\.aws\/config$/i,                        reason: 'AWS config may contain secrets' },
  { level: 'critical', id: 'kube-config',        regex: /(?:^|\/)\.kube\/config$/i,                       reason: 'Kubernetes config contains credentials' },
  { level: 'critical', id: 'pem-key',            regex: /\.pem$/i,                                        reason: 'PEM key file' },
  { level: 'critical', id: 'key-file',           regex: /\.key$/i,                                        reason: 'Key file' },
  { level: 'critical', id: 'p12-key',            regex: /\.(p12|pfx)$/i,                                  reason: 'PKCS12 key file' },

  // HIGH
  { level: 'high', id: 'credentials-json',       regex: /(?:^|\/)credentials\.json$/i,                    reason: 'Credentials file' },
  { level: 'high', id: 'secrets-file',           regex: /(?:^|\/)(secrets?|credentials?)\.(json|ya?ml|toml)$/i, reason: 'Secrets configuration file' },
  { level: 'high', id: 'service-account',        regex: /service[_-]?account.*\.json$/i,                  reason: 'GCP service account key' },
  { level: 'high', id: 'gcloud-creds',           regex: /(?:^|\/)\.config\/gcloud\/.*(credentials|tokens)/i, reason: 'GCloud credentials' },
  { level: 'high', id: 'azure-creds',            regex: /(?:^|\/)\.azure\/(credentials|accessTokens)/i,   reason: 'Azure credentials' },
  { level: 'high', id: 'docker-config',          regex: /(?:^|\/)\.docker\/config\.json$/i,               reason: 'Docker config may contain registry auth' },
  { level: 'high', id: 'netrc',                  regex: /(?:^|\/)\.netrc$/i,                              reason: '.netrc contains credentials' },
  { level: 'high', id: 'npmrc',                  regex: /(?:^|\/)\.npmrc$/i,                              reason: '.npmrc may contain auth tokens' },
  { level: 'high', id: 'pypirc',                 regex: /(?:^|\/)\.pypirc$/i,                             reason: '.pypirc contains PyPI credentials' },
  { level: 'high', id: 'gem-creds',              regex: /(?:^|\/)\.gem\/credentials$/i,                   reason: 'RubyGems credentials' },
  { level: 'high', id: 'vault-token',            regex: /(?:^|\/)(\.vault-token|vault-token)$/i,          reason: 'Vault token file' },
  { level: 'high', id: 'keystore',               regex: /\.(keystore|jks)$/i,                             reason: 'Java keystore' },
  { level: 'high', id: 'htpasswd',               regex: /(?:^|\/)\.?htpasswd$/i,                          reason: 'htpasswd contains hashed passwords' },
  { level: 'high', id: 'pgpass',                 regex: /(?:^|\/)\.pgpass$/i,                             reason: 'PostgreSQL password file' },
  { level: 'high', id: 'my-cnf',                 regex: /(?:^|\/)\.my\.cnf$/i,                            reason: 'MySQL config may contain password' },

  // STRICT
  { level: 'strict', id: 'database-config',      regex: /(?:^|\/)(?:config\/)?database\.(json|ya?ml)$/i,  reason: 'Database config may contain passwords' },
  { level: 'strict', id: 'ssh-known-hosts',      regex: /(?:^|\/)\.ssh\/known_hosts$/i,                   reason: 'SSH known_hosts reveals infrastructure' },
  { level: 'strict', id: 'gitconfig',            regex: /(?:^|\/)\.gitconfig$/i,                          reason: '.gitconfig may contain credentials' },
  { level: 'strict', id: 'curlrc',               regex: /(?:^|\/)\.curlrc$/i,                             reason: '.curlrc may contain auth' },
];

// Bash patterns that expose or exfiltrate secrets
const BASH_PATTERNS = [
  // CRITICAL
  { level: 'critical', id: 'cat-env',            regex: /\b(cat|less|head|tail|more|bat|view)\s+[^|;]*\.env\b/i,           reason: 'Reading .env file exposes secrets' },
  { level: 'critical', id: 'cat-ssh-key',        regex: /\b(cat|less|head|tail|more|bat)\s+[^|;]*(id_rsa|id_ed25519|id_ecdsa|id_dsa|\.pem|\.key)\b/i, reason: 'Reading private key' },
  { level: 'critical', id: 'cat-aws-creds',      regex: /\b(cat|less|head|tail|more)\s+[^|;]*\.aws\/credentials/i,         reason: 'Reading AWS credentials' },

  // HIGH - Environment exposure
  { level: 'high', id: 'env-dump',               regex: /\bprintenv\b|(?:^|[;&|]\s*)env\s*(?:$|[;&|])/,                    reason: 'Environment dump may expose secrets' },
  { level: 'high', id: 'echo-secret-var',        regex: /\becho\b[^;|&]*\$\{?[A-Za-z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASSW|CREDENTIAL|API_KEY|AUTH|PRIVATE)[A-Za-z_]*\}?/i, reason: 'Echoing secret variable' },
  { level: 'high', id: 'printf-secret-var',      regex: /\bprintf\b[^;|&]*\$\{?[A-Za-z_]*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|API_KEY|AUTH|PRIVATE)[A-Za-z_]*\}?/i, reason: 'Printing secret variable' },
  { level: 'high', id: 'cat-secrets-file',       regex: /\b(cat|less|head|tail|more)\s+[^|;]*(credentials?|secrets?)\.(json|ya?ml|toml)/i, reason: 'Reading secrets file' },
  { level: 'high', id: 'cat-netrc',              regex: /\b(cat|less|head|tail|more)\s+[^|;]*\.netrc/i,                    reason: 'Reading .netrc credentials' },
  { level: 'high', id: 'source-env',             regex: /\bsource\s+[^|;]*\.env\b|(?:^|[;&|]\s*)\.\s+[^|;]*\.env\b|^\.\s+[^|;]*\.env\b/i, reason: 'Sourcing .env loads secrets' },
  { level: 'high', id: 'export-cat-env',         regex: /export\s+.*\$\(cat\s+[^)]*\.env/i,                                reason: 'Exporting secrets from .env' },

  // HIGH - Exfiltration
  { level: 'high', id: 'curl-upload-env',        regex: /\bcurl\b[^;|&]*(-d\s*@|-F\s*[^=]+=@|--data[^=]*=@)[^;|&]*(\.env|credentials|secrets|id_rsa|\.pem|\.key)/i, reason: 'Uploading secrets via curl' },
  { level: 'high', id: 'curl-post-secrets',      regex: /\bcurl\b[^;|&]*-X\s*POST[^;|&]*[^;|&]*(\.env|credentials|secrets)/i, reason: 'POSTing secrets via curl' },
  { level: 'high', id: 'wget-post-secrets',      regex: /\bwget\b[^;|&]*--post-file[^;|&]*(\.env|credentials|secrets)/i,  reason: 'POSTing secrets via wget' },
  { level: 'high', id: 'scp-secrets',            regex: /\bscp\b[^;|&]*(\.env|credentials|secrets|id_rsa|\.pem|\.key)[^;|&]+:/i, reason: 'Copying secrets via scp' },
  { level: 'high', id: 'rsync-secrets',          regex: /\brsync\b[^;|&]*(\.env|credentials|secrets|id_rsa)[^;|&]+:/i,    reason: 'Syncing secrets via rsync' },
  { level: 'high', id: 'nc-secrets',             regex: /\bnc\b[^;|&]*<[^;|&]*(\.env|credentials|secrets|id_rsa)/i,       reason: 'Exfiltrating secrets via netcat' },

  // HIGH - Write/overwrite secrets via tee or shell redirection
  // `tee` writes stdin to a file, bypassing the Write tool check entirely.
  // Shell redirections like `echo x > .env` or `cat > .env << EOF` are caught
  // here since the Bash hook sees the raw command string.
  { level: 'high', id: 'tee-env',                regex: /\btee\b[^;|&]*\.env\b/i,                                          reason: 'Writing to .env via tee' },
  { level: 'high', id: 'tee-ssh-key',            regex: /\btee\b[^;|&]*(id_rsa|id_ed25519|id_ecdsa|\.pem|\.key)\b/i,       reason: 'Writing to key file via tee' },
  { level: 'high', id: 'redirect-env',           regex: /(?<![<])>\s*\.env\b/i,                                             reason: 'Shell redirection overwrites .env' },

  // HIGH - Encode/dump secrets (reads file content even without cat)
  // These tools read files and emit their content in another form, which is
  // functionally equivalent to `cat` for exfiltration purposes.
  { level: 'high', id: 'encode-env',             regex: /\b(base64|xxd|od|hexdump|strings)\b[^|;]*\.env\b/i,               reason: 'Encoding/dumping .env exposes secrets' },
  { level: 'high', id: 'encode-ssh-key',         regex: /\b(base64|xxd|od|hexdump)\b[^|;]*(id_rsa|id_ed25519|id_ecdsa|\.pem|\.key)\b/i, reason: 'Encoding/dumping private key' },
  { level: 'high', id: 'encode-aws-creds',       regex: /\b(base64|xxd|od|hexdump)\b[^|;]*\.aws\/credentials/i,            reason: 'Encoding/dumping AWS credentials' },

  // HIGH - Copy/move/delete secrets
  { level: 'high', id: 'cp-env',                 regex: /\bcp\b[^;|&]*\.env\b/i,                                           reason: 'Copying .env file' },
  { level: 'high', id: 'cp-ssh-key',             regex: /\bcp\b[^;|&]*(id_rsa|id_ed25519|\.pem|\.key)\b/i,                 reason: 'Copying private key' },
  { level: 'high', id: 'mv-env',                 regex: /\bmv\b[^;|&]*\.env\b/i,                                           reason: 'Moving .env file' },
  { level: 'high', id: 'rm-ssh-key',             regex: /\brm\b[^;|&]*(id_rsa|id_ed25519|id_ecdsa|authorized_keys)/i,      reason: 'Deleting SSH key' },
  { level: 'high', id: 'rm-env',                 regex: /\brm\b.*\.env\b/i,                                                 reason: 'Deleting .env file' },
  { level: 'high', id: 'rm-aws-creds',           regex: /\brm\b[^;|&]*\.aws\/credentials/i,                                reason: 'Deleting AWS credentials' },
  { level: 'high', id: 'truncate-secrets',       regex: /\btruncate\b.*\.(env|pem|key)\b/i,                                 reason: 'Truncating secrets file' },

  // HIGH - Process environ
  { level: 'high', id: 'proc-environ',           regex: /\/proc\/[^/]*\/environ/,                                          reason: 'Reading process environment' },
  { level: 'high', id: 'xargs-cat-env',          regex: /xargs.*cat|\.env.*xargs/i,                                         reason: 'Reading .env via xargs' },
  { level: 'high', id: 'find-exec-cat-env',      regex: /find\b.*\.env.*-exec|find\b.*-exec.*(cat|less)/i,                 reason: 'Finding and reading .env files' },

  // STRICT
  { level: 'strict', id: 'grep-password',        regex: /\bgrep\b[^|;]*(-r|--recursive)[^|;]*(password|secret|api.?key|token|credential)/i, reason: 'Grep for secrets may expose them' },
];

const LEVELS = { critical: 1, high: 2, strict: 3 };
const EMOJIS = { critical: '🔐', high: '🛡️', strict: '⚠️' };
const LOG_DIR = path.join(process.env.HOME, '.claude', 'hooks-logs');

function log(data) {
  try {
    if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
    const file = path.join(LOG_DIR, `${new Date().toISOString().slice(0, 10)}.jsonl`);
    fs.appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), hook: 'protect-secrets', ...data }) + '\n');
  } catch {}
}

function isAllowlisted(filePath) {
  return filePath && ALLOWLIST.some(p => p.test(filePath));
}

function checkFilePath(filePath, safetyLevel = SAFETY_LEVEL) {
  if (!filePath || isAllowlisted(filePath)) return { blocked: false, pattern: null };
  const threshold = LEVELS[safetyLevel] || 2;
  for (const p of SENSITIVE_FILES) {
    if (LEVELS[p.level] <= threshold && p.regex.test(filePath)) {
      return { blocked: true, pattern: p };
    }
  }
  return { blocked: false, pattern: null };
}

function checkBashCommand(cmd, safetyLevel = SAFETY_LEVEL) {
  if (!cmd) return { blocked: false, pattern: null };
  for (const allow of ALLOWLIST) {
    if (allow.test(cmd)) return { blocked: false, pattern: null };
  }
  const threshold = LEVELS[safetyLevel] || 2;
  for (const p of BASH_PATTERNS) {
    if (LEVELS[p.level] <= threshold && p.regex.test(cmd)) {
      return { blocked: true, pattern: p };
    }
  }
  return { blocked: false, pattern: null };
}

function check(toolName, toolInput, safetyLevel = SAFETY_LEVEL) {
  if (['Read', 'Edit', 'Write'].includes(toolName)) {
    return checkFilePath(toolInput?.file_path, safetyLevel);
  }
  if (toolName === 'Bash') {
    return checkBashCommand(toolInput?.command, safetyLevel);
  }
  return { blocked: false, pattern: null };
}

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;

  try {
    const data = JSON.parse(input);
    const { tool_name, tool_input, session_id, cwd, permission_mode } = data;

    if (!['Read', 'Edit', 'Write', 'Bash'].includes(tool_name)) {
      return console.log('{}');
    }

    const result = check(tool_name, tool_input);

    if (result.blocked) {
      const p = result.pattern;
      const target = tool_input?.file_path || tool_input?.command?.slice(0, 100);
      log({ level: 'BLOCKED', id: p.id, priority: p.level, tool: tool_name, target, session_id, cwd, permission_mode });

      const action = { Read: 'read', Edit: 'modify', Write: 'write to', Bash: 'execute' }[tool_name];
      return console.log(JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: `${EMOJIS[p.level]} [${p.id}] Cannot ${action}: ${p.reason}`
        }
      }));
    }
    console.log('{}');
  } catch (e) {
    log({ level: 'ERROR', error: e.message });
    console.log('{}');
  }
}

if (require.main === module) {
  main();
} else {
  module.exports = {
    SENSITIVE_FILES, BASH_PATTERNS, ALLOWLIST, LEVELS, SAFETY_LEVEL,
    check, checkFilePath, checkBashCommand, isAllowlisted,
  };
}
