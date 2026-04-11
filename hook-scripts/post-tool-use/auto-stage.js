#!/usr/bin/env node
/**
 * Auto Stage - PostToolUse Hook for Edit|Write
 * Automatically stages files after Claude Code modifies them.
 * Logs to: ~/.claude/hooks-logs/
 *
 * Benefits:
 *   - `git status` shows exactly what Claude modified
 *   - Easy to review changes before committing
 *   - No manual staging needed
 *
 * Note: Sensitive files are skipped regardless of .gitignore state. See SENSITIVE_PATTERNS.
 *
 * Setup in .claude/settings.json:
 * {
 *   "hooks": {
 *     "PostToolUse": [{
 *       "matcher": "Edit|Write",
 *       "hooks": [{ "type": "command", "command": "node /path/to/auto-stage.js" }]
 *     }]
 *   }
 * }
 */

const fs = require('fs');
const path = require('path');
const { execSync, spawnSync } = require('child_process');

// Files that must never be staged regardless of .gitignore state.
// Mirrors the CRITICAL + HIGH entries from protect-secrets.js so that even if
// that hook is misconfigured, auto-stage won't silently commit secrets.
const SENSITIVE_PATTERNS = [
  // CRITICAL — environment and key files
  /(?:^|\/)\.env(?:\.[^/]*)?$/i,
  /(?:^|\/)\.envrc$/i,
  /(?:^|\/)\.ssh\/id_[^/]+$/i,
  /(?:^|\/)(id_rsa|id_ed25519|id_ecdsa|id_dsa)$/i,
  /(?:^|\/)\.ssh\/authorized_keys$/i,
  /(?:^|\/)\.aws\/credentials$/i,
  /(?:^|\/)\.aws\/config$/i,
  /(?:^|\/)\.kube\/config$/i,
  /\.pem$/i,
  /\.key$/i,
  /\.(p12|pfx)$/i,

  // HIGH — credentials and auth files
  /(?:^|\/)credentials\.json$/i,
  /(?:^|\/)(secrets?|credentials?)\.(json|ya?ml|toml)$/i,
  /service[_-]?account.*\.json$/i,
  /(?:^|\/)\.config\/gcloud\/.*(credentials|tokens)/i,
  /(?:^|\/)\.azure\/(credentials|accessTokens)/i,
  /(?:^|\/)\.docker\/config\.json$/i,
  /(?:^|\/)\.netrc$/i,
  /(?:^|\/)\.npmrc$/i,
  /(?:^|\/)\.pypirc$/i,
  /(?:^|\/)\.gem\/credentials$/i,
  /(?:^|\/)(\.vault-token|vault-token)$/i,
  /\.(keystore|jks)$/i,
  /(?:^|\/)\.?htpasswd$/i,
  /(?:^|\/)\.pgpass$/i,
  /(?:^|\/)\.my\.cnf$/i,
];

const SENSITIVE_ALLOWLIST = [
  /\.env\.example$/i, /\.env\.sample$/i, /\.env\.template$/i,
  /\.env\.schema$/i, /\.env\.defaults$/i, /env\.example$/i, /example\.env$/i,
];

function isSensitiveFile(filePath) {
  if (SENSITIVE_ALLOWLIST.some(p => p.test(filePath))) return false;
  return SENSITIVE_PATTERNS.some(p => p.test(filePath));
}

const LOG_DIR = path.join(process.env.HOME, '.claude', 'hooks-logs');

function log(data) {
  try {
    if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
    const file = path.join(LOG_DIR, `${new Date().toISOString().slice(0, 10)}.jsonl`);
    fs.appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), hook: 'auto-stage', ...data }) + '\n');
  } catch {}
}

function isInGitRepo(filePath) {
  try {
    const dir = path.dirname(filePath);
    execSync('git rev-parse --git-dir', { cwd: dir, stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function stageFile(filePath) {
  try {
    const dir = path.dirname(filePath);
    const result = spawnSync('git', ['add', '--', filePath], { cwd: dir, stdio: 'pipe' });
    if (result.status !== 0) {
      const stderr = result.stderr ? result.stderr.toString() : '';
      return { success: false, error: stderr || `exit code ${result.status}` };
    }
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;

  try {
    const data = JSON.parse(input);
    const { tool_name, tool_input, session_id, cwd } = data;

    if (!['Edit', 'Write'].includes(tool_name)) {
      return console.log('{}');
    }

    const filePath = tool_input?.file_path;
    if (!filePath) {
      log({ level: 'SKIP', reason: 'no file_path', tool: tool_name, session_id });
      return console.log('{}');
    }

    // Resolve to absolute path if relative
    const absPath = path.isAbsolute(filePath) ? filePath : path.join(cwd || process.cwd(), filePath);

    if (isSensitiveFile(absPath)) {
      log({ level: 'SKIP', reason: 'sensitive file', file: absPath, session_id });
      return console.log('{}');
    }

    if (!isInGitRepo(absPath)) {
      log({ level: 'SKIP', reason: 'not in git repo', file: absPath, session_id });
      return console.log('{}');
    }

    const result = stageFile(absPath);
    if (result.success) {
      log({ level: 'STAGED', file: absPath, tool: tool_name, session_id });
    } else {
      log({ level: 'ERROR', file: absPath, error: result.error, session_id });
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
  module.exports = { isInGitRepo, stageFile, isSensitiveFile, log };
}
