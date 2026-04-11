#!/usr/bin/env node
/**
 * Notification Hook - Sends Slack alerts when Claude needs user input.
 * Logs to: ~/.claude/hooks-logs/YYYY-MM-DD.jsonl
 *
 * Setup in .claude/settings.json:
 * {
 *   "hooks": {
 *     "Notification": [{
 *       "matcher": "permission_prompt|idle_prompt|elicitation_dialog",
 *       "hooks": [{ "type": "command", "command": "node /path/to/notify-permission.js" }]
 *     }]
 *   }
 * }
 *
 * Environment: CCH_SLA_WEBHOOK (Slack webhook URL)
 *
 * Privacy note: This hook is explicitly designed to send data off-machine.
 * The Slack payload contains: project name (basename only, not full path),
 * a 6-character session fragment, notification type, and a redacted message.
 * Secret-like values in the message are masked by redactSecrets() before
 * being sent to Slack or written to local logs. Do not set CCH_SLA_WEBHOOK
 * if you are working in a sensitive environment and cannot accept any
 * outbound notification traffic.
 */

const fs = require('fs');
const path = require('path');

// Channel webhooks (Discord/Telegram coming soon)
const SLACK_WEBHOOK = process.env.CCH_SLA_WEBHOOK || '';

const LOG_DIR = path.join(process.env.HOME, '.claude', 'hooks-logs');

function log(data) {
  try {
    if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
    const file = path.join(LOG_DIR, `${new Date().toISOString().slice(0, 10)}.jsonl`);
    fs.appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), hook: 'notify-permission', ...data }) + '\n');
  } catch {}
}

function getNotificationType(data) {
  if (data.notification_type) return data.notification_type;
  const msg = (data.message || '').toLowerCase();
  if (msg.includes('permission') || msg.includes('approve')) return 'permission_prompt';
  if (msg.includes('idle') || msg.includes('waiting')) return 'idle_prompt';
  if (msg.includes('elicitation') || msg.includes('mcp')) return 'elicitation_dialog';
  return 'notification';
}

function getProjectName(cwd) {
  return cwd ? path.basename(cwd) : 'unknown';
}

// Redact secret-like patterns from notification messages before they are sent
// to external channels. Notification messages can include content from blocked
// commands (e.g. a permission prompt for `echo $SECRET_KEY`), so we replace
// anything that looks like a secret value with [REDACTED].
const SECRET_PATTERNS = [
  // KEY=value or SECRET=value assignment forms
  /\b([A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|AUTH|PRIVATE)[A-Z_]*)=\S+/gi,
  // Bearer / Basic auth headers
  /\b(Bearer|Basic)\s+[A-Za-z0-9+/=._-]{8,}/gi,
  // AWS-style access keys (AKIA...)
  /\b(AKIA|ASIA|AROA)[A-Z0-9]{16}\b/g,
  // Long high-entropy strings that look like tokens (hex/base64, 20+ chars)
  /\b[A-Za-z0-9+/]{20,}={0,2}\b/g,
];

function redactSecrets(message) {
  if (!message) return message;
  let out = message;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, (match, ...groups) => {
      // For KEY=value patterns keep the key name, redact only the value
      const key = groups[0];
      return key && match.includes('=') ? `${key}=[REDACTED]` : '[REDACTED]';
    });
  }
  return out;
}

function getShortSessionId(sessionId) {
  return sessionId ? sessionId.slice(0, 6) : '????';
}

function getEmoji(type) {
  return { permission_prompt: '🔐', idle_prompt: '💤', elicitation_dialog: '🔧' }[type] || '🔔';
}

function getTitle(type, message) {
  const msg = (message || '').toLowerCase();

  if (type === 'elicitation_dialog' || msg.includes('select') || msg.includes('choose') || msg.includes('which')) {
    return 'Claude needs your choice';
  }
  if (type === 'permission_prompt') {
    if (msg.includes('bash') || msg.includes('command')) return 'Claude needs permission (Bash)';
    if (msg.includes('write') || msg.includes('create file')) return 'Claude needs permission (Write)';
    if (msg.includes('edit') || msg.includes('modify')) return 'Claude needs permission (Edit)';
    if (msg.includes('read')) return 'Claude needs permission (Read)';
    return 'Claude needs your attention';
  }
  if (type === 'idle_prompt') return 'Claude is waiting for you';
  return 'Claude notification';
}

function formatMessage(message) {
  if (!message) return '_No details provided_';
  return message.length > 200 ? message.slice(0, 200) + '...' : message;
}

async function sendSlack(data, type) {
  if (!SLACK_WEBHOOK) return { channel: 'slack', sent: false, reason: 'no webhook' };

  const payload = {
    blocks: [
      {
        type: 'header',
        text: { type: 'plain_text', text: `${getEmoji(type)} ${getTitle(type, data.message)}`, emoji: true },
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Project:*\n\`${getProjectName(data.cwd)}\`` },
          { type: 'mrkdwn', text: `*Session:*\n\`${getShortSessionId(data.session_id)}\`` },
        ],
      },
      {
        type: 'section',
        text: { type: 'mrkdwn', text: `*Details:*\n${formatMessage(redactSecrets(data.message))}` },
      },
      {
        type: 'context',
        elements: [
          { type: 'mrkdwn', text: `📁 \`${getProjectName(data.cwd)}\`` },
          { type: 'mrkdwn', text: `🕐 ${new Date().toLocaleTimeString()}` },
        ],
      },
    ],
  };

  try {
    const res = await fetch(SLACK_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return res.ok ? { channel: 'slack', sent: true } : { channel: 'slack', sent: false, error: `HTTP ${res.status}` };
  } catch (e) {
    return { channel: 'slack', sent: false, error: e.message };
  }
}

async function sendAll(data, type) {
  return Promise.all([sendSlack(data, type)]);
}

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;

  try {
    const data = JSON.parse(input);
    if (data.hook_event_name !== 'Notification') return console.log('{}');

    log({ level: 'INPUT', notification_type: data.notification_type, message: redactSecrets(data.message), session_id: data.session_id });

    const type = getNotificationType(data);
    const results = await sendAll(data, type);

    const sent = results.filter(r => r.sent).map(r => r.channel);
    const failed = results.filter(r => !r.sent && r.error);

    log({ level: sent.length ? 'SENT' : 'NONE', type, sent, failed, session_id: data.session_id });
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
    SLACK_WEBHOOK,
    getNotificationType,
    getProjectName,
    getShortSessionId,
    getEmoji,
    getTitle,
    formatMessage,
    redactSecrets,
    sendSlack,
    sendAll,
  };
}
