#!/usr/bin/env node
/**
 * Tests for auto-stage.js
 *
 * Run: node --test hook-scripts/tests/post-tool-use/auto-stage.test.js
 * Or:  npm test
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn, execSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { isInGitRepo, stageFile, isSensitiveFile } = require('../../post-tool-use/auto-stage.js');

const SCRIPT_PATH = path.join(__dirname, '../../post-tool-use/auto-stage.js');

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

function runHook(toolName, toolInput, cwd = '/tmp') {
  return new Promise((resolve, reject) => {
    const child = spawn('node', [SCRIPT_PATH]);
    let stdout = '', stderr = '';

    child.stdout.on('data', d => stdout += d);
    child.stderr.on('data', d => stderr += d);
    child.on('close', code => {
      try {
        resolve({ code, output: JSON.parse(stdout.trim() || '{}'), stderr });
      } catch (e) {
        reject(new Error(`Failed to parse: ${stdout}`));
      }
    });

    child.stdin.write(JSON.stringify({
      hook_event_name: 'PostToolUse',
      tool_name: toolName,
      tool_input: toolInput,
      tool_response: { success: true },
      session_id: 'test-session',
      cwd,
    }));
    child.stdin.end();
  });
}

let tempDir, testFile;

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests - isInGitRepo
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests - isSensitiveFile
// ─────────────────────────────────────────────────────────────────────────────

describe('Unit: isSensitiveFile()', () => {
  // CRITICAL
  it('blocks .env', () => assert.strictEqual(isSensitiveFile('/app/.env'), true));
  it('blocks .env.local', () => assert.strictEqual(isSensitiveFile('/app/.env.local'), true));
  it('blocks .ENV (uppercase, macOS)', () => assert.strictEqual(isSensitiveFile('/app/.ENV'), true));
  it('blocks ~/.aws/credentials', () => assert.strictEqual(isSensitiveFile('/home/user/.aws/credentials'), true));
  it('blocks ~/.ssh/id_rsa', () => assert.strictEqual(isSensitiveFile('/home/user/.ssh/id_rsa'), true));
  it('blocks server.pem', () => assert.strictEqual(isSensitiveFile('/ssl/server.pem'), true));
  it('blocks private.key', () => assert.strictEqual(isSensitiveFile('/ssl/private.key'), true));
  // HIGH
  it('blocks credentials.json', () => assert.strictEqual(isSensitiveFile('/app/credentials.json'), true));
  it('blocks secrets.yaml', () => assert.strictEqual(isSensitiveFile('/app/secrets.yaml'), true));
  it('blocks service-account.json', () => assert.strictEqual(isSensitiveFile('/app/service-account.json'), true));
  it('blocks ~/.docker/config.json', () => assert.strictEqual(isSensitiveFile('/home/user/.docker/config.json'), true));
  it('blocks ~/.netrc', () => assert.strictEqual(isSensitiveFile('/home/user/.netrc'), true));
  it('blocks ~/.npmrc', () => assert.strictEqual(isSensitiveFile('/home/user/.npmrc'), true));
  it('blocks ~/.pypirc', () => assert.strictEqual(isSensitiveFile('/home/user/.pypirc'), true));
  it('blocks ~/.pgpass', () => assert.strictEqual(isSensitiveFile('/home/user/.pgpass'), true));
  it('blocks debug.keystore', () => assert.strictEqual(isSensitiveFile('/app/debug.keystore'), true));
  // allowlist
  it('allows .env.example', () => assert.strictEqual(isSensitiveFile('/app/.env.example'), false));
  it('allows .env.sample', () => assert.strictEqual(isSensitiveFile('/app/.env.sample'), false));
  it('allows package.json', () => assert.strictEqual(isSensitiveFile('/app/package.json'), false));
  it('allows src/index.js', () => assert.strictEqual(isSensitiveFile('/app/src/index.js'), false));
});

describe('Unit: isInGitRepo()', () => {
  it('returns true for file in git repo', () => {
    assert.strictEqual(isInGitRepo(__filename), true);
  });

  it('returns false for /tmp', () => {
    assert.strictEqual(isInGitRepo('/tmp/somefile.txt'), false);
  });

  it('returns false for nonexistent path', () => {
    assert.strictEqual(isInGitRepo('/nonexistent/path/file.txt'), false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests - stageFile
// ─────────────────────────────────────────────────────────────────────────────

describe('Unit: stageFile()', () => {
  before(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'auto-stage-test-'));
    execSync('git init && git config user.email "test@test.com" && git config user.name "Test"', { cwd: tempDir, stdio: 'pipe' });
    testFile = path.join(tempDir, 'test.txt');
    fs.writeFileSync(testFile, 'hello');
  });

  after(() => {
    if (tempDir) fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('stages file successfully', () => {
    const result = stageFile(testFile);
    assert.strictEqual(result.success, true);
    const status = execSync('git status --porcelain', { cwd: tempDir, encoding: 'utf8' });
    assert.ok(status.includes('A  test.txt') || status.includes('M  test.txt'));
  });

  it('handles nonexistent file', () => {
    const result = stageFile(path.join(tempDir, 'nonexistent.txt'));
    assert.ok('success' in result);
  });

  it('does not execute shell commands embedded in filenames', () => {
    // A filename containing shell metacharacters must be treated as a literal
    // path, not executed. With the old execSync(`git add "${filePath}"`), a
    // name like: evil"; touch marker; echo "x  would break out of the quotes
    // and run `touch marker` with cwd=tempDir.
    const markerName = `injection-marker-${Date.now()}`;
    const markerPath = path.join(tempDir, markerName);
    // Use only characters valid in a Unix filename (no slashes).
    // The injected command touches markerName relative to cwd (tempDir).
    const maliciousName = `evil"; touch ${markerName}; echo "x.txt`;
    const maliciousFile = path.join(tempDir, maliciousName);
    fs.writeFileSync(maliciousFile, 'payload');

    stageFile(maliciousFile);

    assert.strictEqual(
      fs.existsSync(markerPath),
      false,
      `Shell injection succeeded — marker file was created at ${markerPath}`
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Integration Tests - gitignore behavior
// ─────────────────────────────────────────────────────────────────────────────

describe('Integration: gitignore behavior', () => {
  let gitDir, ignoredFile;

  before(() => {
    gitDir = fs.mkdtempSync(path.join(os.tmpdir(), 'auto-stage-gitignore-'));
    execSync('git init && git config user.email "test@test.com" && git config user.name "Test"', { cwd: gitDir, stdio: 'pipe' });
    fs.writeFileSync(path.join(gitDir, '.gitignore'), 'ignored.txt\n');
    ignoredFile = path.join(gitDir, 'ignored.txt');
    fs.writeFileSync(ignoredFile, 'SECRET=123');
  });

  after(() => {
    if (gitDir) fs.rmSync(gitDir, { recursive: true, force: true });
  });

  it('git add on ignored file fails gracefully', () => {
    const result = stageFile(ignoredFile);
    // git add returns error for ignored files (exit code 1)
    assert.strictEqual(result.success, false);
    assert.ok(result.error.includes('ignored'));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Integration Tests - sensitive file guard
// ─────────────────────────────────────────────────────────────────────────────

describe('Integration: sensitive file guard', () => {
  let gitDir;

  before(() => {
    gitDir = fs.mkdtempSync(path.join(os.tmpdir(), 'auto-stage-sensitive-'));
    execSync('git init && git config user.email "test@test.com" && git config user.name "Test"', { cwd: gitDir, stdio: 'pipe' });
  });

  after(() => {
    if (gitDir) fs.rmSync(gitDir, { recursive: true, force: true });
  });

  it('does not stage .env even without .gitignore', async () => {
    const envFile = path.join(gitDir, '.env');
    fs.writeFileSync(envFile, 'SECRET=abc123');
    await runHook('Write', { file_path: envFile }, gitDir);
    const staged = execSync('git diff --cached --name-only', { cwd: gitDir, encoding: 'utf8' });
    assert.ok(!staged.includes('.env'), '.env should not be staged');
  });

  it('does not stage .ENV (uppercase)', async () => {
    const envFile = path.join(gitDir, '.ENV');
    fs.writeFileSync(envFile, 'SECRET=abc123');
    await runHook('Write', { file_path: envFile }, gitDir);
    const staged = execSync('git diff --cached --name-only', { cwd: gitDir, encoding: 'utf8' });
    assert.ok(!staged.toLowerCase().includes('.env'), '.ENV should not be staged');
  });

  it('does not stage .env.local', async () => {
    const envFile = path.join(gitDir, '.env.local');
    fs.writeFileSync(envFile, 'SECRET=abc123');
    await runHook('Write', { file_path: envFile }, gitDir);
    const staged = execSync('git diff --cached --name-only', { cwd: gitDir, encoding: 'utf8' });
    assert.ok(!staged.includes('.env.local'), '.env.local should not be staged');
  });

  it('still stages normal files', async () => {
    const jsFile = path.join(gitDir, 'index.js');
    fs.writeFileSync(jsFile, 'console.log("hello")');
    await runHook('Write', { file_path: jsFile }, gitDir);
    const staged = execSync('git diff --cached --name-only', { cwd: gitDir, encoding: 'utf8' });
    assert.ok(staged.includes('index.js'), 'index.js should be staged');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Integration Tests - stdin/stdout hook flow
// ─────────────────────────────────────────────────────────────────────────────

describe('Integration: stdin/stdout hook flow', () => {
  it('returns {} for Edit tool', async () => {
    const { code, output } = await runHook('Edit', { file_path: '/tmp/test.js', old_string: 'a', new_string: 'b' });
    assert.strictEqual(code, 0);
    assert.deepStrictEqual(output, {});
  });

  it('returns {} for Write tool', async () => {
    const { code, output } = await runHook('Write', { file_path: '/tmp/test.js', content: 'hello' });
    assert.strictEqual(code, 0);
    assert.deepStrictEqual(output, {});
  });

  it('returns {} for non-Edit/Write tool', async () => {
    const { code, output } = await runHook('Read', { file_path: '/tmp/test.js' });
    assert.strictEqual(code, 0);
    assert.deepStrictEqual(output, {});
  });

  it('handles missing file_path', async () => {
    const { code, output } = await runHook('Edit', { old_string: 'a', new_string: 'b' });
    assert.strictEqual(code, 0);
    assert.deepStrictEqual(output, {});
  });

  it('handles malformed JSON', async () => {
    const child = spawn('node', [SCRIPT_PATH]);
    let stdout = '';
    const result = await new Promise(resolve => {
      child.stdout.on('data', d => stdout += d);
      child.on('close', code => resolve({ code, output: stdout.trim() }));
      child.stdin.write('not json');
      child.stdin.end();
    });
    assert.strictEqual(result.output, '{}');
  });
});
