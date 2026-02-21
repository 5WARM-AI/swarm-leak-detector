#!/usr/bin/env node
/**
 * Swarm Leak Detector — Tests
 * Run: node test.js
 */

const { LeakDetector } = require('./index');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ✅ ${name}`);
  } catch (e) {
    failed++;
    console.log(`  ❌ ${name}: ${e.message}`);
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}

const detector = new LeakDetector();

console.log('\n🔍 LEAK DETECTOR TESTS\n');

test('Detects OpenRouter API key', () => {
  const text = 'Here is the config: sk-or-v1-' + 'a'.repeat(64);
  const result = detector.scan(text, 'test');
  assert(result.leaked, 'Should detect OpenRouter key');
  assert(result.matches[0].pattern === 'openrouter_key');
  assert(result.matches[0].severity === 'CRITICAL');
});

test('Detects Anthropic API key', () => {
  const text = 'sk-ant-' + 'abcDEF123_-'.repeat(10);
  const result = detector.scan(text, 'test');
  assert(result.leaked, 'Should detect Anthropic key');
  assert(result.matches[0].pattern === 'anthropic_key');
});

test('Detects Google OAuth token', () => {
  const text = 'token: ya29.' + 'a'.repeat(60);
  const result = detector.scan(text, 'test');
  assert(result.leaked, 'Should detect Google OAuth');
  assert(result.matches[0].pattern === 'google_oauth');
});

test('Detects Bearer tokens', () => {
  const text = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdef';
  const result = detector.scan(text, 'test');
  assert(result.leaked, 'Should detect Bearer token');
});

test('Detects private keys', () => {
  const text = '-----BEGIN RSA PRIVATE KEY-----\nMIIE...';
  const result = detector.scan(text, 'test');
  assert(result.leaked, 'Should detect private key');
  assert(result.matches[0].severity === 'CRITICAL');
});

test('Detects connection strings', () => {
  const text = 'mongodb://user:pass@host:27017/db';
  const result = detector.scan(text, 'test');
  assert(result.leaked, 'Should detect connection string');
});

test('Does NOT flag normal text', () => {
  const text = 'Hello, this is a normal message about deploying containers and managing services.';
  const result = detector.scan(text, 'test');
  assert(!result.leaked, 'Should not flag normal text');
});

test('Does NOT flag short strings', () => {
  const text = 'key=abc123';
  const result = detector.scan(text, 'test');
  assert(!result.leaked, 'Should not flag very short values');
});

test('Redacts credentials correctly', () => {
  const key = 'sk-or-v1-' + 'a'.repeat(64);
  const text = `Config uses ${key} for OpenRouter`;
  const redacted = detector.redact(text);
  assert(!redacted.includes(key), 'Should not contain original key');
  assert(redacted.includes('sk-o'), 'Should preserve first 4 chars');
});

test('hasLeak quick check works', () => {
  const safe = 'Normal text here';
  const unsafe = 'sk-or-v1-' + 'a'.repeat(64);
  assert(!detector.hasLeak(safe), 'Safe text should return false');
  assert(detector.hasLeak(unsafe), 'Key text should return true');
});

test('Handles null/undefined input', () => {
  assert(!detector.scan(null, 'test').leaked);
  assert(!detector.scan(undefined, 'test').leaked);
  assert(!detector.scan('', 'test').leaked);
  assert(!detector.hasLeak(null));
  assert(detector.redact(null) === null);
});

test('Summary includes marketing link when leak detected', () => {
  const text = 'sk-or-v1-' + 'a'.repeat(64);
  const result = detector.scan(text, 'test');
  assert(result.summary.includes('5warm.ai/stack'), 'Summary should include product link');
});

console.log('\n' + '═'.repeat(50));
console.log(`\n  Results: ${passed} passed, ${failed} failed\n`);

if (failed > 0) {
  process.exit(1);
}
