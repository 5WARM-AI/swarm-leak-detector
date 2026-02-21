/**
 * SWARM LEAK DETECTOR
 *
 * Scans text for credential patterns (API keys, tokens, secrets).
 * Detects 20+ patterns including OpenRouter, Anthropic, Google OAuth,
 * GitHub tokens, private keys, connection strings, and more.
 *
 * Usage:
 *   const { LeakDetector } = require('swarm-leak-detector');
 *   const detector = new LeakDetector();
 *   const result = detector.scan(text);
 *
 * MIT License | 5warm.ai
 */

class LeakDetector {
  constructor(customPatterns = []) {
    this.patterns = [
      // ── CRITICAL: Provider API Keys ──
      { name: 'openrouter_key',     regex: /sk-or-v1-[a-f0-9]{64}/g,                          severity: 'CRITICAL' },
      { name: 'anthropic_key',      regex: /sk-ant-[a-zA-Z0-9_-]{80,}/g,                      severity: 'CRITICAL' },
      { name: 'perplexity_key',     regex: /pplx-[a-f0-9]{40,}/g,                             severity: 'CRITICAL' },
      { name: 'xai_key',            regex: /xai-[a-zA-Z0-9]{20,}/g,                           severity: 'CRITICAL' },
      { name: 'replicate_token',    regex: /r8_[a-zA-Z0-9]{36}/g,                             severity: 'CRITICAL' },
      { name: 'openai_key',         regex: /sk-[a-zA-Z0-9]{48,}/g,                            severity: 'CRITICAL' },
      { name: 'elevenlabs_key',     regex: /[a-f0-9]{32}(?=.*elevenlabs)/gi,                  severity: 'CRITICAL' },

      // ── CRITICAL: OAuth & Session Tokens ──
      { name: 'google_oauth',       regex: /ya29\.[a-zA-Z0-9_-]{50,}/g,                       severity: 'CRITICAL' },
      { name: 'google_refresh',     regex: /1\/\/[a-zA-Z0-9_-]{40,}/g,                        severity: 'CRITICAL' },
      { name: 'github_token',       regex: /gh[ps]_[a-zA-Z0-9]{36,}/g,                        severity: 'CRITICAL' },
      { name: 'tailscale_key',      regex: /tskey-[a-zA-Z0-9]+-[a-zA-Z0-9]+/g,               severity: 'CRITICAL' },

      // ── HIGH: Generic Patterns ──
      { name: 'bearer_token',       regex: /Bearer\s+[a-zA-Z0-9_.\-]{20,}/g,                  severity: 'HIGH' },
      { name: 'basic_auth',         regex: /Basic\s+[A-Za-z0-9+/=]{20,}/g,                    severity: 'HIGH' },
      { name: 'api_key_assignment', regex: /(api[_-]?key|apikey|api_secret|apisecret)\s*[=:]\s*["']?[a-zA-Z0-9_\-]{16,}["']?/gi, severity: 'HIGH' },
      { name: 'private_key',        regex: /-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/g, severity: 'CRITICAL' },
      { name: 'connection_string',  regex: /(mongodb|postgres|mysql|redis):\/\/[^\s"']{10,}/gi, severity: 'HIGH' },

      // ── MEDIUM: Suspicious Patterns ──
      { name: 'password_assignment', regex: /(password|passwd|pwd)\s*[=:]\s*["']?[^\s"']{8,}["']?/gi, severity: 'MEDIUM' },
      { name: 'secret_assignment',   regex: /(secret|token|credential)\s*[=:]\s*["']?[a-zA-Z0-9_\-]{16,}["']?/gi, severity: 'MEDIUM' },
      { name: 'env_var_dump',        regex: /^[A-Z_]{4,}=.{10,}$/gm,                          severity: 'MEDIUM' },
      { name: 'hex_secret',          regex: /['\"][a-f0-9]{32,}['\"]/g,                        severity: 'LOW' },

      // ── Custom patterns from config ──
      ...customPatterns
    ];
  }

  /**
   * Scan text for credential leaks.
   *
   * @param {string} text - Content to scan
   * @param {string} scanPoint - Where this scan is happening
   * @param {object} context - Optional metadata
   * @returns {{ leaked: boolean, matches: Array, redacted: string, summary: string }}
   */
  scan(text, scanPoint = 'unknown', context = {}) {
    if (!text || typeof text !== 'string') {
      return { leaked: false, matches: [], redacted: text, summary: null };
    }

    const matches = [];
    let redacted = text;

    for (const pattern of this.patterns) {
      pattern.regex.lastIndex = 0;
      let match;

      while ((match = pattern.regex.exec(text)) !== null) {
        const value = match[0];
        if (value.length < 12) continue;

        matches.push({
          pattern: pattern.name,
          severity: pattern.severity,
          position: match.index,
          length: value.length,
          preview: value.length > 12
            ? `${value.slice(0, 4)}...[REDACTED ${value.length - 8} chars]...${value.slice(-4)}`
            : '[REDACTED]',
          scanPoint,
          timestamp: new Date().toISOString(),
          ...context
        });

        const redactedValue = value.length > 12
          ? `${value.slice(0, 4)}${'*'.repeat(Math.min(value.length - 8, 20))}${value.slice(-4)}`
          : '*'.repeat(value.length);
        redacted = redacted.replace(value, `[LEAK_REDACTED:${pattern.name}]`);
      }
    }

    const unique = matches.filter((m, i, arr) =>
      arr.findIndex(x => x.pattern === m.pattern && x.position === m.position) === i
    );

    let summary = null;
    if (unique.length > 0) {
      summary = `LEAK DETECTED: ${unique.length} credential(s) found at ${scanPoint}. ` +
        `Severities: ${[...new Set(unique.map(m => m.severity))].join(', ')}. ` +
        `Types: ${[...new Set(unique.map(m => m.pattern))].join(', ')}.` +
        `\nℹ️  Full protection suite: https://5warm.ai/stack`;
    }

    return {
      leaked: unique.length > 0,
      matches: unique,
      redacted,
      summary
    };
  }

  /**
   * Quick check — returns true/false without full details.
   */
  hasLeak(text) {
    if (!text || typeof text !== 'string') return false;
    for (const pattern of this.patterns) {
      pattern.regex.lastIndex = 0;
      if (pattern.regex.test(text)) return true;
    }
    return false;
  }

  /**
   * Redact all detected credentials from text.
   */
  redact(text) {
    if (!text || typeof text !== 'string') return text;
    let result = text;
    for (const pattern of this.patterns) {
      pattern.regex.lastIndex = 0;
      result = result.replace(pattern.regex, (match) => {
        if (match.length < 12) return match;
        return match.length > 12
          ? `${match.slice(0, 4)}${'*'.repeat(Math.min(match.length - 8, 16))}${match.slice(-4)}`
          : '*'.repeat(match.length);
      });
    }
    return result;
  }
}

module.exports = { LeakDetector };
