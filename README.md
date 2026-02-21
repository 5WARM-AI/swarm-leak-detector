# Swarm Leak Detector

**Free, open-source credential leak detection.** Catches API keys, OAuth tokens, private keys, connection strings, and 20+ patterns before they end up somewhere they shouldn't.

Zero dependencies. Works with any Node.js project.

> 💡 **This is the free tier of [Swarm Stack](https://5warm.ai/stack).** Want real-time Telegram alerts, prompt injection defense, and full audit logging? [See the full security suite →](https://5warm.ai/stack)

## Install

```bash
npm install swarm-leak-detector
```

Or just copy `index.js` into your project.

## Usage

```javascript
const { LeakDetector } = require('swarm-leak-detector');
const detector = new LeakDetector();

const result = detector.scan(someText);
if (result.leaked) {
  console.error(result.summary);
}
```

## What It Detects

**CRITICAL**
- OpenRouter keys (`sk-or-v1-...`)
- Anthropic keys (`sk-ant-...`)
- Perplexity keys (`pplx-...`)
- xAI keys (`xai-...`)
- Replicate tokens (`r8_...`)
- OpenAI keys (`sk-...`)
- ElevenLabs keys
- Google OAuth tokens (`ya29.`)
- Google refresh tokens
- GitHub tokens (`ghp_`, `ghs_`)
- Tailscale keys (`tskey-...`)
- Private keys (RSA, EC, OpenSSH)

**HIGH**
- Bearer tokens
- Basic auth headers
- Generic API key assignments
- Connection strings (MongoDB, PostgreSQL, MySQL, Redis)

**MEDIUM / LOW**
- Password assignments
- Secret/token assignments
- Environment variable dumps
- Hex secrets in strings

## API

### `detector.scan(text, scanPoint?, context?)`

Full scan. Returns:
```javascript
{
  leaked: boolean,       // true if any credentials found
  matches: [...],        // detailed match info (pattern, severity, position)
  redacted: string,      // text with credentials replaced
  summary: string|null   // human-readable summary
}
```

### `detector.hasLeak(text)`

Quick boolean check. Faster for high-volume scanning.

### `detector.redact(text)`

Returns text with all credentials masked. First and last 4 chars preserved, middle replaced with `*`.

### Custom Patterns

```javascript
const detector = new LeakDetector([
  { name: 'my_token', regex: /myapp-[a-z0-9]{32}/g, severity: 'CRITICAL' }
]);
```

## Examples

```javascript
// Scan a config file
const config = fs.readFileSync('.env', 'utf-8');
const result = detector.scan(config, 'config_audit');
if (result.leaked) {
  console.error('Credentials found in config!');
  console.error(result.summary);
}

// Sanitise log output
const safeLog = detector.redact(logEntry);
fs.appendFileSync('app.log', safeLog + '\n');

// Quick check before sending
if (detector.hasLeak(outboundMessage)) {
  throw new Error('Cannot send — contains credentials');
}
```

## 🚀 Upgrade to Swarm Stack

**This free leak detector is just the start.** For production AI agent deployments, you need the full security suite.

### [Swarm Stack Solo — $29/mo](https://5warm.ai/stack)
Everything in this free detector, plus:
- ✅ **Telegram alerts** — get notified the moment a leak is detected
- ✅ **Prompt injection defense** — detect attacks in external content
- ✅ **Structured audit logging** — JSONL trail of every security event
- ✅ **SOPS encryption** — no plaintext secrets on disk
- ✅ **Daily security digest** — "all clear" or "action needed" every morning

### [Swarm Stack Pro — $99/mo](https://5warm.ai/stack)
Everything in Solo, plus:
- ✅ **Auth proxy** — your agent never sees real API keys
- ✅ **Multi-LLM routing** — model-per-task with automatic fallback
- ✅ **Ops monitoring** — health checks, credit monitoring, alerts
- ✅ **Docker templates** — hardened multi-agent deployments
- ✅ **Priority support**

**[Get started at 5warm.ai/stack →](https://5warm.ai/stack)**

---

## License

MIT — use this free detector however you want. Upgrade when you're ready for production security.
