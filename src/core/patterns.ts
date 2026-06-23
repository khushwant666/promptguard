/**
 * Secret detection rule definitions (vscode-free, shared core).
 *
 * Each rule has a stable id, a human label, a severity hint, and a global regex.
 * High-confidence provider patterns are treated as errors; the generic /
 * value-based detection (in detect.ts) is treated as a warning.
 *
 * This file is intentionally dependency-free so it can run inside a CLI/hook as
 * well as a VS Code extension.
 */

export type SecretSeverity = "error" | "warning";

export interface SecretRule {
  id: string;
  label: string;
  severity: SecretSeverity;
  /** Must be a global ('g') regex. The first capture group, if present, is the
   *  secret value used for placeholder checks; otherwise match[0]. */
  regex: RegExp;
}

/**
 * Known provider credential formats. These are high-signal: a match is almost
 * certainly a real secret, so they are reported as errors. They do not require
 * the value to be quoted, so they catch keys pasted bare into a prompt.
 */
export const PROVIDER_RULES: SecretRule[] = [
  {
    id: "aws-access-key-id",
    label: "AWS Access Key ID",
    severity: "error",
    regex: /\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16})\b/g,
  },
  {
    id: "github-token",
    label: "GitHub token",
    severity: "error",
    regex: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b/g,
  },
  {
    id: "github-fine-grained-token",
    label: "GitHub fine-grained token",
    severity: "error",
    regex: /\b(github_pat_[A-Za-z0-9_]{22,})\b/g,
  },
  {
    id: "gitlab-token",
    label: "GitLab personal access token",
    severity: "error",
    regex: /\b(glpat-[A-Za-z0-9_-]{20})\b/g,
  },
  {
    id: "anthropic-key",
    label: "Anthropic API key",
    severity: "error",
    regex: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/g,
  },
  {
    id: "openai-key",
    label: "OpenAI API key",
    severity: "error",
    regex: /\b(sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,})\b/g,
  },
  {
    id: "stripe-secret-key",
    label: "Stripe secret key",
    severity: "error",
    regex: /\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b/g,
  },
  {
    id: "google-api-key",
    label: "Google API key",
    severity: "error",
    regex: /\b(AIza[A-Za-z0-9_-]{35})\b/g,
  },
  {
    id: "slack-token",
    label: "Slack token",
    severity: "error",
    regex: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g,
  },
  {
    id: "slack-webhook",
    label: "Slack incoming webhook URL",
    severity: "error",
    regex: /(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+)/g,
  },
  {
    id: "sendgrid-key",
    label: "SendGrid API key",
    severity: "error",
    regex: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,
  },
  {
    id: "twilio-api-key",
    label: "Twilio API key SID",
    severity: "error",
    regex: /\b(SK[0-9a-fA-F]{32})\b/g,
  },
  {
    id: "npm-token",
    label: "npm access token",
    severity: "error",
    regex: /\b(npm_[A-Za-z0-9]{36})\b/g,
  },
  {
    id: "jwt",
    label: "JSON Web Token (JWT)",
    severity: "warning",
    regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
  },
  {
    id: "private-key-block",
    label: "Private key block",
    severity: "error",
    regex: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)/g,
  },
  {
    id: "google-oauth-secret",
    label: "Google OAuth client secret",
    severity: "error",
    regex: /\b(GOCSPX-[A-Za-z0-9_-]{20,})\b/g,
  },
  {
    id: "azure-devops-pat",
    label: "Azure DevOps PAT",
    severity: "error",
    regex: /\b([A-Za-z0-9]{52}JQQJ99[A-Za-z0-9]{20,})\b/g,
  },
  {
    id: "digitalocean-token",
    label: "DigitalOcean token",
    severity: "error",
    regex: /\b(dop_v1_[a-f0-9]{64})\b/g,
  },
  {
    id: "openvsx-token",
    label: "Open VSX token",
    severity: "error",
    regex: /\b(ovsxat_[A-Za-z0-9-]{20,})\b/g,
  },
];

/**
 * Generic "assignment to a secret-looking variable" pattern. The secret keyword
 * may appear anywhere inside a larger identifier, so compound/camelCase names
 * like `snowflakeSecret`, `dbPassword`, `myApiKey`, `userAuthToken` are caught.
 *
 * Captures: group 1 = the key/variable name, group 2 = the quoted value.
 */
export const GENERIC_ASSIGNMENT_REGEX =
  /(?:^|[^A-Za-z0-9_$])([A-Za-z0-9_$]*(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|pwd|passphrase|private[_-]?key|token|credential)[A-Za-z0-9_$]*)\s*[:=]\s*['"]([^'"\n]{4,})['"]/gi;

/**
 * Values that are obviously placeholders, not real secrets. Compared
 * case-insensitively against the captured value (trimmed).
 */
const PLACEHOLDER_VALUES = new Set<string>([
  "your_api_key",
  "your-api-key",
  "yourapikey",
  "your_api_key_here",
  "your_secret",
  "your_token",
  "your_password",
  "api_key",
  "apikey",
  "secret",
  "token",
  "password",
  "changeme",
  "change_me",
  "example",
  "test",
  "todo",
  "tbd",
  "none",
  "null",
  "undefined",
  "xxx",
  "xxxx",
  "xxxxxxxx",
  "placeholder",
  "redacted",
  "dummy",
  "sample",
  "foo",
  "bar",
  "foobar",
]);

/**
 * Returns true if the value looks like a placeholder / non-secret and should be
 * ignored even if it matched a generic assignment.
 */
export function isPlaceholderValue(rawValue: string): boolean {
  const value = rawValue.trim();

  if (value.length === 0) {
    return true;
  }

  const lower = value.toLowerCase();

  if (PLACEHOLDER_VALUES.has(lower)) {
    return true;
  }

  // Wrapped in angle brackets like <your-key> or templated like ${VAR}, {{VAR}}.
  if (
    /^[<{[(]/.test(value) ||
    value.includes("${") ||
    value.includes("{{") ||
    value.includes("%(")
  ) {
    return true;
  }

  // Environment-variable references rather than literal secrets.
  if (/process\.env|os\.environ|os\.getenv|getenv|ENV\[/.test(value)) {
    return true;
  }

  // All-same-character masks (e.g. "********", "xxxxxxxx").
  if (/^(.)\1{4,}$/.test(value)) {
    return true;
  }

  // Mostly placeholder-ish words.
  if (/^(your|my|the|some|insert|put|add|enter)[ _-]/i.test(lower)) {
    return true;
  }

  // Obvious example domains / urls only.
  if (/^https?:\/\/(localhost|example\.(com|org|net)|127\.0\.0\.1)/.test(lower)) {
    return true;
  }

  return false;
}
