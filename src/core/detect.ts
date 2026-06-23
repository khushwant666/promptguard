/**
 * vscode-free secret detection core.
 *
 * `detectSecrets(text)` scans an arbitrary string (a prompt, a file, a clipboard
 * payload) and returns structured findings. This is the shared engine behind the
 * PromptGuard hook; it mirrors SecretGuard's editor scanner so detection stays
 * consistent across the suite.
 */

import {
  GENERIC_ASSIGNMENT_REGEX,
  PROVIDER_RULES,
  isPlaceholderValue,
} from "./patterns";

export type FindingKind = "provider" | "name" | "value";

export interface Finding {
  /** Start offset of the secret value within the scanned text. */
  start: number;
  /** End offset (exclusive). */
  end: number;
  /** Human-readable label, e.g. "AWS Access Key ID". */
  label: string;
  /** The raw matched value (callers should mask before displaying). */
  value: string;
  kind: FindingKind;
  severity: "error" | "warning";
}

export interface DetectOptions {
  /**
   * Also flag values assigned to secret-looking names (apiKey, password, ...).
   * Noisier on natural-language prompts, so it is off by default.
   */
  aggressiveNames?: boolean;
  /**
   * Flag string values that look like a secret by shape/entropy regardless of
   * surrounding name. On by default.
   */
  valueScan?: boolean;
}

/** Matches any single/double/back-quoted string literal (content in group 2). */
const STRING_LITERAL_REGEX = /(['"`])((?:\\.|(?!\1)[^\\\r\n])*)\1/g;

/** Whitespace-delimited tokens (for bare keys pasted into prose). */
const BARE_TOKEN_REGEX = /\S+/g;

/** Shannon entropy in bits per character. Random/encoded secrets score high. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) {
    return 0;
  }
  const counts = new Map<string, number>();
  for (const ch of value) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Truncate a secret so callers never echo the whole thing back. */
export function maskSecret(secret: string): string {
  const trimmed = secret.trim();
  if (trimmed.length <= 8) {
    return `${trimmed[0] ?? ""}***`;
  }
  return `${trimmed.slice(0, 4)}…${trimmed.slice(-2)}`;
}

/** Line text before `offset` (used to detect import/module-specifier context). */
function lineBefore(text: string, offset: number): string {
  const lineStart = text.lastIndexOf("\n", Math.max(0, offset - 1)) + 1;
  return text.slice(lineStart, offset);
}

/**
 * True when the value at `valueOffset` is a module specifier — the text right
 * before it is import/require/from/include. Those paths are never secrets.
 */
function isModuleSpecifierContext(text: string, valueOffset: number): boolean {
  // valueOffset points just inside the opening quote; drop that quote char.
  const before = lineBefore(text, Math.max(0, valueOffset - 1));
  return /(?:\bfrom|\bimport|\brequire|\binclude|@import)\s*\(?\s*$/.test(before);
}

/**
 * Heuristic: does this raw value *look like* a secret/key/token on its own?
 * Aggressive by design — random, mixed-character, high-entropy strings flag.
 * Obvious non-secrets (placeholders, URLs, emails, paths, packages, UUIDs,
 * plain words) are excluded.
 */
export function looksLikeSecretValue(rawValue: string): boolean {
  const v = rawValue.trim();

  if (v.length < 10) {
    return false;
  }
  if (/\s/.test(v)) {
    return false; // secrets don't contain whitespace; sentences do
  }
  if (isPlaceholderValue(v)) {
    return false;
  }
  if (/^https?:\/\//i.test(v)) {
    return false; // URLs (real secrets in URLs are caught by provider rules)
  }
  if (/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(v)) {
    return false; // email address
  }
  if (/^[./~\\]/.test(v)) {
    return false; // file path
  }
  if (/\.(png|jpe?g|gif|svg|webp|ico|css|scss|less|js|mjs|cjs|ts|tsx|jsx|json|html|md|txt|ya?ml|xml|py|java|go|rb|php|sql|sh)$/i.test(v)) {
    return false; // file name
  }
  // Module specifiers / package names / import paths (e.g. @scope/pkg, lodash/fp,
  // ./utils/helper, com.example.app): lowercase, slash/dot/at separated words.
  if (
    (v.includes("/") || v.startsWith("@") || v.startsWith(".") || v.includes(".")) &&
    /^@?\.{0,2}\/?[a-z0-9]+(?:[._/-][a-z0-9]+)*$/.test(v)
  ) {
    return false;
  }
  // UUIDs / GUIDs are identifiers, not secrets.
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) {
    return false;
  }

  const hasLower = /[a-z]/.test(v);
  const hasUpper = /[A-Z]/.test(v);
  const hasDigit = /[0-9]/.test(v);
  const hasSpecial = /[^A-Za-z0-9]/.test(v);
  const classes = [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length;
  const entropy = shannonEntropy(v);

  // Long, fairly random strings (typical tokens/keys).
  if (v.length >= 16 && entropy >= 3.3) {
    return true;
  }
  // Shorter but clearly mixed (upper+lower+digit / special) and random-ish.
  if (v.length >= 10 && classes >= 3 && entropy >= 3.3) {
    return true;
  }
  return false;
}

/**
 * Scan arbitrary text for secrets. Pure and synchronous.
 */
export function detectSecrets(text: string, options: DetectOptions = {}): Finding[] {
  const valueScan = options.valueScan !== false;
  const findings: Finding[] = [];
  const seen = new Set<number>();

  const add = (
    start: number,
    value: string,
    label: string,
    kind: FindingKind,
    severity: "error" | "warning"
  ): void => {
    if (value.length === 0 || seen.has(start)) {
      return;
    }
    seen.add(start);
    findings.push({ start, end: start + value.length, label, value, kind, severity });
  };

  // 1) High-confidence provider patterns (quoted or bare).
  for (const rule of PROVIDER_RULES) {
    rule.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = rule.regex.exec(text)) !== null) {
      const value = match[1] ?? match[0];
      const valueOffset = match.index + match[0].indexOf(value);
      add(valueOffset, value, rule.label, "provider", rule.severity);
      if (match.index === rule.regex.lastIndex) {
        rule.regex.lastIndex++;
      }
    }
  }

  // 2) Name-based assignments (opt-in; noisy in natural-language prompts).
  if (options.aggressiveNames) {
    GENERIC_ASSIGNMENT_REGEX.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = GENERIC_ASSIGNMENT_REGEX.exec(text)) !== null) {
      const keyName = match[1];
      const value = match[2];
      const valueOffset = match.index + match[0].lastIndexOf(value);
      if (isPlaceholderValue(value)) {
        continue;
      }
      add(valueOffset, value, `secret assigned to "${keyName}"`, "name", "warning");
    }
  }

  // 3) Value-based detection by shape/entropy.
  if (valueScan) {
    // 3a) Quoted string literals (code-like content).
    STRING_LITERAL_REGEX.lastIndex = 0;
    let lit: RegExpExecArray | null;
    while ((lit = STRING_LITERAL_REGEX.exec(text)) !== null) {
      const value = lit[2];
      const valueOffset = lit.index + 1; // skip opening quote
      if (lit.index === STRING_LITERAL_REGEX.lastIndex) {
        STRING_LITERAL_REGEX.lastIndex++;
      }
      if (isModuleSpecifierContext(text, valueOffset)) {
        continue;
      }
      if (looksLikeSecretValue(value)) {
        add(valueOffset, value, "high-entropy secret/key", "value", "warning");
      }
    }

    // 3b) Bare tokens (keys pasted into prose without quotes).
    BARE_TOKEN_REGEX.lastIndex = 0;
    let tok: RegExpExecArray | null;
    while ((tok = BARE_TOKEN_REGEX.exec(text)) !== null) {
      const rawToken = tok[0];
      // Strip surrounding punctuation/quotes but keep key-safe chars.
      const lead = (rawToken.match(/^[^A-Za-z0-9_+/=.@-]*/) ?? [""])[0].length;
      const stripped = rawToken
        .slice(lead)
        .replace(/[^A-Za-z0-9_+/=.@-]*$/, "");
      const offset = tok.index + lead;
      if (isModuleSpecifierContext(text, offset)) {
        continue;
      }
      if (looksLikeSecretValue(stripped)) {
        add(offset, stripped, "high-entropy secret/key", "value", "warning");
      }
    }
  }

  return findings.sort((a, b) => a.start - b.start);
}
