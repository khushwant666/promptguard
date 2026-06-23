/**
 * `promptguard scan` — the hook entry point.
 *
 * Reads a hook payload as JSON on stdin (Cursor `beforeSubmitPrompt` or Claude
 * Code `UserPromptSubmit`), extracts the prompt text, runs the shared detection
 * core, and either allows the prompt (exit 0) or blocks it.
 *
 * Blocking conventions (verified against Cursor + Claude hook docs):
 *   - Cursor: print `{ "continue": false, "user_message": ... }` to stdout, exit 0.
 *   - Claude: print the reason to stderr, exit 2.
 *   - Exit code 2 also blocks in both tools, so we use it as a belt-and-braces
 *     fallback when emitting a block decision.
 */

import { detectSecrets, Finding, maskSecret } from "./core/detect";

type Target = "cursor" | "claude" | "generic";

interface ParsedArgs {
  target: Target;
  aggressive: boolean;
  text?: string;
}

function parseArgs(args: string[]): ParsedArgs {
  const target: Target = args.includes("--claude")
    ? "claude"
    : args.includes("--cursor")
      ? "cursor"
      : "generic";
  const aggressive = args.includes("--aggressive");

  let text: string | undefined;
  const textIdx = args.indexOf("--text");
  if (textIdx !== -1 && args[textIdx + 1] !== undefined) {
    text = args[textIdx + 1];
  }

  return { target, aggressive, text };
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) {
      resolve(""); // no piped input (e.g. run manually in a terminal)
      return;
    }
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
    });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", () => resolve(data));
  });
}

/** Pull the prompt text out of a hook payload, tolerating shape differences. */
function extractPrompt(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return "";
  }
  try {
    const data = JSON.parse(trimmed) as Record<string, unknown>;
    const candidates = [
      data.prompt,
      data.text,
      data.message,
      data.user_prompt,
      data.input,
      data.content,
    ];
    for (const candidate of candidates) {
      if (typeof candidate === "string" && candidate.length > 0) {
        return candidate;
      }
    }
    // Unknown JSON shape: scan the whole payload so we still catch secrets.
    return trimmed;
  } catch {
    // Not JSON (e.g. --text or a raw paste): scan as-is.
    return trimmed;
  }
}

function buildMessage(findings: Finding[]): string {
  const lines = findings.map((f) => `  • ${f.label} (${maskSecret(f.value)})`);
  const unique = [...new Set(lines)];
  return [
    "PromptGuard blocked this prompt — it looks like it contains a secret:",
    ...unique,
    "",
    "Your secret never left your machine. Remove it (or refer to it by an",
    "environment variable / name instead of pasting the value) and send again.",
  ].join("\n");
}

function emitAllow(target: Target): void {
  if (target === "cursor") {
    process.stdout.write(JSON.stringify({ continue: true }) + "\n");
  }
  // Claude / generic: silence + exit 0 means "allow".
}

function emitBlock(target: Target, findings: Finding[]): void {
  const message = buildMessage(findings);
  if (target === "cursor") {
    process.stdout.write(
      JSON.stringify({ continue: false, user_message: message }) + "\n"
    );
  } else {
    // Claude reads stderr on exit 2 and surfaces it to the user.
    process.stderr.write(message + "\n");
  }
}

export async function runScan(args: string[]): Promise<void> {
  const { target, aggressive, text } = parseArgs(args);

  const promptText = text !== undefined ? text : extractPrompt(await readStdin());

  if (promptText.length === 0) {
    emitAllow(target);
    process.exit(0);
  }

  const findings = detectSecrets(promptText, {
    aggressiveNames: aggressive,
    valueScan: true,
  });

  if (findings.length === 0) {
    emitAllow(target);
    process.exit(0);
  }

  emitBlock(target, findings);
  // Exit 2 blocks in both Cursor and Claude (Cursor also honors the JSON above).
  process.exit(2);
}
