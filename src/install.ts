/**
 * `promptguard install` / `uninstall`.
 *
 * Wires the scan command into the supported prompt-interception hooks:
 *   - Cursor: `beforeSubmitPrompt` in hooks.json (matcher "UserPromptSubmit").
 *   - Claude Code: `UserPromptSubmit` in settings.json.
 *
 * Configs are merged, not overwritten — existing user hooks are preserved and
 * PromptGuard's entries are identified by a stable marker so uninstall is clean.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";

/** Stable marker embedded in every command we write, used to find/remove ours. */
const MARKER = "promptguard";

type Scope = "user" | "project";

interface InstallArgs {
  cursor: boolean;
  claude: boolean;
  scope: Scope;
  strict: boolean;
  aggressive: boolean;
}

function parseInstallArgs(args: string[]): InstallArgs {
  const onlyCursor = args.includes("--cursor");
  const onlyClaude = args.includes("--claude");
  // Default: both tools unless one is explicitly selected.
  const cursor = onlyCursor || !onlyClaude;
  const claude = onlyClaude || !onlyCursor;
  const scope: Scope = args.includes("--project") ? "project" : "user";
  return {
    cursor,
    claude,
    scope,
    strict: args.includes("--strict"),
    aggressive: args.includes("--aggressive"),
  };
}

/** Absolute path to this installed CLI's entry, with forward slashes for JSON. */
function cliEntryPath(): string {
  // __dirname is .../out at runtime; cli.js sits beside this file.
  return path.join(__dirname, "cli.js").replace(/\\/g, "/");
}

/** The shell command a hook should run. `node <abs cli.js> scan ...`. */
function hookCommand(flag: "--cursor" | "--claude", aggressive: boolean): string {
  const parts = [`node "${cliEntryPath()}" scan ${flag}`];
  if (aggressive) {
    parts.push("--aggressive");
  }
  return parts.join(" ");
}

function readJson(file: string): any {
  try {
    const text = fs.readFileSync(file, "utf8").trim();
    return text.length ? JSON.parse(text) : {};
  } catch {
    return {};
  }
}

function writeJson(file: string, data: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n", "utf8");
}

function isOurCommand(cmd: unknown): boolean {
  return typeof cmd === "string" && cmd.includes(MARKER);
}

// --- Cursor -----------------------------------------------------------------

function cursorConfigPath(scope: Scope): string {
  return scope === "project"
    ? path.join(process.cwd(), ".cursor", "hooks.json")
    : path.join(os.homedir(), ".cursor", "hooks.json");
}

function installCursor(args: InstallArgs): string {
  const file = cursorConfigPath(args.scope);
  const config = readJson(file);
  if (typeof config.version !== "number") {
    config.version = 1;
  }
  config.hooks = config.hooks ?? {};
  const list: any[] = Array.isArray(config.hooks.beforeSubmitPrompt)
    ? config.hooks.beforeSubmitPrompt
    : [];

  const cleaned = list.filter((entry) => !isOurCommand(entry?.command));
  const entry: Record<string, unknown> = {
    command: hookCommand("--cursor", args.aggressive),
  };
  if (args.strict) {
    entry.failClosed = true;
  }
  cleaned.push(entry);
  config.hooks.beforeSubmitPrompt = cleaned;

  writeJson(file, config);
  return file;
}

// --- Claude Code ------------------------------------------------------------

function claudeConfigPath(scope: Scope): string {
  return scope === "project"
    ? path.join(process.cwd(), ".claude", "settings.json")
    : path.join(os.homedir(), ".claude", "settings.json");
}

function installClaude(args: InstallArgs): string {
  const file = claudeConfigPath(args.scope);
  const config = readJson(file);
  config.hooks = config.hooks ?? {};

  const groups: any[] = Array.isArray(config.hooks.UserPromptSubmit)
    ? config.hooks.UserPromptSubmit
    : [];

  // Drop any prior PromptGuard entries (whole group if it only held ours).
  const cleaned = groups
    .map((group) => {
      if (!group || !Array.isArray(group.hooks)) {
        return group;
      }
      return {
        ...group,
        hooks: group.hooks.filter((h: any) => !isOurCommand(h?.command)),
      };
    })
    .filter((group) => !group || !Array.isArray(group.hooks) || group.hooks.length > 0);

  cleaned.push({
    hooks: [
      {
        type: "command",
        command: hookCommand("--claude", args.aggressive),
      },
    ],
  });
  config.hooks.UserPromptSubmit = cleaned;

  writeJson(file, config);
  return file;
}

// --- Public commands --------------------------------------------------------

export function runInstall(rawArgs: string[]): void {
  const args = parseInstallArgs(rawArgs);
  const written: string[] = [];

  if (args.cursor) {
    written.push(installCursor(args));
  }
  if (args.claude) {
    written.push(installClaude(args));
  }

  const out = [
    "PromptGuard installed.",
    "",
    ...written.map((f) => `  ✓ ${f}`),
    "",
    `Scope:  ${args.scope}`,
    `Mode:   ${args.strict ? "strict (fail closed)" : "fail open"}${
      args.aggressive ? " + aggressive name matching" : ""
    }`,
    "",
    "Restart Cursor (or reload Claude Code) so the new hook is picked up.",
    "Test it by sending a prompt containing a fake key, e.g.:",
    "  AKIAIOSFODNN7EXAMPLE",
    "",
  ].join("\n");
  process.stdout.write(out);
}

export function runUninstall(rawArgs: string[]): void {
  const args = parseInstallArgs(rawArgs);
  const touched: string[] = [];

  if (args.cursor) {
    const file = cursorConfigPath(args.scope);
    const config = readJson(file);
    if (config?.hooks?.beforeSubmitPrompt) {
      config.hooks.beforeSubmitPrompt = config.hooks.beforeSubmitPrompt.filter(
        (entry: any) => !isOurCommand(entry?.command)
      );
      if (config.hooks.beforeSubmitPrompt.length === 0) {
        delete config.hooks.beforeSubmitPrompt;
      }
      writeJson(file, config);
      touched.push(file);
    }
  }

  if (args.claude) {
    const file = claudeConfigPath(args.scope);
    const config = readJson(file);
    if (config?.hooks?.UserPromptSubmit) {
      config.hooks.UserPromptSubmit = config.hooks.UserPromptSubmit
        .map((group: any) =>
          group && Array.isArray(group.hooks)
            ? { ...group, hooks: group.hooks.filter((h: any) => !isOurCommand(h?.command)) }
            : group
        )
        .filter(
          (group: any) =>
            !group || !Array.isArray(group.hooks) || group.hooks.length > 0
        );
      if (config.hooks.UserPromptSubmit.length === 0) {
        delete config.hooks.UserPromptSubmit;
      }
      writeJson(file, config);
      touched.push(file);
    }
  }

  const out =
    touched.length > 0
      ? ["PromptGuard removed from:", "", ...touched.map((f) => `  ✓ ${f}`), ""].join("\n")
      : "Nothing to remove — PromptGuard was not installed in the selected scope.\n";
  process.stdout.write(out);
}
