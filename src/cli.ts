#!/usr/bin/env node
/**
 * PromptGuard CLI — a secret firewall for AI prompts.
 *
 * Commands:
 *   promptguard scan        Read a hook payload on stdin and allow/block it.
 *   promptguard install     Wire up the Cursor/Claude prompt hook.
 *   promptguard uninstall   Remove PromptGuard's hook entries.
 */

import { runScan } from "./scan";
import { runInstall, runUninstall } from "./install";

const HELP = `PromptGuard — secret firewall for AI prompts

Usage:
  promptguard scan [--cursor|--claude] [--aggressive] [--text "<prompt>"]
  promptguard install [--cursor] [--claude] [--user|--project] [--strict]
  promptguard uninstall [--cursor] [--claude] [--user|--project]
  promptguard --version

Commands:
  scan        Read a hook payload (JSON) on stdin, scan the prompt for secrets,
              and block submission (exit 2) if any are found. Used by the hook.
  install     Register the prompt hook in Cursor (~/.cursor/hooks.json) and/or
              Claude Code (~/.claude/settings.json). Installs both by default.
  uninstall   Remove only PromptGuard's hook entries.

Options:
  --cursor / --claude   Limit the action to one tool (default: both).
  --user / --project    Install to the home dir (default) or the current repo.
  --strict              Fail closed: if the hook errors, block the prompt.
  --aggressive          Also flag values assigned to secret-looking names.
`;

function getVersion(): string {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require("../package.json").version as string;
  } catch {
    return "0.0.0";
  }
}

async function main(): Promise<void> {
  const [, , cmd, ...args] = process.argv;

  switch (cmd) {
    case "scan":
      await runScan(args);
      return;
    case "install":
      runInstall(args);
      return;
    case "uninstall":
      runUninstall(args);
      return;
    case "-v":
    case "--version":
      process.stdout.write(getVersion() + "\n");
      return;
    case undefined:
    case "-h":
    case "--help":
    case "help":
      process.stdout.write(HELP);
      return;
    default:
      process.stderr.write(`Unknown command: ${cmd}\n\n${HELP}`);
      process.exit(1);
  }
}

main().catch((err) => {
  process.stderr.write(`promptguard: ${err?.message ?? err}\n`);
  // Non-2 exit => fail-open in the hook (unless failClosed is set).
  process.exit(1);
});
