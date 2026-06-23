# PromptGuard

A secret firewall for your AI prompts.

When you're deep in a coding session, it's easy to paste a real API key, token, or
`.env` value straight into a Cursor or Claude Code prompt — "here's my key, go run
this for me." The moment you hit send, that secret leaves your machine and lands in
a chat history you don't control.

PromptGuard sits in front of that send button. It scans every prompt locally,
and if it spots something that looks like a secret, it blocks the prompt before it
ever hits the network. The secret never leaves your laptop.

## How it works

PromptGuard isn't an extension — extensions can't read the chat box. Instead it
plugs into the prompt hooks both tools already expose:

- **Cursor** — `beforeSubmitPrompt` in `~/.cursor/hooks.json`
- **Claude Code** — `UserPromptSubmit` in `~/.claude/settings.json`

Each time you submit a prompt, the tool pipes it to PromptGuard. If it's clean,
the prompt goes through. If it contains a secret, PromptGuard blocks it and shows
you a message telling you what it caught.

## Install

You'll need Node.js 18+ on your PATH.

```bash
npx @khushwant.r/promptguard install
```

That wires up the hook for both Cursor and Claude Code. Restart Cursor (or reload
Claude Code) so it picks up the new hook.

Want just one tool, or a stricter setup?

```bash
npx @khushwant.r/promptguard install --cursor          # Cursor only
npx @khushwant.r/promptguard install --claude          # Claude Code only
npx @khushwant.r/promptguard install --project         # this repo only (.cursor / .claude)
npx @khushwant.r/promptguard install --strict          # fail closed: if the hook breaks, block
npx @khushwant.r/promptguard install --aggressive      # also flag values assigned to secret-ish names
```

Remove it just as easily:

```bash
npx @khushwant.r/promptguard uninstall
```

## Try it

Send a prompt with a fake key in it, e.g.:

```
run this for me with AKIAIOSFODNN7EXAMPLE
```

PromptGuard will stop the submission and tell you a secret was detected. Delete the
key and send again — it goes straight through.

## What it catches

- **Known provider credentials** — AWS keys, OpenAI / Anthropic keys, GitHub &
  GitLab tokens, Stripe, Google API keys & OAuth secrets, Slack tokens & webhooks,
  SendGrid, Twilio, npm tokens, JWTs, private key blocks, Azure DevOps PATs,
  DigitalOcean & Open VSX tokens, and more.
- **Anything that looks like a key** — long, random, high-entropy strings, even if
  they don't match a known provider format.
- **Secret-ish assignments** (with `--aggressive`) — values handed to names like
  `apiKey`, `password`, `token`, `clientSecret`, etc.

It deliberately ignores obvious non-secrets — placeholders (`your_api_key`),
import paths (`@angular/core`), UUIDs, URLs, emails, and file paths — so it stays
out of your way on normal prompts.

## Safety & privacy

- Everything runs **locally**. PromptGuard makes no network calls and stores
  nothing. Your prompts and secrets stay on your machine.
- By default it **fails open** — if the hook ever errors, your prompt still goes
  through so you're never stuck. Use `--strict` to fail closed instead (block on
  error), which is the safer choice for security-critical setups.
- When it does block, it only ever shows a **masked preview** of the secret
  (`AKIA…LE`), never the whole thing.

## Commands

| Command | What it does |
| --- | --- |
| `promptguard scan` | Reads a hook payload on stdin and allows/blocks it. Used by the hook. |
| `promptguard install` | Registers the prompt hook in Cursor and/or Claude Code. |
| `promptguard uninstall` | Removes only PromptGuard's hook entries. |
| `promptguard --version` | Prints the version. |

## Support

If PromptGuard stopped a secret from leaking into a chat log, consider giving it a
⭐ on GitHub — it genuinely helps.

Built by [Khushwant R.](https://khushwant.dev)
