/**
 * PromptGuard test harness (no framework, zero deps).
 *
 * Run with: npm test  (which builds first, then runs this)
 *
 * Covers:
 *   - detectSecrets() unit cases (provider, value, name-based, false positives)
 *   - end-to-end `scan` over piped Cursor / Claude hook JSON (block vs allow)
 */

const path = require("path");
const { spawnSync } = require("child_process");
const { detectSecrets } = require("../out/core/detect.js");

const CLI = path.join(__dirname, "..", "out", "cli.js");

let passed = 0;
let failed = 0;

function check(name, cond) {
  if (cond) {
    passed++;
    console.log(`  ok   ${name}`);
  } else {
    failed++;
    console.error(`  FAIL ${name}`);
  }
}

// --- Unit: detectSecrets ----------------------------------------------------

console.log("detectSecrets()");

check(
  "flags AWS access key id",
  detectSecrets("deploy with AKIAIOSFODNN7EXAMPLE now").some((f) => f.kind === "provider")
);

check(
  "flags OpenAI key",
  detectSecrets("key: sk-proj-abcdefghijklmnopqrstuvwx").some((f) => f.kind === "provider")
);

check(
  "flags Anthropic key (not mislabeled as OpenAI)",
  detectSecrets("sk-ant-abcdefghijklmnopqrstuvwxyz").some(
    (f) => f.label === "Anthropic API key"
  )
);

check(
  "flags bare high-entropy token in prose",
  detectSecrets("here is the token Zx9Kq2Lp8Wm3Rn7Vt4Yb run it").some(
    (f) => f.kind === "value"
  )
);

check(
  "clean prose produces no findings",
  detectSecrets("Please refactor this function so it runs faster and add tests.").length === 0
);

check(
  "import path is not flagged",
  detectSecrets('import { Component } from "@angular/core";').length === 0
);

check(
  "UUID is not flagged",
  detectSecrets("id is 550e8400-e29b-41d4-a716-446655440000 here").length === 0
);

check(
  "name-based assignment is OFF by default",
  detectSecrets('password = "abcabcabcabc"').length === 0
);

check(
  "name-based assignment is caught with aggressiveNames",
  detectSecrets('password = "abcabcabcabc"', { aggressiveNames: true }).some(
    (f) => f.kind === "name"
  )
);

check(
  "masked value never contains the full secret",
  detectSecrets("AKIAIOSFODNN7EXAMPLE").every(
    (f) => !require("../out/core/detect.js").maskSecret(f.value).includes(f.value)
  )
);

// --- E2E: scan over hook JSON ----------------------------------------------

function runScan(flag, payloadObj) {
  const res = spawnSync(process.execPath, [CLI, "scan", flag], {
    input: JSON.stringify(payloadObj),
    encoding: "utf8",
  });
  return res;
}

console.log("scan (Cursor beforeSubmitPrompt)");

{
  const res = runScan("--cursor", { prompt: "ship it with AKIAIOSFODNN7EXAMPLE" });
  check("blocks: exit code 2", res.status === 2);
  check("blocks: stdout has continue:false", /"continue":\s*false/.test(res.stdout));
  check("blocks: user_message present", /user_message/.test(res.stdout));
}

{
  const res = runScan("--cursor", { prompt: "just clean up this file please" });
  check("allows: exit code 0", res.status === 0);
  check("allows: stdout has continue:true", /"continue":\s*true/.test(res.stdout));
}

console.log("scan (Claude UserPromptSubmit)");

{
  const res = runScan("--claude", {
    hook_event_name: "UserPromptSubmit",
    prompt: "use sk-ant-abcdefghijklmnopqrstuvwxyz and run",
  });
  check("blocks: exit code 2", res.status === 2);
  check("blocks: reason on stderr", /PromptGuard blocked/.test(res.stderr));
  check("blocks: stdout stays empty", res.stdout.trim() === "");
}

{
  const res = runScan("--claude", {
    hook_event_name: "UserPromptSubmit",
    prompt: "explain how promises work in javascript",
  });
  check("allows: exit code 0", res.status === 0);
}

// --- Summary ----------------------------------------------------------------

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
