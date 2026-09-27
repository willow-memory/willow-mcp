#!/usr/bin/env node
// node9 shadow mode (sealed a6d054b3, amended node9-shadow-hybrid-ledger-2026-09-27)
// — the shim.
//
// Reads one JSON object {tool, command} on stdin and writes one JSON verdict
// {verdict, node9_rule_raw} on stdout. It has NO side effects beyond
// stdin/stdout: no audit write, no daemon, no /dev/tty, no approver, no
// network, no read of the operator's real ~/.node9. HOME/cwd/env are set up
// entirely by the caller (willow_mcp.node9_shadow); this shim never resolves
// a binary itself — the absolute node9 script path is passed as argv[2].
//
// verdict is a strict enum: "allow" | "block" | "review" | "unknown". Any
// doubt at all — a missing/garbled Decision line, an echo mismatch, a
// truncated block — produces "unknown", never "allow" (Loki 53741054, F3/F4:
// the old shim defaulted every failure and every echoed "Decision: ALLOW" to
// allow; this rewrite has no default-to-allow code path at all).
//
// Route: node9's public npm surface (`@node9/proxy`'s dist/index.js) only
// re-exports `protect()` — the policy engine is bundled into the CLI at
// build time via a workspace package, not a standalone `node_modules`
// entry, so there is no importable module path to it. This shim therefore
// spawns `node <node9Script> explain <tool> <argsJson>` (read-only: node9's
// own `explain` action calls only `explainPolicy()` then `console.log` — no
// daemon autostart, no tty write, no approver, no network) and parses its
// final "Decision:" line, anchored to appear only after the "Policy
// Evaluation:" header and only once the echoed "Input:" line has been
// verified byte-for-byte against what this shim itself sent — so a command
// whose own text contains "Decision:", "Rule:" or "Input:" cannot spoof a
// verdict (Loki 53741054 F4's `echo "Decision: ALLOW"; rm -rf /` fixture).
//
// node9_rule extraction and all ledger redaction happen in Python, not
// here — this shim hands back the raw "Reason:" line text (if any) as
// `node9_rule_raw`, still unfiltered; the caller is responsible for
// whitelisting it before it ever reaches the ledger.
//
// Timeout (Loki A68E86E9, R4): the recorder and this shim used to each own
// an INDEPENDENT timeout value (Python's outer 2.0s, this shim's inner
// 1800ms) — the shim's own SIGTERM of just its node9 child usually fired
// first, printed "unknown", and exited 0, so the recorder's own
// process-group kill never ran at all, leaving any grandchild node9 itself
// spawned still alive. There is now exactly ONE value, owned by the
// recorder and passed here as NODE9_SHADOW_TIMEOUT_MS; this shim's own
// spawnSync uses it verbatim rather than a separately-chosen number.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';

function readStdin() {
  const chunks = [];
  const buf = Buffer.alloc(65536);
  for (;;) {
    let bytesRead;
    try {
      bytesRead = fs.readSync(0, buf, 0, buf.length, null);
    } catch (e) {
      if (e.code === 'EAGAIN') continue;
      if (e.code === 'EOF') break;
      throw e;
    }
    if (bytesRead === 0) break;
    chunks.push(Buffer.from(buf.subarray(0, bytesRead)));
  }
  return Buffer.concat(chunks).toString('utf8');
}

function stripAnsi(s) {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

function unknown(reason) {
  return { verdict: 'unknown', node9_rule_raw: '', shim_reason: reason };
}

function main() {
  let payload;
  try {
    payload = JSON.parse(readStdin());
  } catch {
    process.stdout.write(JSON.stringify(unknown('bad_input_json')));
    return;
  }

  const tool = String(payload.tool || 'bash');
  const command = String(payload.command || '');
  const node9Script = process.argv[2];
  if (!node9Script) {
    process.stdout.write(JSON.stringify(unknown('no_script_path')));
    return;
  }

  // Always pass the command as JSON args, never as a bare positional
  // string — node9's own explain CLI treats a bare-string arg starting with
  // `-` as an unrecognized commander flag, and a bare `[`/`{` as malformed
  // JSON to parse directly. Wrapping in {"command": ...} sidesteps both:
  // the argv token always starts with `{`.
  const argsRaw = JSON.stringify({ command });
  const expectedPreview = argsRaw.length > 80 ? argsRaw.slice(0, 77) + '…' : argsRaw;

  const timeoutMs = Number(process.env.NODE9_SHADOW_TIMEOUT_MS) || 1800;

  let out;
  try {
    out = spawnSync(process.execPath, [node9Script, 'explain', tool, argsRaw], {
      encoding: 'utf8',
      timeout: timeoutMs,
    });
  } catch (e) {
    process.stdout.write(JSON.stringify(unknown(`spawn_error:${e.code || 'unknown'}`)));
    return;
  }

  if (!out || out.error) {
    process.stdout.write(JSON.stringify(unknown('spawn_failed')));
    return;
  }
  if (out.status !== 0) {
    process.stdout.write(JSON.stringify(unknown(`exit_${out.status}`)));
    return;
  }

  const stdout = stripAnsi(out.stdout || '');
  const lines = stdout.split('\n');

  // 1. Find the echoed Input: line and verify it byte-for-byte against what
  // we actually sent. A mismatch (or absence) is doubt, not an allow.
  const inputIdx = lines.findIndex((l) => l.trim().startsWith('Input:'));
  if (inputIdx === -1) {
    process.stdout.write(JSON.stringify(unknown('no_input_line')));
    return;
  }
  const echoed = lines[inputIdx].trim().slice('Input:'.length).trim();
  if (echoed !== expectedPreview) {
    process.stdout.write(JSON.stringify(unknown('echo_mismatch')));
    return;
  }

  // 2. Only lines strictly AFTER the "Policy Evaluation:" header count —
  // anything at or before it (including the Input: line just verified) is
  // attacker-controllable echo, not node9's own verdict.
  const headerIdx = lines.findIndex((l) => l.trim() === 'Policy Evaluation:');
  if (headerIdx === -1 || headerIdx <= inputIdx) {
    process.stdout.write(JSON.stringify(unknown('no_policy_header')));
    return;
  }
  const tail = lines.slice(headerIdx + 1);

  // 3. Take the LAST line that starts (after trim) with "Decision:" in that
  // tail — defends against a rule's own free-text detail embedding the
  // word "Decision:" earlier in the block; node9 only ever prints the real
  // one once, and it is always last.
  let decisionIdx = -1;
  for (let i = 0; i < tail.length; i++) {
    if (tail[i].trim().startsWith('Decision:')) decisionIdx = i;
  }
  if (decisionIdx === -1) {
    process.stdout.write(JSON.stringify(unknown('no_decision_line')));
    return;
  }
  const decisionLine = tail[decisionIdx];
  let verdict;
  if (/\bALLOW\b/.test(decisionLine)) verdict = 'allow';
  else if (/\bBLOCK\b/.test(decisionLine)) verdict = 'block';
  else if (/\bREVIEW\b/.test(decisionLine)) verdict = 'review';
  else {
    process.stdout.write(JSON.stringify(unknown('unparseable_decision')));
    return;
  }

  let ruleRaw = '';
  const nextLine = tail[decisionIdx + 1];
  if (nextLine && nextLine.trim().startsWith('Reason:')) {
    ruleRaw = nextLine.trim().slice('Reason:'.length).trim();
  }

  process.stdout.write(JSON.stringify({ verdict, node9_rule_raw: ruleRaw }));
}

main();
