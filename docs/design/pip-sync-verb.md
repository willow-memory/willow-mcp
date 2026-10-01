# `pip_sync_execute` — editable install into a vault venv (broker, not Kart)

**Status:** built locally with this bite. Receipt-only; no syscall row.

## Why

Kart mounts product `.venv` and `$WILLOW_HOME/venvs/*` **read-only**
(`kart-sandbox.template.json` `venvs_are_read_only`). A Kart `# allow_net`
`pip install` into those trees always hits `Errno 30`. willow-bot's
`install_receipt` only ran `pip install -e .` when checkout `.venv/bin/pip`
existed — fleet installs skipped. Idea **A.2** in willow-bot `docs/ideas.md`.

Sibling of row 25 `package.upgrade` (tagged, offline wheel). This verb is
**editable + public index** under a hard allowlist.

## Not willow-gate HTTP

[willow-gate on PyPI](https://pypi.org/project/willow-gate/) (v0.1.0) is the
check-in / trust / custody library — not an egress proxy. Atom **27E5D077**
puts willow-gate between the **box** and the open world for bot-owned
`install_package` / lane B (still deferred in `willow-bot-box-spec.md`
§3.3 / §10.3). Broker maintenance verbs (`git_pull_execute`,
`pip_sync_execute`, offline `package_upgrade_execute`) run in the broker
process and leave FRANK ink; they are not Kart net and not box lane B.

Gap **c80704796f2b** (name gate as the box edge in box-spec + gate README)
waits on sealing drafts 9847ada1 / d84fa045 — out of this bite.

Contrast: `model_pull_execute` requires a live lease + envelope because the
Ollama daemon does registry egress. `pip_sync` follows **git_pull**
(receipt-only allowlist), not model.pull.

```text
Kart seat tasks  --RO venvs-->  broker maintenance  -->  world (index / git)
Box run_in_venv  --deferred-->  willow-gate edge    -->  world
```

## Shape

- Tool: `pip_sync_execute(app_id, checkout, venv="", extras=None)`
- Target: `$WILLOW_HOME/venvs/<venv>` only
- Spec: `bin/python -m pip install --upgrade -e '<checkout>[extras]'`
- Allowlist: bundle `pip_sync_allowlist.json`, overridable at
  `$WILLOW_HOME/constitutional/pip_sync_allowlist.json`
- Guards: under github root; allowlisted remote; clean tracked tree;
  default branch; venv writable by this uid (`EPERM`, never escalate)
- Ink: FRANK `pip_sync` / `pip_sync_failed`

## ACL

Own gate name. In `steward_sweep`, `orchestrator`, and `full_access`.
Not on `envelope_apply`.
