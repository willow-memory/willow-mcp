"""Steps `deploy/manifest-grant/install.sh` runs as root or as the trust owner.

They ship inside the willow-mcp wheel so that, on the box, they execute from
the root-owned, preflight-checked trust-owner venv (`/opt/willow-operator/venv`)
and never from the operator-writable checkout. Run them as
`python -I -m willow_mcp.install_steps.<name>`; see INSTALL.md.
"""
