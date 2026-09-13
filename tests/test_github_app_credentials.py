"""github_app_credentials — vault load + permission gate (no live GitHub in CI)."""
from __future__ import annotations

from willow_mcp import github_app_credentials as gac


def test_contents_perm_allows_push():
    assert gac.contents_perm_allows_push({"contents": "write"})
    assert gac.contents_perm_allows_push({"contents": "admin"})
    assert not gac.contents_perm_allows_push({"contents": "read"})
    assert not gac.contents_perm_allows_push({})
    assert not gac.contents_perm_allows_push(None)


def test_load_app_credentials_missing_box(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_VAULT_BOX", str(tmp_path / "nope"))
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)
    out = gac.load_app_credentials()
    assert not out["ok"]


def test_load_app_credentials_from_vault_files(tmp_path, monkeypatch):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "willow-bot.env").write_text("GITHUB_APP_ID=4001890\n")
    (secrets / "willow-bot.pem").write_text(
        "-----BEGIN PRIVATE KEY-----\nQQ==\n-----END PRIVATE KEY-----\n"
    )
    monkeypatch.setenv("WILLOW_VAULT_BOX", str(tmp_path))
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)
    out = gac.load_app_credentials()
    assert out["ok"]
    assert out["app_id"] == "4001890"
    assert "PRIVATE KEY" in out["pem"]


def test_mint_rejects_bad_repo_shape(monkeypatch):
    monkeypatch.setattr(
        gac, "load_app_credentials",
        lambda: {"ok": True, "app_id": "1", "pem": "x"},
    )
    out = gac.mint_installation_token("not-a-repo")
    assert not out["ok"]
    assert "org/name" in out["reason"]
