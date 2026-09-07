# willow_mcp/vault.py — Fernet-encrypted secret store.
# Lifted from willow-2.0/core/vault.py, adapted for standalone use.
import os
import sqlite3
from pathlib import Path

from cryptography.fernet import Fernet


from . import paths


def _willow_home() -> Path:
    return paths.willow_home()


class Vault:
    def __init__(
        self,
        vault_path: Path | None = None,
        key_path: Path | None = None,
    ):
        self._vault = Path(vault_path) if vault_path is not None else paths.vault_db_path()
        self._key_path = Path(key_path) if key_path is not None else paths.vault_key_path()
        self._fernet: Fernet | None = None

    def init(self) -> None:
        """Create vault DB and Fernet key if they don't exist."""
        self._vault.parent.mkdir(parents=True, exist_ok=True)
        self._key_path.parent.mkdir(parents=True, exist_ok=True)

        if not self._key_path.exists():
            fd = os.open(str(self._key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(Fernet.generate_key())

        self._key_path.chmod(0o600)
        self._fernet = Fernet(self._key_path.read_bytes())

        conn = sqlite3.connect(str(self._vault))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                name TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )
        """)
        conn.commit()
        conn.close()
        self._vault.chmod(0o600)

    def _get_fernet(self) -> Fernet:
        if self._fernet is None:
            self._fernet = Fernet(self._key_path.read_bytes())
        return self._fernet

    def write(self, name: str, value: str) -> None:
        encrypted = self._get_fernet().encrypt(value.encode())
        conn = sqlite3.connect(str(self._vault))
        conn.execute(
            "INSERT INTO secrets (name, value) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
            (name, encrypted),
        )
        conn.commit()
        conn.close()

    def read(self, name: str) -> str | None:
        conn = sqlite3.connect(str(self._vault))
        row = conn.execute(
            "SELECT value FROM secrets WHERE name = ?", (name,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        return self._get_fernet().decrypt(row[0]).decode()

    def has(self, name: str) -> bool:
        return self.read(name) is not None

    def list_keys(self) -> list[str]:
        conn = sqlite3.connect(str(self._vault))
        rows = conn.execute("SELECT name FROM secrets ORDER BY name").fetchall()
        conn.close()
        return [r[0] for r in rows]


def default_vault() -> "Vault":
    """Return a Vault pointing at the operator secrets box, initializing if needed."""
    v = Vault()
    db_exists = paths.vault_db_path().exists()
    key_exists = paths.vault_key_path().exists()
    if db_exists and not key_exists:
        raise FileNotFoundError(
            f"Vault database exists but key file is missing: {v._key_path}\n"
            "Restore the key from backup or delete the vault and re-initialize."
        )
    if not db_exists:
        v.init()
    return v
