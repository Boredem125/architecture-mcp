"""Unit tests for migrate.py resolve_db_url (AGG_DATABASE_URL_FILE support).

No Postgres required.  Tests verify:
  - AGG_DATABASE_URL_FILE is read and stripped
  - AGG_DATABASE_URL wins when both are set
  - Missing file raises with a message that does not leak the URL/password
  - Neither set raises RuntimeError
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Remove both URL env vars before every test."""
    monkeypatch.delenv("AGG_DATABASE_URL", raising=False)
    monkeypatch.delenv("AGG_DATABASE_URL_FILE", raising=False)


class TestResolveDbUrl:
    """Tests for agg_cp.migrate.resolve_db_url."""

    def test_reads_file_and_strips(self, tmp_path, monkeypatch):
        """AGG_DATABASE_URL_FILE should be read and trailing whitespace
        (including newline) stripped."""
        url = "postgresql+psycopg://user:s3cret@host:5432/db"
        f = tmp_path / "db_url"
        f.write_text(url + "\n", encoding="utf-8")
        monkeypatch.setenv("AGG_DATABASE_URL_FILE", str(f))

        from agg_cp.migrate import resolve_db_url

        assert resolve_db_url() == url

    def test_direct_env_wins_over_file(self, tmp_path, monkeypatch):
        """AGG_DATABASE_URL takes precedence when both are set."""
        direct = "postgresql+psycopg://direct:pw@host/db"
        file_url = "postgresql+psycopg://file:pw@host/db"
        f = tmp_path / "db_url"
        f.write_text(file_url, encoding="utf-8")
        monkeypatch.setenv("AGG_DATABASE_URL", direct)
        monkeypatch.setenv("AGG_DATABASE_URL_FILE", str(f))

        from agg_cp.migrate import resolve_db_url

        assert resolve_db_url() == direct

    def test_missing_file_raises(self, tmp_path, monkeypatch):
        """A non-existent file must raise with a message that names
        the path but does NOT contain the URL or password."""
        missing = tmp_path / "does_not_exist"
        monkeypatch.setenv("AGG_DATABASE_URL_FILE", str(missing))

        from agg_cp.migrate import resolve_db_url

        with pytest.raises(RuntimeError, match="missing file"):
            resolve_db_url()

    def test_neither_set_raises(self):
        """When both env vars are absent, RuntimeError is raised."""
        from agg_cp.migrate import resolve_db_url

        with pytest.raises(RuntimeError, match="AGG_DATABASE_URL"):
            resolve_db_url()

    def test_error_does_not_leak_url(self, tmp_path, monkeypatch):
        """The error message for a missing file must not contain any
        password or URL content."""
        secret_path = tmp_path / "secret_db_url"
        monkeypatch.setenv("AGG_DATABASE_URL_FILE", str(secret_path))

        from agg_cp.migrate import resolve_db_url

        with pytest.raises(RuntimeError) as exc_info:
            resolve_db_url()
        msg = str(exc_info.value)
        # The path is acceptable in the message, but no URL content
        assert "postgresql" not in msg.lower()
        assert "password" not in msg.lower()
        assert "s3cret" not in msg

    def test_empty_file_raises(self, tmp_path, monkeypatch):
        """A file that is empty (or whitespace-only) must raise."""
        f = tmp_path / "empty"
        f.write_text("   \n", encoding="utf-8")
        monkeypatch.setenv("AGG_DATABASE_URL_FILE", str(f))

        from agg_cp.migrate import resolve_db_url

        with pytest.raises(RuntimeError, match="AGG_DATABASE_URL"):
            resolve_db_url()

    # -- positive controls --

    def test_positive_control_direct_env(self, monkeypatch):
        """Direct AGG_DATABASE_URL must work as before."""
        url = "postgresql+psycopg://user:pw@host/db"
        monkeypatch.setenv("AGG_DATABASE_URL", url)

        from agg_cp.migrate import resolve_db_url

        assert resolve_db_url() == url
