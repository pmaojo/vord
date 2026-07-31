# clean.py — negative regression corpus for Python rules.
#
# Adapted from Bandit/Ruff valid-code patterns (Apache-2.0 / MIT).
# Scanned under a production-like path (`app/src/`) so rules that skip
# `fixtures/` still run here.
#
# Expected: NO python:* or owasp:* issues on this file.
# Expected hotspot: owasp:command-execution on subprocess.run (review-only).

from __future__ import annotations

import logging
import os
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone

import requests
import yaml

logger = logging.getLogger(__name__)


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def run_command(argv: list[str]) -> int:
    proc = subprocess.run(argv, check=False)
    return proc.returncode


def fetch_url(url: str) -> requests.Response:
    return requests.get(url, timeout=30)


def extract_archive(archive_path: str, dest: str) -> None:
    with tarfile.open(archive_path) as archive:
        archive.extractall(dest, filter="data")


def write_temp(data: bytes) -> str:
    fd, path = tempfile.mkstemp()
    try:
        with open(path, "wb") as handle:
            handle.write(data)
    finally:
        os.close(fd)
    return path


def find_active(users) -> list:
    result = []
    for user in users:
        if user is None:
            continue
        if user.active:
            result.append(user)
    return result


def parse_value(raw):
    if raw is None:
        return None
    if isinstance(raw, str):
        raw = raw.strip()
        if not raw:
            return None
    try:
        return int(raw)
    except ValueError as exc:
        logger.warning("parse failed: %s", exc)
        raise ValueError(f"invalid integer: {raw!r}") from exc


def register_routes(app) -> None:
    app.run(host="127.0.0.1", port=8080)


class Counter:
    def __init__(self) -> None:
        self.count = 0


def build_query() -> str:
    return "SELECT id FROM users WHERE id = ?"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def sum_squares(values: list[int]) -> int:
    return sum(v * v for v in values)
