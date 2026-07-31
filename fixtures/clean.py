# clean.py — negative regression fixture for Python rules that run inside
# `fixtures/` (rules skipping test/fixture paths are covered by
# `corpus/clean/app/src/clean.py` instead).
#
# Adapted from Bandit/Ruff valid-code patterns (Apache-2.0 / MIT).
#
# Expected: NO python:* issues on this file.

from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


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


class Counter:
    def __init__(self) -> None:
        self.count = 0


def sum_squares(values: list[int]) -> int:
    return sum(v * v for v in values)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
