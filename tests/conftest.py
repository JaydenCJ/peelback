"""Shared fixtures for the peelback test suite.

Token *builders* live in ``tests/tokens.py`` (a plain module, importable
from any test file); this file holds only pytest fixtures.
"""

from __future__ import annotations

import pytest

from tokens import compact_json


@pytest.fixture()
def sample_json() -> bytes:
    return compact_json({"user": "amara", "roles": ["admin", "ops"], "n": 7})
