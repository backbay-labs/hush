"""Fixtures shared by the whole suite."""

from __future__ import annotations

import pytest

from hushspec.evaluate import deactivate_panic


@pytest.fixture(autouse=True)
def reset_panic_mode():
    """Leave panic mode off around every test.

    Panic is process-global and latching (core spec section 9), so a test that
    activates it and does not clear it makes every later test in the process
    deny everything. Resetting here rather than per module means no test can
    forget, and the suite does not depend on collection order.
    """
    deactivate_panic()
    yield
    deactivate_panic()
