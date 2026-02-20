#!/usr/bin/env python3
"""
Compatibility shim.

The PM board originally lived under coach-feishu-suite/docs/live_server.py.
To keep CLI/offline tools working (they import `live_server`), the actual
implementation now lives in `pm_server.py`.
"""

from __future__ import annotations

from pm_server import *  # noqa: F401,F403


if __name__ == "__main__":
    main()

