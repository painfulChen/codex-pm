#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> int:
    here = Path(__file__).resolve().parent
    cli = here / "board_cli.py"
    os.chdir(str(here.parent))
    cmd = [sys.executable, str(cli), "daemon", *sys.argv[1:]]
    os.execv(sys.executable, cmd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
