#!/usr/bin/env python3
from __future__ import annotations

"""
License issuer helper (stdlib-only; uses openssl for signing).

This is a dev/admin tool for generating a signed License Key that can be used by:
  - local offline verification (PM tool)
  - cloud activation service (license_service.py)

Private key MUST NOT be committed.
Default expected path:
  ~/.codex/pm-subscription/private_key.pem
"""

import argparse
import base64
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--private-key", default=str(Path.home() / ".codex" / "pm-subscription" / "private_key.pem"))
    p.add_argument("--sub", default="")
    p.add_argument("--tier", default="pro")
    p.add_argument("--exp", default="")  # ISO8601 or epoch seconds
    p.add_argument("--iat", default="")
    p.add_argument("--lid", default="")
    p.add_argument("--max-devices", type=int, default=1)
    args = p.parse_args()

    priv = Path(args.private_key).expanduser()
    if not priv.exists():
        raise SystemExit(f"private key not found: {priv}")

    lid = (args.lid or "").strip() or f"lic-{uuid4().hex[:12]}"
    payload = {
        "lid": lid,
        "sub": (args.sub or "").strip(),
        "tier": (args.tier or "pro").strip() or "pro",
        "iat": (args.iat or "").strip() or now_iso(),
        "maxDevices": int(args.max_devices or 1),
    }
    if args.exp:
        payload["exp"] = str(args.exp).strip()

    payload_bytes = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    with tempfile.TemporaryDirectory(prefix="pm-issue-license-") as td:
        td_path = Path(td)
        payload_path = td_path / "payload.json"
        sig_path = td_path / "sig.bin"
        payload_path.write_bytes(payload_bytes)
        cmd = ["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(priv), "-out", str(sig_path), str(payload_path)]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise SystemExit(proc.stderr.strip() or "openssl sign failed")
        sig_bytes = sig_path.read_bytes()

    key = b64url_encode(payload_bytes) + "." + b64url_encode(sig_bytes)
    print(key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

