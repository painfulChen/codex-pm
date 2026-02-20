#!/usr/bin/env python3
from __future__ import annotations

"""
Local mock for "cloud activation" (revoke / device binding / concurrency).

This is intentionally stdlib-only so it can be used as a reference for a real
cloud service later.

Endpoints:
  - GET  /healthz
  - POST /v1/activate   { licenseKey, deviceId, deviceName }
  - POST /v1/validate   { activationToken }
  - POST /v1/issue      { sub, tier, exp, maxDevices, lid? }   (admin, requires private key)
  - POST /v1/revoke     { licenseId }   (admin)
  - GET  /v1/licenses   (admin)
  - POST /v1/webhook/stripe   (no auth; verifies Stripe signature; issues license on checkout.session.completed)

Admin auth:
  Authorization: Bearer $PM_LICENSE_ADMIN_TOKEN
"""

import base64
import hashlib
import hmac
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from typing import Any, Dict
from urllib.parse import urlparse
from uuid import uuid4

HERE = Path(__file__).resolve().parent
DEFAULT_PUBKEY = HERE / "public_key.pem"
STORE_PATH = Path(
    os.environ.get("PM_LICENSE_STORE") or str(Path.home() / ".codex" / "pm-license-service" / "store.json")
).expanduser()
ADMIN_TOKEN = str(os.environ.get("PM_LICENSE_ADMIN_TOKEN") or "").strip()
PRIVATE_KEY = str(os.environ.get("PM_LICENSE_PRIVATE_KEY") or "").strip()
STRIPE_WEBHOOK_SECRET = str(os.environ.get("STRIPE_WEBHOOK_SECRET") or "").strip()

_LOCK = Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    s = (s or "").strip()
    if not s:
        return b""
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _parse_iso_dt(val: Any) -> datetime | None:
    if val is None:
        return None
    if isinstance(val, (int, float)):
        try:
            return datetime.fromtimestamp(float(val), tz=timezone.utc)
        except Exception:
            return None
    s = str(val).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def read_store() -> Dict[str, Any]:
    if not STORE_PATH.exists():
        return {"version": 1, "updatedAt": now_iso(), "_meta": {}, "licenses": {}, "purchases": {}}
    try:
        data = json.loads(STORE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"version": 1, "updatedAt": now_iso(), "_meta": {}, "licenses": {}, "purchases": {}}
    if not isinstance(data, dict):
        return {"version": 1, "updatedAt": now_iso(), "_meta": {}, "licenses": {}, "purchases": {}}
    if not isinstance(data.get("_meta"), dict):
        data["_meta"] = {}
    if not isinstance(data.get("licenses"), dict):
        data["licenses"] = {}
    if not isinstance(data.get("purchases"), dict):
        data["purchases"] = {}
    if "version" not in data:
        data["version"] = 1
    if "updatedAt" not in data:
        data["updatedAt"] = now_iso()
    return data


def write_store(store: Dict[str, Any]) -> None:
    store["updatedAt"] = now_iso()
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STORE_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(store, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(STORE_PATH)


def ensure_secret(store: Dict[str, Any]) -> str:
    meta = store.get("_meta")
    if not isinstance(meta, dict):
        meta = {}
        store["_meta"] = meta
    secret = str(meta.get("secret") or "").strip()
    if secret:
        return secret
    secret = uuid4().hex + uuid4().hex
    meta["secret"] = secret
    return secret


def verify_license_key(license_key: str) -> Dict[str, Any]:
    key = (license_key or "").strip()
    if not key:
        return {"ok": False, "status": "inactive", "error": "empty"}
    if "." not in key:
        return {"ok": False, "status": "invalid", "error": "bad_format"}
    if not DEFAULT_PUBKEY.exists():
        return {"ok": False, "status": "invalid", "error": "missing_public_key", "pubKey": str(DEFAULT_PUBKEY)}

    part_payload, part_sig = key.split(".", 1)
    try:
        payload_bytes = _b64url_decode(part_payload)
        sig_bytes = _b64url_decode(part_sig)
    except Exception:
        return {"ok": False, "status": "invalid", "error": "bad_base64"}
    if not payload_bytes or not sig_bytes:
        return {"ok": False, "status": "invalid", "error": "empty_parts"}
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        payload = None
    if not isinstance(payload, dict):
        return {"ok": False, "status": "invalid", "error": "bad_payload"}

    try:
        with tempfile.TemporaryDirectory(prefix="pm-license-svc-") as td:
            td_path = Path(td)
            payload_path = td_path / "payload.json"
            sig_path = td_path / "sig.bin"
            payload_path.write_bytes(payload_bytes)
            sig_path.write_bytes(sig_bytes)
            cmd = [
                "/usr/bin/openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(DEFAULT_PUBKEY),
                "-signature",
                str(sig_path),
                str(payload_path),
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                return {"ok": False, "status": "invalid", "error": "bad_signature"}
    except Exception:
        return {"ok": False, "status": "invalid", "error": "verify_failed"}

    tier = str(payload.get("tier") or "pro").strip() or "pro"
    subject = str(payload.get("sub") or payload.get("email") or "").strip()
    license_id = str(payload.get("lid") or payload.get("licenseId") or payload.get("id") or "").strip()
    if not license_id:
        # Backward-compatible: deterministic id from payload.
        digest = hashlib.sha256(payload_bytes).hexdigest()[:12]
        license_id = f"lic-{digest}"
    try:
        max_devices = int(payload.get("maxDevices") or payload.get("devices") or payload.get("seats") or 1)
    except Exception:
        max_devices = 1
    if max_devices < 1:
        max_devices = 1
    exp_dt = _parse_iso_dt(payload.get("exp"))
    expires_at = exp_dt.astimezone().isoformat() if exp_dt else ""
    if exp_dt and datetime.now(timezone.utc) > exp_dt:
        return {
            "ok": False,
            "status": "expired",
            "error": "expired",
            "licenseId": license_id,
            "tier": tier,
            "subject": subject,
            "expiresAt": expires_at,
            "maxDevices": max_devices,
        }
    return {
        "ok": True,
        "status": "active",
        "error": "",
        "licenseId": license_id,
        "tier": tier,
        "subject": subject,
        "expiresAt": expires_at,
        "maxDevices": max_devices,
    }


def require_admin(handler: BaseHTTPRequestHandler) -> bool:
    if not ADMIN_TOKEN:
        return False
    auth = str(handler.headers.get("Authorization") or "").strip()
    return auth == f"Bearer {ADMIN_TOKEN}"


def _parse_stripe_sig_header(h: str) -> Dict[str, Any]:
    # Stripe-Signature: t=...,v1=...,v1=...
    out: Dict[str, Any] = {"t": "", "v1": []}
    parts = [p.strip() for p in (h or "").split(",") if p.strip()]
    for p in parts:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        k = k.strip()
        v = v.strip()
        if k == "t":
            out["t"] = v
        elif k == "v1":
            out["v1"].append(v)
    return out


def verify_stripe_webhook(raw: bytes, sig_header: str) -> Dict[str, Any]:
    """
    Verify Stripe webhook signature (v1) without third-party deps.

    expected = hex(hmac_sha256(secret, f"{t}.{raw}"))
    """
    if not STRIPE_WEBHOOK_SECRET:
        return {"ok": False, "error": "missing_STRIPE_WEBHOOK_SECRET"}
    sig = _parse_stripe_sig_header(sig_header)
    t = str(sig.get("t") or "").strip()
    v1 = sig.get("v1") if isinstance(sig.get("v1"), list) else []
    if not t or not v1:
        return {"ok": False, "error": "bad_signature_header"}
    try:
        t_int = int(t)
    except Exception:
        return {"ok": False, "error": "bad_signature_timestamp"}
    now_ts = int(datetime.now(timezone.utc).timestamp())
    if abs(now_ts - t_int) > 300:
        return {"ok": False, "error": "timestamp_out_of_tolerance"}
    msg = (t + ".").encode("utf-8") + raw
    expected = hmac.new(STRIPE_WEBHOOK_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, str(s)) for s in v1):
        return {"ok": False, "error": "bad_signature"}
    return {"ok": True, "ts": t_int}


def issue_license_key(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not PRIVATE_KEY:
        return {"ok": False, "error": "missing_PM_LICENSE_PRIVATE_KEY"}
    priv = Path(PRIVATE_KEY).expanduser()
    if not priv.exists():
        return {"ok": False, "error": "private_key_not_found", "path": str(priv)}

    payload_bytes = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    with tempfile.TemporaryDirectory(prefix="pm-license-issue-") as td:
        td_path = Path(td)
        payload_path = td_path / "payload.json"
        sig_path = td_path / "sig.bin"
        payload_path.write_bytes(payload_bytes)
        cmd = ["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(priv), "-out", str(sig_path), str(payload_path)]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            return {"ok": False, "error": "openssl_sign_failed", "detail": (proc.stderr or "").strip()}
        sig_bytes = sig_path.read_bytes()

    key = _b64url_encode(payload_bytes) + "." + _b64url_encode(sig_bytes)
    return {"ok": True, "licenseKey": key, "payload": payload}


def issue_activation_token(secret: str, *, license_id: str, device_id: str, tier: str, expires_at: str) -> str:
    payload = {"lid": license_id, "did": device_id, "tier": tier, "exp": expires_at, "iat": now_iso()}
    payload_bytes = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
    return _b64url_encode(payload_bytes) + "." + _b64url_encode(sig)


def verify_activation_token(secret: str, token: str) -> Dict[str, Any]:
    t = (token or "").strip()
    if "." not in t:
        return {"ok": False, "error": "bad_token_format"}
    a, b = t.split(".", 1)
    try:
        payload_bytes = _b64url_decode(a)
        sig = _b64url_decode(b)
    except Exception:
        return {"ok": False, "error": "bad_token_base64"}
    expected = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return {"ok": False, "error": "bad_token_signature"}
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        payload = None
    if not isinstance(payload, dict):
        return {"ok": False, "error": "bad_token_payload"}
    exp_dt = _parse_iso_dt(payload.get("exp"))
    if exp_dt and datetime.now(timezone.utc) > exp_dt:
        return {"ok": False, "error": "token_expired", "payload": payload}
    return {"ok": True, "payload": payload}


class Handler(BaseHTTPRequestHandler):
    server_version = "pm-license-service/0.1"

    def _send_json(self, payload: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _parse_body(self) -> tuple[bytes, Dict[str, Any]]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(max(0, length)) if length > 0 else b""
        if not raw:
            return b"", {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            return raw, {}
        return raw, (data if isinstance(data, dict) else {})

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self._send_json(
                {
                    "ok": True,
                    "ts": now_iso(),
                    "store": str(STORE_PATH),
                    "pubKey": str(DEFAULT_PUBKEY),
                    "hasAdmin": bool(ADMIN_TOKEN),
                    "hasPrivateKey": bool(PRIVATE_KEY),
                    "hasStripeSecret": bool(STRIPE_WEBHOOK_SECRET),
                }
            )
            return
        if parsed.path == "/v1/licenses":
            if not require_admin(self):
                self._send_json({"ok": False, "error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            with _LOCK:
                store = read_store()
            self._send_json({"ok": True, "data": store.get("licenses", {})})
            return
        if parsed.path == "/v1/purchases":
            if not require_admin(self):
                self._send_json({"ok": False, "error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            with _LOCK:
                store = read_store()
            self._send_json({"ok": True, "data": store.get("purchases", {})})
            return
        self._send_json({"ok": False, "error": "not_found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        raw, body = self._parse_body()

        if parsed.path == "/v1/webhook/stripe":
            sig_header = str(self.headers.get("Stripe-Signature") or "").strip()
            ver = verify_stripe_webhook(raw, sig_header)
            if not ver.get("ok"):
                self._send_json({"ok": False, "error": ver.get("error")}, status=HTTPStatus.BAD_REQUEST)
                return

            event = body
            ev_id = str(event.get("id") or "").strip()
            ev_type = str(event.get("type") or "").strip()
            data_obj = event.get("data", {}).get("object", {}) if isinstance(event.get("data"), dict) else {}

            with _LOCK:
                store = read_store()
                purchases = store.get("purchases")
                if not isinstance(purchases, dict):
                    purchases = {}
                    store["purchases"] = purchases
                meta = store.get("_meta")
                if not isinstance(meta, dict):
                    meta = {}
                    store["_meta"] = meta
                seen = meta.get("stripeEvents")
                if not isinstance(seen, dict):
                    seen = {}
                    meta["stripeEvents"] = seen
                if ev_id and ev_id in seen:
                    self._send_json({"ok": True, "status": "ignored", "reason": "duplicate_event", "eventId": ev_id})
                    return
                if ev_id:
                    seen[ev_id] = {"type": ev_type, "receivedAt": now_iso()}
                purchases[f"stripe:{ev_id or uuid4().hex[:8]}"] = {"eventId": ev_id, "type": ev_type, "receivedAt": now_iso()}
                write_store(store)

            # MVP: optionally issue a license immediately on checkout completion.
            if ev_type == "checkout.session.completed" and PRIVATE_KEY:
                email = str(data_obj.get("customer_details", {}).get("email") or data_obj.get("customer_email") or "").strip()
                metadata = data_obj.get("metadata") if isinstance(data_obj.get("metadata"), dict) else {}
                tier = str(metadata.get("tier") or metadata.get("pm_tier") or "pro").strip() or "pro"
                exp = str(metadata.get("exp") or "").strip()
                try:
                    max_devices = int(metadata.get("maxDevices") or metadata.get("pm_max_devices") or 1)
                except Exception:
                    max_devices = 1
                lid = str(metadata.get("lid") or "").strip() or f"lic-{uuid4().hex[:12]}"
                payload = {"lid": lid, "sub": email, "tier": tier, "iat": now_iso(), "maxDevices": max_devices}
                if exp:
                    payload["exp"] = exp
                issued = issue_license_key(payload)
                if issued.get("ok"):
                    with _LOCK:
                        store = read_store()
                        licenses = store.get("licenses")
                        if not isinstance(licenses, dict):
                            licenses = {}
                            store["licenses"] = licenses
                        lic = licenses.get(lid)
                        if not isinstance(lic, dict):
                            lic = {"createdAt": now_iso(), "activations": {}}
                            licenses[lid] = lic
                        lic["tier"] = tier
                        lic["subject"] = email
                        lic["maxDevices"] = max_devices
                        if exp:
                            lic["expiresAt"] = exp
                        lic["issuedBy"] = "stripe"
                        lic["issuedAt"] = now_iso()
                        write_store(store)
                    self._send_json({"ok": True, "status": "issued", "licenseId": lid})
                    return

            self._send_json({"ok": True, "status": "received", "eventId": ev_id, "type": ev_type})
            return

        if parsed.path == "/v1/issue":
            if not require_admin(self):
                self._send_json({"ok": False, "error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            sub = str(body.get("sub") or body.get("email") or "").strip()
            tier = str(body.get("tier") or "pro").strip() or "pro"
            exp = body.get("exp")
            lid = str(body.get("lid") or body.get("licenseId") or "").strip() or f"lic-{uuid4().hex[:12]}"
            try:
                max_devices = int(body.get("maxDevices") or 1)
            except Exception:
                max_devices = 1
            if max_devices < 1:
                max_devices = 1
            payload = {"lid": lid, "sub": sub, "tier": tier, "iat": now_iso(), "maxDevices": max_devices}
            if exp:
                payload["exp"] = exp

            issued = issue_license_key(payload)
            if not issued.get("ok"):
                self._send_json(
                    {"ok": False, "error": issued.get("error"), "detail": issued.get("detail", ""), "path": issued.get("path", "")},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return

            with _LOCK:
                store = read_store()
                licenses = store.get("licenses")
                if not isinstance(licenses, dict):
                    licenses = {}
                    store["licenses"] = licenses
                lic = licenses.get(lid)
                if not isinstance(lic, dict):
                    lic = {"createdAt": now_iso(), "activations": {}}
                    licenses[lid] = lic
                lic["tier"] = tier
                lic["subject"] = sub
                lic["maxDevices"] = max_devices
                lic["expiresAt"] = str(exp or "")
                lic["issuedBy"] = "admin"
                lic["issuedAt"] = now_iso()
                write_store(store)

            self._send_json({"ok": True, "status": "issued", "licenseId": lid, "licenseKey": issued.get("licenseKey")})
            return

        if parsed.path == "/v1/activate":
            license_key = str(body.get("licenseKey") or "").strip()
            device_id = str(body.get("deviceId") or "").strip() or f"dev-{uuid4().hex[:12]}"
            device_name = str(body.get("deviceName") or "").strip()

            ver = verify_license_key(license_key)
            if not ver.get("ok"):
                st = str(ver.get("status") or "invalid")
                self._send_json({"ok": False, "status": st, "error": ver.get("error", ""), "result": ver}, status=HTTPStatus.BAD_REQUEST)
                return

            license_id = str(ver.get("licenseId") or "").strip()
            tier = str(ver.get("tier") or "pro").strip() or "pro"
            subject = str(ver.get("subject") or "").strip()
            expires_at = str(ver.get("expiresAt") or "").strip()
            max_devices = int(ver.get("maxDevices") or 1)

            with _LOCK:
                store = read_store()
                secret = ensure_secret(store)
                licenses = store.get("licenses")
                if not isinstance(licenses, dict):
                    licenses = {}
                    store["licenses"] = licenses
                lic = licenses.get(license_id)
                if not isinstance(lic, dict):
                    lic = {}
                    licenses[license_id] = lic
                lic.setdefault("createdAt", now_iso())
                lic["tier"] = tier
                lic["subject"] = subject
                lic["expiresAt"] = expires_at
                lic["maxDevices"] = max_devices
                if not isinstance(lic.get("activations"), dict):
                    lic["activations"] = {}
                acts: Dict[str, Any] = lic["activations"]

                if str(lic.get("revokedAt") or "").strip():
                    write_store(store)
                    self._send_json({"ok": False, "status": "revoked", "error": "revoked", "licenseId": license_id})
                    return

                # Concurrency: count unique device activations.
                if device_id not in acts and len(acts) >= max_devices:
                    write_store(store)
                    self._send_json(
                        {
                            "ok": False,
                            "status": "limit_reached",
                            "error": "device_limit_reached",
                            "licenseId": license_id,
                            "maxDevices": max_devices,
                            "activeDevices": len(acts),
                        },
                        status=HTTPStatus.CONFLICT,
                    )
                    return

                entry = acts.get(device_id)
                if not isinstance(entry, dict):
                    entry = {}
                    acts[device_id] = entry
                entry["deviceName"] = device_name
                entry.setdefault("activatedAt", now_iso())
                entry["lastSeenAt"] = now_iso()

                token = issue_activation_token(secret, license_id=license_id, device_id=device_id, tier=tier, expires_at=expires_at)
                write_store(store)

            self._send_json(
                {
                    "ok": True,
                    "status": "active",
                    "activationToken": token,
                    "licenseId": license_id,
                    "tier": tier,
                    "subject": subject,
                    "expiresAt": expires_at,
                    "maxDevices": max_devices,
                    "activeDevices": None,  # avoid leaking list by default
                    "deviceId": device_id,
                }
            )
            return

        if parsed.path == "/v1/validate":
            token = str(body.get("activationToken") or "").strip()
            with _LOCK:
                store = read_store()
                secret = ensure_secret(store)
                licenses = store.get("licenses") if isinstance(store.get("licenses"), dict) else {}
            ver = verify_activation_token(secret, token)
            if not ver.get("ok"):
                self._send_json({"ok": False, "status": "invalid", "error": ver.get("error")}, status=HTTPStatus.BAD_REQUEST)
                return
            payload = ver.get("payload") if isinstance(ver.get("payload"), dict) else {}
            license_id = str(payload.get("lid") or "").strip()
            device_id = str(payload.get("did") or "").strip()
            lic = licenses.get(license_id) if isinstance(licenses, dict) else None
            if isinstance(lic, dict) and str(lic.get("revokedAt") or "").strip():
                self._send_json({"ok": False, "status": "revoked", "error": "revoked"})
                return
            # Best-effort lastSeen update
            if isinstance(lic, dict):
                acts = lic.get("activations")
                if isinstance(acts, dict) and isinstance(acts.get(device_id), dict):
                    acts[device_id]["lastSeenAt"] = now_iso()
                    with _LOCK:
                        store = read_store()
                        store.setdefault("licenses", {})[license_id] = lic
                        write_store(store)
            self._send_json({"ok": True, "status": "active", "licenseId": license_id, "deviceId": device_id, "payload": payload})
            return

        if parsed.path == "/v1/revoke":
            if not require_admin(self):
                self._send_json({"ok": False, "error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            license_id = str(body.get("licenseId") or "").strip()
            if not license_id:
                self._send_json({"ok": False, "error": "licenseId required"}, status=HTTPStatus.BAD_REQUEST)
                return
            with _LOCK:
                store = read_store()
                licenses = store.get("licenses")
                if not isinstance(licenses, dict):
                    licenses = {}
                    store["licenses"] = licenses
                lic = licenses.get(license_id)
                if not isinstance(lic, dict):
                    lic = {"createdAt": now_iso(), "activations": {}}
                    licenses[license_id] = lic
                lic["revokedAt"] = now_iso()
                write_store(store)
            self._send_json({"ok": True, "status": "revoked", "licenseId": license_id})
            return

        self._send_json({"ok": False, "error": "not_found"}, status=HTTPStatus.NOT_FOUND)


def main() -> int:
    host = str(os.environ.get("HOST") or "127.0.0.1").strip() or "127.0.0.1"
    try:
        port = int(os.environ.get("PORT") or "8789")
    except Exception:
        port = 8789
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"[pm-license-service] listening on http://{host}:{port} (store={STORE_PATH})")
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
