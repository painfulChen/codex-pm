#!/usr/bin/env python3
from __future__ import annotations

import json
import base64
import os
import subprocess
import tempfile
import re
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import plistlib
from pathlib import Path
from threading import Lock
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse
from uuid import uuid4
import contextlib
import fcntl
import shutil

PM_HOME = Path(__file__).resolve().parent
ASSETS_DIR = PM_HOME / "docs"
DATA_DIR = Path(os.environ.get("PM_DATA_DIR", str(Path.home() / ".clawdbot" / "pm"))).expanduser()
DATA_DIR.mkdir(parents=True, exist_ok=True)

TODOS_PATH = DATA_DIR / "project-todos.json"
ITERATIONS_PATH = DATA_DIR / "project-iterations.json"
CONFIG_PATH = DATA_DIR / "pm-config.json"
TELEMETRY_PATH = DATA_DIR / "telemetry-events.jsonl"
SUBSCRIPTION_PUBKEY_PATH = PM_HOME / "subscription" / "public_key.pem"
_LOCK = Lock()
LOCK_PATH = DATA_DIR / ".pm-store.lock"


@contextlib.contextmanager
def file_lock(path: Path = LOCK_PATH):
    """
    Cross-process lock to prevent lost updates when multiple writers modify the JSON stores.

    Atomic rename in write_store avoids partial reads, but without a lock concurrent
    read-modify-write cycles can still overwrite each other.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            fh.close()
        except Exception:
            pass
STATUSES = {"todo", "doing", "done_requested", "done", "rollback_requested"}
# Tool identity (not a managed project name).
TOOL_NAME = str(PM_HOME.name or "codex-pm").strip() or "codex-pm"
# When tasks/agents provide empty/invalid project names, fall back to a stable project label.
# Default: the user's home folder name (e.g. "Zhuanz").
FALLBACK_PROJECT = str(os.environ.get("PM_DEFAULT_PROJECT", "")).strip() or (Path.home().name.strip() or "project")
PROJECT_SCAN_ROOT = Path(os.environ.get("PM_PROJECT_ROOT") or os.environ.get("LIVE_PROJECT_ROOT") or str(Path.home()))
# Agents heartbeat from terminals can be intermittent (e.g. user doesn't run attach yet).
# Keep them "online" for a few hours so multi-terminal views don't collapse to 0.
AGENT_TTL_SEC = int(os.getenv("PM_AGENT_TTL_SEC", "21600"))
AGENT_RETENTION_SEC = 86400
MAX_ITERATION_ITEMS = 3000
AUTO_LOG_LIMIT = 80
AUTO_ITER_START = "<!-- AUTO_ITERATIONS_START -->"
AUTO_ITER_END = "<!-- AUTO_ITERATIONS_END -->"
AUTO_ARCH_START = "<!-- AUTO_ARCH_STATUS_START -->"
AUTO_ARCH_END = "<!-- AUTO_ARCH_STATUS_END -->"

CHECK_KEYS = {"tests"}
TEST_STATUSES = {"unknown", "not_run", "pass", "fail"}
UI_FEATURE_DEFAULTS: Dict[str, Any] = {
    "projectTabsPagination": True,
    "projectTabsGrouping": True,
    "projectTabsBadges": True,
    "projectTabsSearch": True,
    "projectTabsPageThreshold": 80,
    "projectTabsPageSize": 40,
}

SERVICES_FILENAME = "pm-services.json"
SERVICE_CACHE_TTL_SEC = 2.0
_SERVICE_CACHE: dict[str, dict[str, Any]] = {}
ITER_CACHE_TTL_SEC = 1.0
_ITER_CACHE: dict[str, Any] = {}


def iteration_store_cached() -> Dict[str, Any]:
    """
    Iteration store is read frequently by the UI. Use a tiny cache keyed by file mtime.
    """
    now_ts = time.time()
    try:
        mtime = ITERATIONS_PATH.stat().st_mtime if ITERATIONS_PATH.exists() else 0.0
    except Exception:
        mtime = 0.0
    cached = _ITER_CACHE
    if (
        isinstance(cached, dict)
        and cached.get("mtime") == mtime
        and isinstance(cached.get("ts"), (int, float))
        and now_ts - float(cached.get("ts") or 0) < ITER_CACHE_TTL_SEC
        and isinstance(cached.get("data"), dict)
    ):
        return cached["data"]
    data = read_iteration_store()
    _ITER_CACHE.clear()
    _ITER_CACHE.update({"ts": now_ts, "mtime": mtime, "data": data})
    return data


def iter_latest_by_project(items: Any) -> Dict[str, str]:
    latest: Dict[str, str] = {}
    if not isinstance(items, list):
        return latest
    for x in items:
        if not isinstance(x, dict):
            continue
        p = normalize_project_name(x.get("project"))
        ts = str(x.get("createdAt") or "").strip()
        if not ts:
            continue
        prev = latest.get(p, "")
        if not prev or ts > prev:
            latest[p] = ts
    return latest


def default_config() -> Dict[str, Any]:
    return {
        "version": 1,
        "updatedAt": now_iso(),
        "uiPrefs": {
            "projectFavorites": [],
            "selectedProject": "",
            "projectTabsPage": 0,
            "projectTabsScroll": 0,
            "shortenerPreset": "internal_shortener_v1",
            "shortenerEndpoint": "",
            "shortenerHeaderName": "Authorization",
            "shortenerHeaderTemplate": "Bearer {{TOKEN}}",
        },
        "featureFlags": dict(UI_FEATURE_DEFAULTS),
        "telemetry": {
            # Default off. When enabled, we only log minimal metadata locally.
            "enabled": False,
            "localOnly": True,
            "allowSend": False,
            "endpoint": "",
        },
        "subscription": {
            # Subscription MVP: local license key + offline verification (optional).
            "licenseKey": "",
            "licenseId": "",
            "status": "inactive",  # inactive|active|expired|invalid|unverified
            "tier": "free",
            "subject": "",
            "expiresAt": "",
            "checkedAt": "",
            "lastError": "",
            "maxDevices": 1,
            # Cloud activation is optional. When enabled, we keep the offline verification
            # result, but also track a separate cloud status (revoked/device limit/etc.).
            "activation": {
                "mode": "offline",  # offline|cloud
                "serverUrl": "",
                "deviceId": "",
                "deviceName": "",
                "cloudStatus": "inactive",  # inactive|active|revoked|limit_reached|invalid|error
                "cloudError": "",
                "activationToken": "",
                "activatedAt": "",
                "validatedAt": "",
                "checkedAt": "",
            },
        },
    }


def sanitize_ui_prefs(raw: Any) -> Dict[str, Any]:
    prefs = raw if isinstance(raw, dict) else {}
    favorites_raw = prefs.get("projectFavorites")
    favorites: list[str] = []
    if isinstance(favorites_raw, list):
        seen: set[str] = set()
        for x in favorites_raw:
            p = normalize_optional_project(x)
            if not p or p in seen:
                continue
            favorites.append(p)
            seen.add(p)
            if len(favorites) >= 200:
                break
    selected_project = normalize_optional_project(prefs.get("selectedProject"))
    try:
        tabs_page = int(prefs.get("projectTabsPage") or 0)
    except Exception:
        tabs_page = 0
    if tabs_page < 0:
        tabs_page = 0
    try:
        tabs_scroll = float(prefs.get("projectTabsScroll") or 0)
    except Exception:
        tabs_scroll = 0.0
    if tabs_scroll < 0:
        tabs_scroll = 0.0
    shortener_preset = str(prefs.get("shortenerPreset") or "internal_shortener_v1").strip() or "internal_shortener_v1"
    if shortener_preset not in {"internal_shortener_v1", "generic"}:
        shortener_preset = "internal_shortener_v1"
    shortener_endpoint = str(prefs.get("shortenerEndpoint") or "").strip()[:400]
    shortener_header_name = str(prefs.get("shortenerHeaderName") or "Authorization").strip()[:80] or "Authorization"
    shortener_header_tmpl = str(prefs.get("shortenerHeaderTemplate") or "Bearer {{TOKEN}}").strip()[:200] or "Bearer {{TOKEN}}"
    return {
        "projectFavorites": favorites,
        "selectedProject": selected_project,
        "projectTabsPage": tabs_page,
        "projectTabsScroll": tabs_scroll,
        "shortenerPreset": shortener_preset,
        "shortenerEndpoint": shortener_endpoint,
        "shortenerHeaderName": shortener_header_name,
        "shortenerHeaderTemplate": shortener_header_tmpl,
    }


def sanitize_feature_flags(raw: Any) -> Dict[str, Any]:
    src = raw if isinstance(raw, dict) else {}
    out = dict(UI_FEATURE_DEFAULTS)
    for key in ("projectTabsPagination", "projectTabsGrouping", "projectTabsBadges", "projectTabsSearch"):
        if key in src:
            out[key] = bool(src.get(key))
    if "projectTabsPageThreshold" in src:
        try:
            out["projectTabsPageThreshold"] = max(20, min(1000, int(src.get("projectTabsPageThreshold") or 80)))
        except Exception:
            out["projectTabsPageThreshold"] = int(UI_FEATURE_DEFAULTS["projectTabsPageThreshold"])
    if "projectTabsPageSize" in src:
        try:
            out["projectTabsPageSize"] = max(10, min(200, int(src.get("projectTabsPageSize") or 40)))
        except Exception:
            out["projectTabsPageSize"] = int(UI_FEATURE_DEFAULTS["projectTabsPageSize"])
    return out


def ui_settings_from_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    ui_prefs = sanitize_ui_prefs(cfg.get("uiPrefs"))
    feature_flags = sanitize_feature_flags(cfg.get("featureFlags"))
    return {"uiPrefs": ui_prefs, "featureFlags": feature_flags}


def read_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        cfg = default_config()
        write_config(cfg)
        return cfg
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        data = default_config()
    if not isinstance(data, dict):
        data = default_config()
    if "version" not in data:
        data["version"] = 1
    if "updatedAt" not in data:
        data["updatedAt"] = now_iso()
    data["uiPrefs"] = sanitize_ui_prefs(data.get("uiPrefs"))
    data["featureFlags"] = sanitize_feature_flags(data.get("featureFlags"))
    tel = data.get("telemetry")
    if not isinstance(tel, dict):
        tel = {}
        data["telemetry"] = tel
    tel["enabled"] = bool(tel.get("enabled"))
    tel["localOnly"] = bool(tel.get("localOnly", True))
    tel["allowSend"] = bool(tel.get("allowSend"))
    tel["endpoint"] = str(tel.get("endpoint") or "").strip()

    sub = data.get("subscription")
    if not isinstance(sub, dict):
        sub = {}
        data["subscription"] = sub
    sub["licenseKey"] = str(sub.get("licenseKey") or "").strip()
    sub["licenseId"] = str(sub.get("licenseId") or "").strip()
    sub["status"] = str(sub.get("status") or "inactive").strip() or "inactive"
    sub["tier"] = str(sub.get("tier") or "free").strip() or "free"
    sub["subject"] = str(sub.get("subject") or "").strip()
    sub["expiresAt"] = str(sub.get("expiresAt") or "").strip()
    sub["checkedAt"] = str(sub.get("checkedAt") or "").strip()
    sub["lastError"] = str(sub.get("lastError") or "").strip()
    try:
        sub["maxDevices"] = int(sub.get("maxDevices") or 1)
    except Exception:
        sub["maxDevices"] = 1
    if sub["maxDevices"] < 1:
        sub["maxDevices"] = 1
    activation = sub.get("activation")
    if not isinstance(activation, dict):
        activation = {}
        sub["activation"] = activation
    activation["mode"] = str(activation.get("mode") or "offline").strip() or "offline"
    if activation["mode"] not in {"offline", "cloud"}:
        activation["mode"] = "offline"
    activation["serverUrl"] = str(activation.get("serverUrl") or "").strip()
    activation["deviceId"] = str(activation.get("deviceId") or "").strip()
    activation["deviceName"] = str(activation.get("deviceName") or "").strip()
    activation["cloudStatus"] = str(activation.get("cloudStatus") or "inactive").strip() or "inactive"
    activation["cloudError"] = str(activation.get("cloudError") or "").strip()
    activation["activationToken"] = str(activation.get("activationToken") or "").strip()
    activation["activatedAt"] = str(activation.get("activatedAt") or "").strip()
    activation["validatedAt"] = str(activation.get("validatedAt") or "").strip()
    activation["checkedAt"] = str(activation.get("checkedAt") or "").strip()
    return data


def write_config(cfg: Dict[str, Any]) -> None:
    cfg["updatedAt"] = now_iso()
    # Use unique temp files to avoid cross-process collisions (e.g. offline admin + server).
    tmp = CONFIG_PATH.with_name(CONFIG_PATH.name + f".tmp.{os.getpid()}.{uuid4().hex[:6]}")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(CONFIG_PATH)


def telemetry_enabled(cfg: Dict[str, Any]) -> bool:
    tel = cfg.get("telemetry")
    return bool(isinstance(tel, dict) and tel.get("enabled"))


def log_telemetry(cfg: Dict[str, Any], event: Dict[str, Any]) -> None:
    # Minimal local-only event log. Do not include task text or code content.
    if not telemetry_enabled(cfg):
        return
    payload = dict(event or {})
    payload["ts"] = now_iso()
    try:
        TELEMETRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with TELEMETRY_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        return


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
    # Support trailing Z.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except Exception:
        return None
    if dt.tzinfo is None:
        # If no tz, treat it as UTC to avoid locale ambiguity.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def verify_subscription_license(license_key: str) -> Dict[str, Any]:
    """
    License key format (MVP):
      base64url(JSON payload) + "." + base64url(RSA-SHA256 signature over payload bytes)

    Payload recommended fields:
      - sub: string (subject/email)
      - tier: free|pro|team
      - exp: ISO8601 or epoch seconds (optional)
      - iat: ISO8601 or epoch seconds (optional)
    """
    key = (license_key or "").strip()
    if not key:
        return {"ok": False, "status": "inactive", "tier": "free", "subject": "", "expiresAt": "", "error": ""}
    if "." not in key:
        return {"ok": False, "status": "invalid", "tier": "free", "subject": "", "expiresAt": "", "error": "bad_format"}
    if not SUBSCRIPTION_PUBKEY_PATH.exists():
        return {"ok": False, "status": "unverified", "tier": "free", "subject": "", "expiresAt": "", "error": "missing_public_key"}

    part_payload, part_sig = key.split(".", 1)
    try:
        payload_bytes = _b64url_decode(part_payload)
        sig_bytes = _b64url_decode(part_sig)
    except Exception:
        return {"ok": False, "status": "invalid", "tier": "free", "subject": "", "expiresAt": "", "error": "bad_base64"}
    if not payload_bytes or not sig_bytes:
        return {"ok": False, "status": "invalid", "tier": "free", "subject": "", "expiresAt": "", "error": "empty_parts"}

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        payload = None
    if not isinstance(payload, dict):
        return {"ok": False, "status": "invalid", "tier": "free", "subject": "", "expiresAt": "", "error": "bad_payload"}

    # Verify signature via openssl (stdlib-only).
    try:
        with tempfile.TemporaryDirectory(prefix="pm-license-") as td:
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
                str(SUBSCRIPTION_PUBKEY_PATH),
                "-signature",
                str(sig_path),
                str(payload_path),
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                return {
                    "ok": False,
                    "status": "invalid",
                    "tier": "free",
                    "subject": "",
                    "expiresAt": "",
                    "error": "bad_signature",
                }
    except Exception:
        return {"ok": False, "status": "invalid", "tier": "free", "subject": "", "expiresAt": "", "error": "verify_failed"}

    tier = str(payload.get("tier") or "pro").strip() or "pro"
    subject = str(payload.get("sub") or payload.get("email") or "").strip()
    license_id = str(payload.get("lid") or payload.get("licenseId") or payload.get("id") or "").strip()
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
            "tier": tier,
            "subject": subject,
            "expiresAt": expires_at,
            "error": "expired",
            "licenseId": license_id,
            "maxDevices": max_devices,
            "payload": {"tier": tier, "sub": subject, "exp": expires_at, "lid": license_id, "maxDevices": max_devices},
        }
    return {
        "ok": True,
        "status": "active",
        "tier": tier,
        "subject": subject,
        "expiresAt": expires_at,
        "error": "",
        "licenseId": license_id,
        "maxDevices": max_devices,
        "payload": {"tier": tier, "sub": subject, "exp": expires_at, "lid": license_id, "maxDevices": max_devices},
    }


def http_post_json(url: str, data: Dict[str, Any], timeout: int = 6) -> Dict[str, Any]:
    # Stdlib-only HTTP helper for cloud activation proxy.
    from urllib.request import Request, urlopen

    body = json.dumps(data or {}, ensure_ascii=False).encode("utf-8")
    req = Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json; charset=utf-8")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read() or b"{}"
            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception:
                payload = {"ok": False, "error": "bad_json_response"}
            if isinstance(payload, dict):
                payload["_httpStatus"] = getattr(resp, "status", 200)
                return payload
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return {"ok": False, "error": "unknown"}


def discover_projects() -> list[str]:
    names: list[str] = []
    try:
        for child in PROJECT_SCAN_ROOT.iterdir():
            if not child.is_dir():
                continue
            if child.name.startswith("."):
                continue
            if (child / ".git").exists():
                names.append(child.name)
    except Exception:
        return []
    return sorted(set(names), key=str.lower)


DISCOVERED_PROJECTS = discover_projects()


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def now_epoch() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def normalize_project_name(raw: Any) -> str:
    val = str(raw or "").strip()
    if not val:
        return FALLBACK_PROJECT
    if "/" in val or "\\" in val or val in {".", ".."}:
        return FALLBACK_PROJECT
    return val


def normalize_optional_project(raw: Any) -> str:
    val = str(raw or "").strip()
    if not val:
        return ""
    return normalize_project_name(val)


def infer_project_from_cwd(raw_cwd: Any) -> str:
    text = str(raw_cwd or "").strip()
    if not text:
        return ""
    try:
        cwd = Path(text).resolve()
        home = Path.home().resolve()
    except Exception:
        return ""

    if cwd == home:
        return home.name or ""

    cur = cwd
    while True:
        if (cur / ".git").exists():
            return normalize_project_name(cur.name)
        if cur == cur.parent:
            break
        try:
            cur.relative_to(home)
            cur = cur.parent
            continue
        except Exception:
            break

    try:
        cwd.relative_to(home)
        if cwd.parent == home and cwd.name:
            return normalize_project_name(cwd.name)
    except Exception:
        pass
    return ""


def effective_agent_project(payload: Dict[str, Any], project_override: Any = "") -> str:
    override = normalize_optional_project(project_override)
    if override:
        return override
    payload_project = normalize_optional_project(payload.get("project"))
    inferred = infer_project_from_cwd(payload.get("cwd"))
    if payload_project and payload_project not in {TOOL_NAME}:
        return payload_project
    if inferred:
        return inferred
    if payload_project:
        return payload_project
    return FALLBACK_PROJECT


def default_store() -> Dict[str, Any]:
    return {"version": 1, "updatedAt": now_iso(), "items": [], "agents": {}, "agentAliases": {}, "agentProjects": {}}


def read_store() -> Dict[str, Any]:
    if not TODOS_PATH.exists():
        return default_store()
    try:
        data = json.loads(TODOS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return default_store()
    if not isinstance(data, dict):
        return default_store()
    if not isinstance(data.get("items"), list):
        data["items"] = []
    if "version" not in data:
        data["version"] = 1
    if "updatedAt" not in data:
        data["updatedAt"] = now_iso()
    if not isinstance(data.get("agents"), dict):
        data["agents"] = {}
    if not isinstance(data.get("agentAliases"), dict):
        data["agentAliases"] = {}
    if not isinstance(data.get("agentProjects"), dict):
        data["agentProjects"] = {}
    agents = data["agents"]
    cutoff = now_epoch() - AGENT_RETENTION_SEC
    stale_agents: list[str] = []
    for aid, payload in list(agents.items()):
        if not isinstance(payload, dict):
            stale_agents.append(aid)
            continue
        seen_epoch = int(payload.get("lastSeenEpoch") or 0)
        if seen_epoch and seen_epoch < cutoff:
            stale_agents.append(aid)
    if stale_agents:
        for aid in stale_agents:
            agents.pop(aid, None)
    for item in data["items"]:
        status = str(item.get("status") or "todo").lower()
        if status not in STATUSES:
            status = "todo"
        item["status"] = status
        item["project"] = normalize_project_name(item.get("project"))
        checks = item.get("checks")
        if not isinstance(checks, dict):
            checks = {}
            item["checks"] = checks
        tests = str(checks.get("tests") or "unknown").strip()
        if tests not in TEST_STATUSES:
            tests = "unknown"
        checks["tests"] = tests
        git_meta = item.get("git")
        if git_meta is not None and not isinstance(git_meta, dict):
            item.pop("git", None)
    return data


def write_store(data: Dict[str, Any]) -> None:
    data["updatedAt"] = now_iso()
    # Use unique temp files to avoid cross-process collisions (e.g. offline admin + server).
    tmp_path = TODOS_PATH.with_name(TODOS_PATH.name + f".tmp.{os.getpid()}.{uuid4().hex[:6]}")
    tmp_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp_path.replace(TODOS_PATH)


def find_item(items: list, item_id: str) -> Dict[str, Any] | None:
    for item in items:
        if str(item.get("id")) == item_id:
            return item
    return None


def order_value(raw: Any, default: int) -> int:
    try:
        if raw is None:
            return default
        return int(raw)
    except Exception:
        return default


def priority_rank(raw: Any) -> int:
    pri = str(raw or "").strip().upper()
    if pri == "P0":
        return 0
    if pri == "P1":
        return 1
    if pri == "P2":
        return 2
    return 9


def next_order(items: list, status: str) -> int:
    max_v = 0
    for x in items:
        if str(x.get("status") or "").lower() != status:
            continue
        v = order_value(x.get("order"), 0)
        if v > max_v:
            max_v = v
    return (max_v + 10) if max_v > 0 else 10


def run_cmd(cmd: list[str], cwd: Path, timeout: int = 4) -> str:
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout, check=False)
    except Exception:
        return ""
    if proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip()


def git_snapshot(project: str) -> Dict[str, Any]:
    project_name = normalize_project_name(project)
    root = resolve_project_root(project_name)
    if not (root / ".git").exists():
        return {}

    git = "/usr/bin/git"
    branch = run_cmd([git, "rev-parse", "--abbrev-ref", "HEAD"], root) or ""
    commit = run_cmd([git, "rev-parse", "HEAD"], root) or ""
    subject = run_cmd([git, "log", "-1", "--pretty=%s"], root) or ""
    status_raw = run_cmd([git, "status", "--porcelain"], root) or ""

    staged = set(filter(None, (run_cmd([git, "diff", "--cached", "--name-only"], root) or "").splitlines()))
    unstaged = set(filter(None, (run_cmd([git, "diff", "--name-only"], root) or "").splitlines()))
    untracked = set(filter(None, (run_cmd([git, "ls-files", "--others", "--exclude-standard"], root) or "").splitlines()))
    changed = sorted(staged | unstaged | untracked)

    # Keep it human-usable but bounded.
    max_files = 60
    return {
        "project": project_name,
        "root": str(root),
        "branch": branch,
        "commit": commit,
        "commitShort": commit[:8] if commit else "",
        "commitSubject": subject,
        "dirty": bool(status_raw.strip()),
        "stagedCount": len(staged),
        "unstagedCount": len(unstaged),
        "untrackedCount": len(untracked),
        "changedCount": len(changed),
        "changedFiles": changed[:max_files],
        "capturedAt": now_iso(),
    }


def project_catalog(items: list, agents_raw: Dict[str, Any] | None = None) -> list[str]:
    home_name = Path.home().name.strip()
    names = set()
    if home_name:
        names.add(home_name)
    names.update(DISCOVERED_PROJECTS)
    for x in items:
        p = normalize_project_name(x.get("project"))
        if p:
            names.add(p)
    if isinstance(agents_raw, dict):
        for payload in agents_raw.values():
            if not isinstance(payload, dict):
                continue
            p = effective_agent_project(payload)
            if p:
                names.add(p)
    names.discard(TOOL_NAME)
    return sorted(names, key=str.lower)


def default_iteration_store() -> Dict[str, Any]:
    return {"version": 1, "updatedAt": now_iso(), "items": []}


def read_iteration_store() -> Dict[str, Any]:
    if not ITERATIONS_PATH.exists():
        return default_iteration_store()
    try:
        data = json.loads(ITERATIONS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return default_iteration_store()
    if not isinstance(data, dict):
        return default_iteration_store()
    if not isinstance(data.get("items"), list):
        data["items"] = []
    if "version" not in data:
        data["version"] = 1
    if "updatedAt" not in data:
        data["updatedAt"] = now_iso()
    normalized: list[Dict[str, Any]] = []
    for raw in data["items"]:
        if not isinstance(raw, dict):
            continue
        created_at = str(raw.get("createdAt") or "").strip() or now_iso()
        date_key = str(raw.get("date") or "").strip() or created_at[:10]
        normalized.append(
            {
                "id": str(raw.get("id") or f"iter-{uuid4().hex[:10]}"),
                "project": normalize_project_name(raw.get("project")),
                "type": str(raw.get("type") or "manual").strip() or "manual",
                "source": str(raw.get("source") or "manual").strip() or "manual",
                "title": str(raw.get("title") or "").strip(),
                "summary": str(raw.get("summary") or "").strip(),
                "taskId": str(raw.get("taskId") or "").strip(),
                "machineBy": str(raw.get("machineBy") or "").strip(),
                "status": str(raw.get("status") or "").strip(),
                "versionTag": str(raw.get("versionTag") or "").strip(),
                "createdAt": created_at,
                "date": date_key,
            }
        )
    data["items"] = normalized[-MAX_ITERATION_ITEMS:]
    return data


def write_iteration_store(data: Dict[str, Any]) -> None:
    data["updatedAt"] = now_iso()
    # Use unique temp files to avoid cross-process collisions (e.g. offline admin + server).
    tmp_path = ITERATIONS_PATH.with_name(ITERATIONS_PATH.name + f".tmp.{os.getpid()}.{uuid4().hex[:6]}")
    tmp_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp_path.replace(ITERATIONS_PATH)


def resolve_project_root(project: str) -> Path:
    p = normalize_project_name(project)
    home = Path.home()
    if p == home.name and home.exists() and home.is_dir():
        return home
    candidate = PROJECT_SCAN_ROOT / p
    if candidate.exists() and candidate.is_dir():
        return candidate
    # Fallback: return the "would-be" project root under scan root.
    return candidate


def _parse_int_list(val: Any) -> list[int]:
    out: list[int] = []
    if val is None:
        return out
    if isinstance(val, (int, float)):
        try:
            out.append(int(val))
        except Exception:
            return out
        return out
    if isinstance(val, str):
        parts = [x.strip() for x in val.split(",")]
        for p in parts:
            if not p:
                continue
            try:
                out.append(int(p))
            except Exception:
                continue
        return out
    if isinstance(val, list):
        for x in val:
            try:
                out.append(int(x))
            except Exception:
                continue
        return out
    return out


def _services_path_for_project(project: str) -> Path:
    root = resolve_project_root(project)
    return root / "docs" / SERVICES_FILENAME


def read_services_config(project: str) -> dict[str, Any]:
    project_name = normalize_project_name(project)
    path = _services_path_for_project(project_name)
    if not path.exists():
        return {
            "ok": True,
            "project": project_name,
            "path": str(path),
            "source": "default",
            "services": default_services_for_project(project_name),
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        data = None
    if not isinstance(data, dict):
        return {
            "ok": False,
            "error": "bad_services_config",
            "project": project_name,
            "path": str(path),
            "source": "file",
            "services": [],
        }
    raw = data.get("services")
    services: list[dict[str, Any]] = raw if isinstance(raw, list) else []
    normalized: list[dict[str, Any]] = []
    for idx, s in enumerate(services):
        if not isinstance(s, dict):
            continue
        kind = str(s.get("kind") or "").strip().lower()
        if kind not in {"launchd", "port"}:
            continue
        sid = str(s.get("id") or f"svc-{idx+1}").strip() or f"svc-{idx+1}"
        name = str(s.get("name") or sid).strip() or sid
        item: dict[str, Any] = {"id": sid, "name": name, "kind": kind}
        if kind == "launchd":
            label = str(s.get("label") or "").strip()
            if not label:
                continue
            item["label"] = label
            exp_ports = _parse_int_list(s.get("expectedPorts"))
            if exp_ports:
                item["expectedPorts"] = exp_ports
        if kind == "port":
            try:
                port = int(s.get("port") or 0)
            except Exception:
                port = 0
            if port <= 0:
                continue
            item["port"] = port
        open_urls = s.get("openUrls")
        if isinstance(open_urls, list):
            urls = [str(x).strip() for x in open_urls if str(x).strip()]
            if urls:
                item["openUrls"] = urls[:6]
        for k in ["stdoutPath", "stderrPath", "workingDirectory", "generatedFrom", "lastScannedAt"]:
            v = s.get(k)
            if isinstance(v, str) and v.strip():
                item[k] = v.strip()
        normalized.append(item)
    return {
        "ok": True,
        "project": project_name,
        "path": str(path),
        "source": "file",
        "services": normalized,
    }


def default_services_for_project(project: str) -> list[dict[str, Any]]:
    p = normalize_project_name(project)
    if p == "coach-feishu-suite":
        return [
            {
                "id": "pm-board",
                "name": "PM 看板服务",
                "kind": "launchd",
                "label": "com.zhuanz.codex-pm",
                "expectedPorts": [8765],
                "openUrls": ["http://127.0.0.1:8765/pm"],
            },
            {
                "id": "coach-web",
                "name": "Coach Web (apps/web)",
                "kind": "launchd",
                "label": "com.coach.web",
                "expectedPorts": [3001],
                "openUrls": ["http://127.0.0.1:3001/"],
            },
            {
                "id": "coach-server",
                "name": "Coach Server (apps/server)",
                "kind": "launchd",
                "label": "com.coach.server",
            },
            {
                "id": "feishu-worker",
                "name": "Feishu Worker (apps/server/start-server.sh)",
                "kind": "launchd",
                "label": "com.clawdbot.coach-feishu-server",
            },
        ]
    if p.lower() == "trendradar".lower():
        return [
            {
                "id": "trendradar",
                "name": "TrendRadar Dashboard",
                "kind": "launchd",
                "label": "com.trendradar",
                "expectedPorts": [8000],
                "openUrls": ["http://127.0.0.1:8000/"],
            }
        ]
    if p == "clawd":
        return [
            {
                "id": "clawd-dashboard",
                "name": "clawd status_dashboard",
                "kind": "launchd",
                "label": "com.clawdbot.dashboard",
                "expectedPorts": [8787],
                "openUrls": ["http://127.0.0.1:8787/healthz", "http://127.0.0.1:8787/readyz"],
            }
        ]
    return []


def _run(cmd: list[str], timeout: float = 1.2) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except Exception as exc:
        return subprocess.CompletedProcess(cmd, 1, "", str(exc))


def _launchctl_print(label: str) -> str:
    domain = f"gui/{os.getuid()}/{label}"
    proc = _run(["launchctl", "print", domain], timeout=1.5)
    if proc.returncode != 0:
        return ""
    return proc.stdout or ""


def _launchctl_pid(label: str) -> int:
    text = _launchctl_print(label)
    if text:
        m = re.search(r"\bpid\s*=\s*(\d+)\b", text)
        if m:
            try:
                return int(m.group(1))
            except Exception:
                return 0
    # Fallback: launchctl list (best-effort)
    proc = _run(["launchctl", "list"], timeout=1.5)
    if proc.returncode == 0:
        for line in (proc.stdout or "").splitlines():
            if not line.strip().endswith(label):
                continue
            parts = line.split()
            if not parts:
                continue
            if parts[-1] != label:
                continue
            try:
                return int(parts[0]) if parts[0] != "-" else 0
            except Exception:
                return 0
    return 0


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    proc = _run(["ps", "-p", str(pid)], timeout=1.0)
    return proc.returncode == 0


def _listening_ports_by_pid(pid: int) -> list[int]:
    if pid <= 0:
        return []
    proc = _run(["lsof", "-nP", "-a", "-p", str(pid), "-iTCP", "-sTCP:LISTEN"], timeout=1.5)
    if proc.returncode != 0:
        return []
    ports: set[int] = set()
    for line in (proc.stdout or "").splitlines():
        if "LISTEN" not in line:
            continue
        m = re.search(r":(\d+)\s*\(LISTEN\)", line)
        if not m:
            continue
        try:
            ports.add(int(m.group(1)))
        except Exception:
            continue
    return sorted(ports)


def _port_listening(port: int) -> bool:
    if port <= 0:
        return False
    proc = _run(["lsof", "-nP", "-iTCP:%d" % port, "-sTCP:LISTEN"], timeout=1.2)
    return proc.returncode == 0 and "LISTEN" in (proc.stdout or "")


def check_service(project: str, svc: dict[str, Any]) -> dict[str, Any]:
    kind = str(svc.get("kind") or "").strip().lower()
    out: dict[str, Any] = {
        "project": normalize_project_name(project),
        "id": str(svc.get("id") or "").strip(),
        "name": str(svc.get("name") or "").strip(),
        "kind": kind,
        "checkedAt": now_iso(),
        "ok": False,
        "status": "down",
        "detail": "",
    }
    open_urls = svc.get("openUrls")
    if isinstance(open_urls, list):
        out["openUrls"] = [str(x).strip() for x in open_urls if str(x).strip()][:6]
    for k in ["stdoutPath", "stderrPath", "workingDirectory"]:
        v = svc.get(k)
        if isinstance(v, str) and v.strip():
            out[k] = v.strip()
    if kind == "port":
        try:
            port = int(svc.get("port") or 0)
        except Exception:
            port = 0
        out["port"] = port
        ok = _port_listening(port)
        out["ok"] = bool(ok)
        out["status"] = "up" if ok else "down"
        return out
    if kind == "launchd":
        label = str(svc.get("label") or "").strip()
        out["label"] = label
        text = _launchctl_print(label)
        loaded = bool(text)
        pid = _launchctl_pid(label) if loaded else 0
        alive = _pid_alive(pid) if pid else False
        ports = _listening_ports_by_pid(pid) if alive else []
        exp_ports = _parse_int_list(svc.get("expectedPorts"))
        out["loaded"] = loaded
        out["pid"] = pid if pid else 0
        out["alive"] = alive
        if exp_ports:
            out["expectedPorts"] = exp_ports
        # Some launchd jobs spawn child processes that actually bind ports (e.g. pnpm dev).
        # When expectedPorts is set, validate ports directly as a fallback.
        port_hits: list[int] = []
        if exp_ports:
            for p in exp_ports:
                if _port_listening(int(p)):
                    port_hits.append(int(p))
        if port_hits:
            seen = set(ports)
            for p in port_hits:
                if p not in seen:
                    ports.append(p)
        ports = sorted({int(x) for x in ports if int(x) > 0})
        out["ports"] = ports
        ok = loaded and (alive or bool(port_hits)) and (True if not exp_ports else any(p in ports for p in exp_ports))
        out["ok"] = bool(ok)
        out["status"] = "up" if ok else ("loaded" if loaded else "down")
        if loaded and alive and exp_ports and ports and not any(p in ports for p in exp_ports):
            out["detail"] = f"listening ports mismatch (expected {exp_ports}, got {ports})"
        return out
    out["detail"] = "unsupported kind"
    return out


def services_payload(project: str = "") -> dict[str, Any]:
    now_t = time.time()
    if project:
        projects = [normalize_project_name(project)]
    else:
        # Use the same catalog logic as the board, so "全部项目" feels consistent.
        with _LOCK:
            store = read_store()
        agents_raw = store.get("agents") if isinstance(store.get("agents"), dict) else {}
        projects = project_catalog(store.get("items") or [], agents_raw)
    groups: list[dict[str, Any]] = []
    for p in projects:
        cfg = read_services_config(p)
        raw_services = cfg.get("services") if isinstance(cfg.get("services"), list) else []
        results: list[dict[str, Any]] = []
        for svc in raw_services:
            if not isinstance(svc, dict):
                continue
            cache_key = f"{p}:{svc.get('id')}"
            cached = _SERVICE_CACHE.get(cache_key)
            if cached and (now_t - float(cached.get("_t") or 0.0)) <= SERVICE_CACHE_TTL_SEC:
                results.append(dict(cached.get("data") or {}))
                continue
            data = check_service(p, svc)
            _SERVICE_CACHE[cache_key] = {"_t": now_t, "data": data}
            results.append(data)
        groups.append(
            {
                "project": p,
                "source": cfg.get("source"),
                "path": cfg.get("path"),
                "services": results,
            }
        )
    return {"ok": True, "data": {"project": normalize_optional_project(project), "groups": groups, "checkedAt": now_iso()}}


def _guess_ports_from_program_args(args: list[Any]) -> list[int]:
    parts = [str(x) for x in (args or []) if str(x).strip()]
    ports: list[int] = []
    for i, tok in enumerate(parts):
        t = tok.strip()
        if t.startswith("--port="):
            ports.extend(_parse_int_list(t.split("=", 1)[1]))
            continue
        if t in {"--port", "-p"}:
            if i + 1 < len(parts):
                ports.extend(_parse_int_list(parts[i + 1]))
            continue
        if t.startswith("--listen") and "=" in t:
            ports.extend(_parse_int_list(t.split("=", 1)[1]))
            continue
    # Dedupe
    out: list[int] = []
    seen: set[int] = set()
    for p in ports:
        if p <= 0:
            continue
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


def _infer_project_from_plist(label: str, wd: str, program_args: list[Any]) -> str:
    if wd:
        p = infer_project_from_cwd(wd)
        if p:
            return p
    for x in program_args or []:
        s = str(x).strip()
        if not s:
            continue
        if s.startswith(str(Path.home())):
            return infer_project_from_cwd(s) or FALLBACK_PROJECT
    # Last resort: use home name to group "global" services.
    return Path.home().name or FALLBACK_PROJECT


def _slugify_label(label: str) -> str:
    tail = label.split(".")[-2:] if "." in label else [label]
    s = "-".join([x for x in tail if x])
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-")
    return s or label


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}.{uuid4().hex[:6]}")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def scan_launchagents_to_projects(*, mode: str = "merge") -> dict[str, Any]:
    """
    Scan ~/Library/LaunchAgents/*.plist and merge into each project's docs/pm-services.json.
    This is a convenience generator; users can still manually edit pm-services.json later.
    """
    launch_dir = Path.home() / "Library" / "LaunchAgents"
    files = sorted(launch_dir.glob("*.plist"))
    scanned: list[dict[str, Any]] = []
    for f in files:
        try:
            raw = plistlib.loads(f.read_bytes())
        except Exception:
            continue
        if not isinstance(raw, dict):
            continue
        label = str(raw.get("Label") or "").strip()
        if not label:
            continue
        # Ignore unrelated system agents to keep noise down.
        if not (label.startswith("com.coach.") or label.startswith("com.clawdbot.") or label.startswith("com.trendradar") or label.startswith("com.zhuanz.")):
            continue
        wd = str(raw.get("WorkingDirectory") or "").strip()
        env = raw.get("EnvironmentVariables") if isinstance(raw.get("EnvironmentVariables"), dict) else {}
        program_args = raw.get("ProgramArguments") if isinstance(raw.get("ProgramArguments"), list) else []
        stdout_path = str(raw.get("StandardOutPath") or "").strip()
        stderr_path = str(raw.get("StandardErrorPath") or "").strip()
        ports = _parse_int_list(env.get("PORT")) if isinstance(env, dict) else []
        if not ports:
            ports = _guess_ports_from_program_args(program_args)
        project = _infer_project_from_plist(label, wd, program_args)
        entry: dict[str, Any] = {
            "id": _slugify_label(label),
            "name": label,
            "kind": "launchd",
            "label": label,
        }
        if ports:
            entry["expectedPorts"] = ports[:6]
            entry["openUrls"] = [f"http://127.0.0.1:{ports[0]}/"]
        if wd:
            entry["workingDirectory"] = wd
        if stdout_path:
            entry["stdoutPath"] = stdout_path
        if stderr_path:
            entry["stderrPath"] = stderr_path
        scanned.append({"project": project, "entry": entry, "plist": str(f)})

    by_project: dict[str, list[dict[str, Any]]] = {}
    for row in scanned:
        by_project.setdefault(str(row["project"]), []).append(row["entry"])

    updated: list[dict[str, Any]] = []
    for project, entries in sorted(by_project.items(), key=lambda x: x[0].lower()):
        p = normalize_project_name(project)
        path = _services_path_for_project(p)
        existing: dict[str, Any] = {}
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                existing = {}
        if not isinstance(existing, dict):
            existing = {}
        existing_services = existing.get("services") if isinstance(existing.get("services"), list) else []
        existing_services = [x for x in existing_services if isinstance(x, dict)]

        if mode == "replace":
            merged = []
        else:
            merged = list(existing_services)

        # Index existing by label for launchd entries.
        idx_by_label: dict[str, int] = {}
        for i, svc in enumerate(merged):
            if str(svc.get("kind") or "").strip().lower() != "launchd":
                continue
            lb = str(svc.get("label") or "").strip()
            if lb:
                idx_by_label[lb] = i

        added = 0
        patched = 0
        for e in entries:
            lb = str(e.get("label") or "").strip()
            if not lb:
                continue
            if lb not in idx_by_label:
                merged.append(e)
                idx_by_label[lb] = len(merged) - 1
                added += 1
                continue
            i = idx_by_label[lb]
            cur = merged[i]
            changed = False
            # Only fill missing user-facing fields; but always refresh paths/working dir for operability.
            for k in ["workingDirectory", "stdoutPath", "stderrPath"]:
                if e.get(k) and cur.get(k) != e.get(k):
                    cur[k] = e.get(k)
                    changed = True
            for k in ["expectedPorts", "openUrls"]:
                if e.get(k) and not cur.get(k):
                    cur[k] = e.get(k)
                    changed = True
            if changed:
                merged[i] = cur
                patched += 1

        out = {
            "version": int(existing.get("version") or 1),
            "updatedAt": now_iso(),
            "project": p,
            "generatedFrom": "launchagents",
            "lastScannedAt": now_iso(),
            "services": merged,
        }
        _atomic_write_json(path, out)
        updated.append({"project": p, "path": str(path), "added": added, "patched": patched, "total": len(merged)})

    return {"scanned": len(scanned), "projects": len(updated), "updated": updated}


def replace_or_append_block(text: str, title: str, start: str, end: str, body: str) -> str:
    block = f"{title}\n{start}\n{body.rstrip()}\n{end}\n"
    if start in text and end in text:
        prefix, rest = text.split(start, 1)
        _, suffix = rest.split(end, 1)
        # Avoid duplicating the section title on repeated syncs.
        # Many docs already contain `title` immediately above `start`; since `block` includes
        # `title` too, we remove any trailing `title` lines from the prefix.
        prefix_lines = prefix.rstrip().splitlines()
        while prefix_lines and prefix_lines[-1].strip() == title.strip():
            prefix_lines.pop()
        prefix_clean = "\n".join(prefix_lines).rstrip()
        return prefix_clean + "\n" + block + suffix.lstrip("\n")
    base = text.rstrip() + "\n\n" if text.strip() else ""
    return base + block


def render_iteration_lines(entries: list[Dict[str, Any]]) -> list[str]:
    if not entries:
        return ["- 暂无迭代日志。"]
    lines: list[str] = []
    grouped: Dict[str, list[Dict[str, Any]]] = {}
    for item in entries:
        date_key = str(item.get("date") or str(item.get("createdAt") or "")[:10] or "unknown")
        grouped.setdefault(date_key, []).append(item)
    for date_key in sorted(grouped.keys(), reverse=True):
        lines.append(f"### {date_key}")
        day_items = sorted(grouped[date_key], key=lambda x: str(x.get("createdAt") or ""), reverse=True)
        for it in day_items:
            t = str(it.get("createdAt") or "")[11:19] or "--:--:--"
            ver = str(it.get("versionTag") or "").strip()
            head = f"[{ver}] " if ver else ""
            it_type = str(it.get("type") or "manual").strip()
            title = str(it.get("title") or "(未命名迭代)").strip()
            summary = str(it.get("summary") or "").strip()
            tail = f"；{summary}" if summary else ""
            lines.append(f"- {t} {head}{it_type}：{title}{tail}")
    return lines


def render_project_live_auto_block(project: str, project_items: list[Dict[str, Any]], project_iters: list[Dict[str, Any]]) -> str:
    status_count = {k: 0 for k in ["todo", "doing", "done_requested", "rollback_requested", "done"]}
    for item in project_items:
        st = str(item.get("status") or "todo").lower()
        if st not in status_count:
            st = "todo"
        status_count[st] += 1
    lines = [
        f"- 最近自动同步：{now_iso()}",
        f"- 项目：{project}",
        (
            "- 当前任务状态："
            f"待办 {status_count['todo']} / 进行中 {status_count['doing']} / "
            f"待机器完成 {status_count['done_requested']} / 待机器回滚 {status_count['rollback_requested']} / "
            f"已完成 {status_count['done']}"
        ),
        "",
    ]
    lines.extend(render_iteration_lines(project_iters[:AUTO_LOG_LIMIT]))
    return "\n".join(lines).rstrip() + "\n"


def render_arch_auto_block(project: str, project_items: list[Dict[str, Any]], project_iters: list[Dict[str, Any]]) -> str:
    done_items = [x for x in project_items if str(x.get("status") or "").lower() == "done"]
    done_items.sort(key=lambda x: str(x.get("updatedAt") or ""), reverse=True)
    lines = [
        f"- 最近自动同步：{now_iso()}",
        f"- 项目：{project}",
        "- 版本日志（最近 12 条）：",
    ]
    if project_iters:
        for it in project_iters[:12]:
            version = str(it.get("versionTag") or "-")
            summary = str(it.get("summary") or "").strip()
            if len(summary) > 140:
                summary = summary[:137].rstrip() + "..."
            tail = f" · {summary}" if summary else ""
            lines.append(f"  - {version} · {it.get('type', 'manual')} · {it.get('title', '(未命名)')}{tail}")
    else:
        lines.append("  - 暂无")
    lines.append("- 最近完成项（最近 8 条）：")
    if done_items:
        for item in done_items[:8]:
            lines.append(f"  - {item.get('updatedAt', '-')} · {item.get('id', '-')} · {item.get('text', '-')}")
    else:
        lines.append("  - 暂无")
    return "\n".join(lines).rstrip() + "\n"


def ensure_seed_file(path: Path, title: str) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# {title}\n\n", encoding="utf-8")


def apply_done_context_from_payload(item: Dict[str, Any], payload: Dict[str, Any]) -> None:
    if not isinstance(item, dict) or not isinstance(payload, dict):
        return
    done_what = str(payload.get("doneWhat") or payload.get("what") or "").strip()
    optimize = str(payload.get("optimization") or payload.get("optimize") or payload.get("opt") or "").strip()
    impact = str(payload.get("impact") or "").strip()
    if done_what:
        item["doneWhat"] = done_what
    if optimize:
        item["optimization"] = optimize
    if impact:
        item["impact"] = impact
    if done_what or optimize or impact:
        checks = item.get("checks")
        if not isinstance(checks, dict):
            checks = {}
            item["checks"] = checks
        if done_what:
            checks["doneWhat"] = done_what
        if optimize:
            checks["optimization"] = optimize
        if impact:
            checks["impact"] = impact


def build_done_summary(item: Dict[str, Any], item_id: str, machine_by: str, *, snap: Dict[str, Any] | None = None) -> str:
    checks = item.get("checks") if isinstance(item.get("checks"), dict) else {}
    done_what = str(item.get("doneWhat") or checks.get("doneWhat") or item.get("text") or item_id).strip() or item_id
    optimize = str(item.get("optimization") or checks.get("optimization") or "").strip()
    impact = str(item.get("impact") or checks.get("impact") or "").strip()
    tests = str(checks.get("tests") or "unknown").strip() or "unknown"

    git_impact = ""
    if isinstance(snap, dict) and snap:
        head = str(snap.get("commitShort") or (snap.get("commit") or "")[:8] or "-").strip() or "-"
        br = str(snap.get("branch") or "-").strip() or "-"
        dirty = "*" if snap.get("dirty") else ""
        git_impact = f"git={br}@{head}{dirty} files={int(snap.get('changedCount') or 0)}"

    if not optimize:
        optimize = "流程与实现已优化（未填写细项）"
    if not impact:
        impact_parts = [f"tests={tests}"]
        if git_impact:
            impact_parts.insert(0, git_impact)
        impact = "；".join(impact_parts)
    elif git_impact and "git=" not in impact:
        impact = f"{impact}；{git_impact}"

    return (
        f"任务 {item_id} 已由 {machine_by} 机器确认完成；"
        f"做了什么：{done_what}；"
        f"优化点：{optimize}；"
        f"影响：{impact}"
    )


def sync_project_docs(project: str, all_items: list[Dict[str, Any]], all_iterations: list[Dict[str, Any]]) -> None:
    project_name = normalize_project_name(project)
    root = resolve_project_root(project_name)
    live_doc = root / "docs" / "project-live.md"
    arch_doc = root / "ARCHITECTURE.md"
    ensure_seed_file(live_doc, f"{project_name} 项目文档（实时版）")
    ensure_seed_file(arch_doc, f"ARCHITECTURE ({project_name})")
    project_items = [x for x in all_items if normalize_project_name(x.get("project")) == project_name]
    project_iters = [x for x in all_iterations if normalize_project_name(x.get("project")) == project_name]
    project_iters.sort(key=lambda x: str(x.get("createdAt") or ""), reverse=True)

    live_text = live_doc.read_text(encoding="utf-8")
    live_block = render_project_live_auto_block(project_name, project_items, project_iters)
    live_text = replace_or_append_block(live_text, "## 自动日程表与版本日志（机器维护）", AUTO_ITER_START, AUTO_ITER_END, live_block)
    live_doc.write_text(live_text.rstrip() + "\n", encoding="utf-8")

    arch_text = arch_doc.read_text(encoding="utf-8")
    arch_block = render_arch_auto_block(project_name, project_items, project_iters)
    arch_text = replace_or_append_block(arch_text, "## 自动架构同步状态（机器维护）", AUTO_ARCH_START, AUTO_ARCH_END, arch_block)
    arch_doc.write_text(arch_text.rstrip() + "\n", encoding="utf-8")


def append_iteration(
    iteration_store: Dict[str, Any],
    *,
    project: str,
    it_type: str,
    title: str,
    summary: str = "",
    task_id: str = "",
    machine_by: str = "",
    status: str = "",
    source: str = "machine",
) -> Dict[str, Any]:
    project_name = normalize_project_name(project)
    created_at = now_iso()
    date_key = created_at[:10]
    seq = 1
    for x in iteration_store.get("items") or []:
        if normalize_project_name(x.get("project")) != project_name:
            continue
        if str(x.get("date") or "") != date_key:
            continue
        seq += 1
    entry = {
        "id": f"iter-{uuid4().hex[:10]}",
        "project": project_name,
        "type": str(it_type or "manual").strip() or "manual",
        "source": str(source or "manual").strip() or "manual",
        "title": str(title or "(未命名迭代)").strip(),
        "summary": str(summary or "").strip(),
        "taskId": str(task_id or "").strip(),
        "machineBy": str(machine_by or "").strip(),
        "status": str(status or "").strip(),
        "versionTag": f"v{date_key.replace('-', '')}.{seq:02d}",
        "createdAt": created_at,
        "date": date_key,
    }
    items = iteration_store.get("items")
    if not isinstance(items, list):
        items = []
        iteration_store["items"] = items
    items.append(entry)
    if len(items) > MAX_ITERATION_ITEMS:
        iteration_store["items"] = items[-MAX_ITERATION_ITEMS:]
    return entry


def agent_view(
    agent_id: str,
    payload: Dict[str, Any],
    aliases: Dict[str, Any] | None = None,
    project_overrides: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    now = now_epoch()
    seen_epoch = int(payload.get("lastSeenEpoch") or 0)
    stale = (now - seen_epoch) > AGENT_TTL_SEC if seen_epoch else True
    raw_alias = ""
    if isinstance(aliases, dict):
        raw_alias = str(aliases.get(agent_id) or "").strip()
    base_title = str(payload.get("title") or agent_id).strip()
    display_title = raw_alias or base_title
    project_override = ""
    if isinstance(project_overrides, dict):
        project_override = project_overrides.get(agent_id)
    project_value = effective_agent_project(payload, project_override)
    return {
        "agentId": agent_id,
        "title": base_title,
        "alias": raw_alias,
        "displayTitle": display_title,
        "project": project_value,
        "state": str(payload.get("state") or "idle").strip(),
        "taskId": str(payload.get("taskId") or "").strip(),
        "cwd": str(payload.get("cwd") or "").strip(),
        "note": str(payload.get("note") or "").strip(),
        "lastSeenAt": str(payload.get("lastSeenAt") or "").strip(),
        "lastSeenEpoch": seen_epoch,
        "stale": stale,
    }


def build_agent_views(store: Dict[str, Any]) -> list[Dict[str, Any]]:
    agents_raw = store.get("agents") if isinstance(store.get("agents"), dict) else {}
    aliases = store.get("agentAliases") if isinstance(store.get("agentAliases"), dict) else {}
    project_overrides = store.get("agentProjects") if isinstance(store.get("agentProjects"), dict) else {}
    agent_ids: set[str] = set()
    agent_ids.update(str(x) for x in agents_raw.keys())
    agent_ids.update(str(x) for x in aliases.keys())
    agent_ids.update(str(x) for x in project_overrides.keys())
    views = [
        agent_view(
            aid,
            agents_raw.get(aid) if isinstance(agents_raw.get(aid), dict) else {},
            aliases,
            project_overrides,
        )
        for aid in sorted(agent_ids)
    ]
    views.sort(key=lambda x: x.get("lastSeenEpoch", 0), reverse=True)
    return views


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(ASSETS_DIR), **kwargs)

    def end_headers(self) -> None:
        """
        Avoid browser caching for the PM board HTML so we don't need long `?v=...` URLs.
        """
        try:
            path = urlparse(self.path).path or ""
        except Exception:
            path = ""
        if not path.startswith("/api/"):
            if path in {"/", "/pm", "/live-view.html", "/live-view-v3.html"} or path.endswith((".html", ".svg")):
                self.send_header("Cache-Control", "no-store")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
        return super().end_headers()

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        """
        Suppress noisy poll logs; keep errors for debugging.
        """
        try:
            c = int(code) if isinstance(code, (int, str)) and str(code).isdigit() else 200
        except Exception:
            c = 200
        if c >= 400:
            return super().log_request(code, size)
        try:
            path = urlparse(self.path).path or ""
        except Exception:
            path = ""
        if path.startswith("/api/"):
            return
        if path in {"/", "/pm", "/live-view.html", "/live-view-v3.html"} or path.endswith((".html", ".svg")):
            return
        return super().log_request(code, size)

    def _send_json(self, payload: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_store(self, store: Dict[str, Any], status: int = 200) -> None:
        agents_raw = store.get("agents") if isinstance(store.get("agents"), dict) else {}
        agents = build_agent_views(store)
        it_store = iteration_store_cached()
        it_items = it_store.get("items") if isinstance(it_store.get("items"), list) else []
        projects = project_catalog(store.get("items") or [], agents_raw)
        try:
            cfg = read_config()
        except Exception:
            cfg = default_config()
        ui_settings = ui_settings_from_config(cfg)
        cfg_default = normalize_optional_project(cfg.get("defaultProject") if isinstance(cfg, dict) else "") or ""
        default_project = cfg_default or FALLBACK_PROJECT
        if projects:
            if default_project not in projects:
                default_project = FALLBACK_PROJECT if FALLBACK_PROJECT in projects else projects[0]
        self._send_json(
            {
                "ok": True,
                "data": store,
                "projects": projects,
                "defaultProject": default_project,
                "agents": agents,
                "iterLatestByProject": iter_latest_by_project(it_items),
                "iterUpdatedAt": it_store.get("updatedAt", now_iso()),
                "uiPrefs": ui_settings.get("uiPrefs", {}),
                "featureFlags": ui_settings.get("featureFlags", {}),
            },
            status=status,
        )

    def _parse_json_body(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        raw = self.rfile.read(max(0, length))
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    def _send_html_file(self, path: Path, status: int = 200) -> None:
        try:
            body = path.read_bytes()
        except Exception:
            body = b""
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        # Keep the bookmark URL stable: old entrypoints redirect to /pm.
        if parsed.path in {"/live-view-v3.html", "/live-view.html"}:
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/pm")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        if parsed.path in {"", "/"}:
            # Short stable entry.
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/pm")
            self.end_headers()
            return
        if parsed.path == "/pm":
            self._send_html_file(ASSETS_DIR / "live-view-v3.html")
            return
        if parsed.path == "/api/todos":
            with _LOCK:
                store = read_store()
            self._send_store(store)
            return
        if parsed.path == "/api/terminals":
            # Backwards-compatible alias for older UI clients.
            with _LOCK:
                store = read_store()
            agents = build_agent_views(store)
            self._send_json({"ok": True, "data": {"terminals": agents}})
            return
        if parsed.path == "/api/services":
            query = parse_qs(parsed.query or "")
            project = normalize_optional_project((query.get("project") or [""])[0])
            self._send_json(services_payload(project))
            return
        if parsed.path == "/api/config":
            with _LOCK:
                cfg = read_config()
            self._send_json({"ok": True, "data": cfg})
            return
        if parsed.path == "/api/telemetry":
            query = parse_qs(parsed.query or "")
            try:
                limit = int((query.get("limit") or ["200"])[0])
            except Exception:
                limit = 200
            limit = max(0, min(limit, 2000))
            events: list[Dict[str, Any]] = []
            if TELEMETRY_PATH.exists() and limit > 0:
                try:
                    lines = TELEMETRY_PATH.read_text(encoding="utf-8").splitlines()
                    for raw in lines[-limit:]:
                        try:
                            obj = json.loads(raw)
                            if isinstance(obj, dict):
                                events.append(obj)
                        except Exception:
                            continue
                except Exception:
                    events = []
            self._send_json({"ok": True, "data": {"count": len(events), "events": events, "path": str(TELEMETRY_PATH)}})
            return
        if parsed.path == "/api/project-doc":
            query = parse_qs(parsed.query or "")
            project = normalize_project_name((query.get("project") or [FALLBACK_PROJECT])[0])
            root = resolve_project_root(project)
            doc_path = root / "docs" / "project-live.md"
            ensure_seed_file(doc_path, f"{project} 项目文档（实时版）")
            try:
                content = doc_path.read_text(encoding="utf-8")
            except Exception:
                content = ""
            self._send_json(
                {
                    "ok": True,
                    "data": {
                        "project": project,
                        "path": str(doc_path),
                        "content": content,
                    },
                }
            )
            return
        if parsed.path == "/api/iterations":
            query = parse_qs(parsed.query or "")
            project = normalize_optional_project((query.get("project") or [""])[0])
            with _LOCK:
                data = read_iteration_store()
                items = data.get("items") if isinstance(data.get("items"), list) else []
                if project:
                    items = [x for x in items if normalize_project_name(x.get("project")) == project]
                items.sort(key=lambda x: str(x.get("createdAt") or ""), reverse=True)
            self._send_json(
                {
                    "ok": True,
                    "data": {"version": data.get("version", 1), "updatedAt": data.get("updatedAt", now_iso()), "items": items},
                    "defaultProject": FALLBACK_PROJECT,
                }
            )
            return
        return super().do_GET()

    def do_HEAD(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"", "/"}:
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/pm")
            self.end_headers()
            return
        if parsed.path == "/pm":
            path = ASSETS_DIR / "live-view-v3.html"
            try:
                size = path.stat().st_size
            except Exception:
                size = 0
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            return
        return super().do_HEAD()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path not in {"/api/todos", "/api/iterations", "/api/config", "/api/telemetry", "/api/services"}:
            self._send_json({"ok": False, "error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return

        body = self._parse_json_body()
        action = str(body.get("action") or "").strip()
        if not action and parsed.path == "/api/iterations":
            action = "add_iteration"
        if not action:
            self._send_json({"ok": False, "error": "action required"}, status=HTTPStatus.BAD_REQUEST)
            return

        # /api/services does not mutate the todo/iteration stores; avoid taking the store lock.
        if parsed.path == "/api/services":
            if action == "kickstart":
                label = str(body.get("label") or "").strip()
                if not label or not re.fullmatch(r"[A-Za-z0-9._-]+", label):
                    self._send_json({"ok": False, "error": "invalid label"}, status=HTTPStatus.BAD_REQUEST)
                    return
                domain = f"gui/{os.getuid()}/{label}"
                proc = _run(["launchctl", "kickstart", "-k", domain], timeout=4.0)
                if proc.returncode != 0:
                    self._send_json({"ok": False, "error": (proc.stderr or proc.stdout or "kickstart failed").strip()})
                    return
                self._send_json({"ok": True, "result": {"label": label, "domain": domain}})
                return
            if action == "scan_launchagents":
                mode = str(body.get("mode") or "merge").strip().lower() or "merge"
                if mode not in {"merge", "replace"}:
                    mode = "merge"
                result = scan_launchagents_to_projects(mode=mode)
                self._send_json({"ok": True, "result": result})
                return
            self._send_json({"ok": False, "error": f"unsupported action: {action}"}, status=HTTPStatus.BAD_REQUEST)
            return

        with file_lock():
            with _LOCK:
                store = read_store()
                iteration_store = read_iteration_store()
                cfg = read_config()
                items = store["items"]
                agents = store["agents"]
                aliases = store.get("agentAliases") if isinstance(store.get("agentAliases"), dict) else {}
                project_overrides = store.get("agentProjects") if isinstance(store.get("agentProjects"), dict) else {}
                now = now_iso()
                now_ep = now_epoch()

            if parsed.path == "/api/config":
                if action == "set_telemetry":
                    tel = cfg.get("telemetry")
                    if not isinstance(tel, dict):
                        tel = {}
                        cfg["telemetry"] = tel
                    if "enabled" in body:
                        tel["enabled"] = bool(body.get("enabled"))
                    if "localOnly" in body:
                        tel["localOnly"] = bool(body.get("localOnly"))
                    if "allowSend" in body:
                        tel["allowSend"] = bool(body.get("allowSend"))
                    if "endpoint" in body:
                        tel["endpoint"] = str(body.get("endpoint") or "").strip()
                    write_config(cfg)
                    self._send_json({"ok": True, "data": cfg})
                    return
                if action == "set_ui_prefs":
                    incoming = body.get("prefs")
                    if not isinstance(incoming, dict):
                        incoming = {
                            "projectFavorites": body.get("projectFavorites"),
                            "selectedProject": body.get("selectedProject"),
                            "projectTabsPage": body.get("projectTabsPage"),
                            "projectTabsScroll": body.get("projectTabsScroll"),
                        }
                    current = sanitize_ui_prefs(cfg.get("uiPrefs"))
                    merged = dict(current)
                    for k, v in incoming.items():
                        merged[k] = v
                    cfg["uiPrefs"] = sanitize_ui_prefs(merged)
                    write_config(cfg)
                    self._send_json({"ok": True, "data": cfg})
                    return
                if action == "set_feature_flags":
                    incoming_flags = body.get("flags")
                    if not isinstance(incoming_flags, dict):
                        incoming_flags = {k: body.get(k) for k in UI_FEATURE_DEFAULTS.keys() if k in body}
                    current_flags = sanitize_feature_flags(cfg.get("featureFlags"))
                    next_flags = dict(current_flags)
                    for k, v in incoming_flags.items():
                        next_flags[k] = v
                    cfg["featureFlags"] = sanitize_feature_flags(next_flags)
                    write_config(cfg)
                    self._send_json({"ok": True, "data": cfg})
                    return

                if action == "set_subscription":
                    lk = str(body.get("licenseKey") or body.get("license") or "").strip()
                    sub = cfg.get("subscription")
                    if not isinstance(sub, dict):
                        sub = {}
                        cfg["subscription"] = sub
                    sub["licenseKey"] = lk
                    res = verify_subscription_license(lk)
                    sub["status"] = str(res.get("status") or "inactive")
                    sub["tier"] = str(res.get("tier") or "free")
                    sub["subject"] = str(res.get("subject") or "")
                    sub["expiresAt"] = str(res.get("expiresAt") or "")
                    sub["licenseId"] = str(res.get("licenseId") or "")
                    try:
                        sub["maxDevices"] = int(res.get("maxDevices") or sub.get("maxDevices") or 1)
                    except Exception:
                        sub["maxDevices"] = 1
                    sub["checkedAt"] = now
                    sub["lastError"] = str(res.get("error") or "")
                    write_config(cfg)
                    log_telemetry(cfg, {"type": "set_subscription", "status": sub.get("status"), "tier": sub.get("tier")})
                    self._send_json({"ok": True, "data": cfg, "result": res})
                    return

                if action == "set_activation":
                    sub = cfg.get("subscription")
                    if not isinstance(sub, dict):
                        sub = {}
                        cfg["subscription"] = sub
                    activation = sub.get("activation")
                    if not isinstance(activation, dict):
                        activation = {}
                        sub["activation"] = activation
                    mode = str(body.get("mode") or activation.get("mode") or "offline").strip() or "offline"
                    if mode not in {"offline", "cloud"}:
                        mode = "offline"
                    activation["mode"] = mode
                    if "serverUrl" in body:
                        activation["serverUrl"] = str(body.get("serverUrl") or "").strip()
                    if "deviceName" in body:
                        activation["deviceName"] = str(body.get("deviceName") or "").strip()
                    if not activation.get("deviceId"):
                        activation["deviceId"] = f"dev-{uuid4().hex[:12]}"
                    activation["checkedAt"] = now
                    write_config(cfg)
                    log_telemetry(cfg, {"type": "set_activation", "mode": activation.get("mode")})
                    self._send_json({"ok": True, "data": cfg})
                    return

                if action == "clear_activation":
                    sub = cfg.get("subscription")
                    if not isinstance(sub, dict):
                        sub = {}
                        cfg["subscription"] = sub
                    activation = sub.get("activation")
                    if not isinstance(activation, dict):
                        activation = {}
                        sub["activation"] = activation
                    activation["cloudStatus"] = "inactive"
                    activation["cloudError"] = ""
                    activation["activationToken"] = ""
                    activation["activatedAt"] = ""
                    activation["validatedAt"] = ""
                    activation["checkedAt"] = now
                    write_config(cfg)
                    log_telemetry(cfg, {"type": "clear_activation"})
                    self._send_json({"ok": True, "data": cfg})
                    return

                if action == "activate_subscription":
                    sub = cfg.get("subscription")
                    if not isinstance(sub, dict):
                        sub = {}
                        cfg["subscription"] = sub
                    activation = sub.get("activation")
                    if not isinstance(activation, dict):
                        activation = {}
                        sub["activation"] = activation
                    server_url = str(body.get("serverUrl") or activation.get("serverUrl") or "").strip()
                    license_key = str(body.get("licenseKey") or sub.get("licenseKey") or "").strip()
                    if not server_url:
                        self._send_json({"ok": False, "error": "serverUrl required"}, status=HTTPStatus.BAD_REQUEST)
                        return
                    if not license_key:
                        self._send_json({"ok": False, "error": "licenseKey required"}, status=HTTPStatus.BAD_REQUEST)
                        return
                    if not activation.get("deviceId"):
                        activation["deviceId"] = f"dev-{uuid4().hex[:12]}"
                    if "deviceName" in body:
                        activation["deviceName"] = str(body.get("deviceName") or "").strip()
                    url = server_url.rstrip("/") + "/v1/activate"
                    req = {
                        "licenseKey": license_key,
                        "deviceId": str(activation.get("deviceId") or ""),
                        "deviceName": str(activation.get("deviceName") or ""),
                        "client": {"app": "codex-pm", "ts": now},
                    }
                    result = http_post_json(url, req, timeout=6)
                    st = str(result.get("status") or ("active" if result.get("ok") else "error")).strip() or "error"
                    activation["cloudStatus"] = st
                    activation["cloudError"] = str(result.get("error") or "")
                    token = str(result.get("activationToken") or "").strip()
                    if token:
                        activation["activationToken"] = token
                        activation["activatedAt"] = now
                    activation["checkedAt"] = now
                    write_config(cfg)
                    log_telemetry(cfg, {"type": "activate_subscription", "status": st})
                    self._send_json({"ok": True, "data": cfg, "result": result})
                    return

                self._send_json({"ok": False, "error": "unsupported action"}, status=HTTPStatus.BAD_REQUEST)
                return

            if parsed.path == "/api/telemetry":
                if action == "clear":
                    try:
                        TELEMETRY_PATH.write_text("", encoding="utf-8")
                    except Exception:
                        pass
                    self._send_json({"ok": True, "data": {"cleared": True, "path": str(TELEMETRY_PATH)}})
                    return
                if action in {"track", "track_event"}:
                    event = body.get("event")
                    if not isinstance(event, dict):
                        event = {}
                    name = str(event.get("name") or body.get("name") or "").strip()[:80]
                    props = event.get("props")
                    if not isinstance(props, dict):
                        props = {}
                    # Keep telemetry payload bounded and metadata-only.
                    safe_props: Dict[str, Any] = {}
                    for k, v in props.items():
                        key = str(k or "").strip()[:40]
                        if not key:
                            continue
                        if isinstance(v, (bool, int, float)):
                            safe_props[key] = v
                            continue
                        text = str(v or "")
                        safe_props[key] = text[:200]
                    log_telemetry(
                        cfg,
                        {
                            "type": "ui_event",
                            "name": name or "unknown",
                            "props": safe_props,
                            "source": str(body.get("source") or "web"),
                        },
                    )
                    self._send_json({"ok": True, "data": {"tracked": True}})
                    return
                self._send_json({"ok": True, "data": {"noop": True}})
                return

            if action == "agent_ping":
                agent_id = str(body.get("agentId") or "").strip()
                if not agent_id:
                    self._send_json({"ok": False, "error": "agentId required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                agent = agents.get(agent_id) if isinstance(agents.get(agent_id), dict) else {}
                raw_project = body.get("project") or agent.get("project") or ""
                raw_cwd = str(body.get("cwd") or agent.get("cwd") or "").strip()
                agent["project"] = effective_agent_project({"project": raw_project, "cwd": raw_cwd})
                agent["title"] = str(body.get("title") or agent.get("title") or agent_id).strip() or agent_id
                agent["state"] = str(body.get("state") or agent.get("state") or "idle").strip() or "idle"
                agent["taskId"] = str(body.get("taskId") or "").strip()
                agent["cwd"] = raw_cwd
                agent["note"] = str(body.get("note") or "").strip()
                agent["lastSeenAt"] = now
                agent["lastSeenEpoch"] = now_ep
                agents[agent_id] = agent
                write_store(store)
                log_telemetry(cfg, {"type": "agent_ping", "agentId": agent_id, "project": agent.get("project"), "state": agent.get("state")})
                self._send_store(store)
                return

            if action == "cleanup_agents":
                max_age = int(body.get("maxAgeSec") or AGENT_TTL_SEC)
                if max_age < AGENT_TTL_SEC:
                    max_age = AGENT_TTL_SEC
                cutoff = now_ep - max_age
                stale_ids: list[str] = []
                for aid, payload in list(agents.items()):
                    if not isinstance(payload, dict):
                        stale_ids.append(aid)
                        continue
                    seen_epoch = int(payload.get("lastSeenEpoch") or 0)
                    if not seen_epoch or seen_epoch < cutoff:
                        stale_ids.append(aid)
                if stale_ids:
                    for aid in stale_ids:
                        agents.pop(aid, None)
                write_store(store)
                log_telemetry(cfg, {"type": "cleanup_agents", "removed": len(stale_ids)})
                self._send_store(store)
                return

            if action == "claim_next":
                agent_id = str(body.get("agentId") or "").strip()
                project = normalize_optional_project(body.get("project") or "")
                if not agent_id:
                    self._send_json({"ok": False, "error": "agentId required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                candidates = []
                for item in items:
                    if str(item.get("status") or "").lower() != "todo":
                        continue
                    if project and normalize_project_name(item.get("project")) != project:
                        continue
                    owner = str(item.get("claimedBy") or "").strip()
                    if owner and owner != agent_id:
                        continue
                    candidates.append(item)
                if not candidates:
                    self._send_json(
                        {
                            "ok": True,
                            "data": store,
                            "projects": project_catalog(store.get("items") or [], agents),
                            "defaultProject": FALLBACK_PROJECT,
                            "agents": build_agent_views(store),
                            "claimed": None,
                        }
                    )
                    return
                candidates.sort(
                    key=lambda x: (
                        priority_rank(x.get("priority")),
                        order_value(x.get("order"), 999999),
                        str(x.get("createdAt") or ""),
                    )
                )
                item = candidates[0]
                item_id = str(item.get("id"))
                item["status"] = "doing"
                item["order"] = next_order(items, "doing")
                item["claimedBy"] = agent_id
                item["claimedAt"] = now
                item["updatedAt"] = now
                agent = agents.get(agent_id) if isinstance(agents.get(agent_id), dict) else {}
                agent["project"] = normalize_project_name(item.get("project") or project or FALLBACK_PROJECT)
                agent["title"] = str(body.get("title") or agent.get("title") or agent_id).strip() or agent_id
                agent["state"] = "busy"
                agent["taskId"] = item_id
                agent["cwd"] = str(body.get("cwd") or agent.get("cwd") or "").strip()
                agent["note"] = str(body.get("note") or agent.get("note") or "").strip()
                agent["lastSeenAt"] = now
                agent["lastSeenEpoch"] = now_ep
                agents[agent_id] = agent
                write_store(store)
                log_telemetry(cfg, {"type": "claim_next", "agentId": agent_id, "project": agent.get("project"), "taskId": item_id})
                agents_out = build_agent_views(store)
                self._send_json(
                    {
                        "ok": True,
                        "data": store,
                        "projects": project_catalog(store.get("items") or [], agents),
                        "defaultProject": FALLBACK_PROJECT,
                        "agents": agents_out,
                        "claimed": item,
                    }
                )
                return

            if action == "claim_task":
                item_id = str(body.get("id") or "").strip()
                agent_id = str(body.get("agentId") or "").strip()
                if not item_id or not agent_id:
                    self._send_json({"ok": False, "error": "id and agentId required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                item = find_item(items, item_id)
                if not item:
                    self._send_json({"ok": False, "error": "item not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                current = str(item.get("status") or "todo").lower()
                current_owner = str(item.get("claimedBy") or "").strip()
                if current not in {"todo", "doing"}:
                    self._send_json({"ok": False, "error": "only todo/doing item can be claimed"}, status=HTTPStatus.BAD_REQUEST)
                    return
                if current_owner and current_owner != agent_id:
                    self._send_json({"ok": False, "error": f"already claimed by {current_owner}"}, status=HTTPStatus.CONFLICT)
                    return
                if current == "todo":
                    item["status"] = "doing"
                    item["order"] = next_order(items, "doing")
                item["claimedBy"] = agent_id
                item["claimedAt"] = now
                item["updatedAt"] = now
                agent = agents.get(agent_id) if isinstance(agents.get(agent_id), dict) else {}
                agent["project"] = normalize_project_name(item.get("project") or FALLBACK_PROJECT)
                agent["title"] = str(body.get("title") or agent.get("title") or agent_id).strip() or agent_id
                agent["state"] = "busy"
                agent["taskId"] = item_id
                agent["lastSeenAt"] = now
                agent["lastSeenEpoch"] = now_ep
                agents[agent_id] = agent
                write_store(store)
                log_telemetry(cfg, {"type": "claim_task", "agentId": agent_id, "taskId": item_id, "project": agent.get("project")})
                self._send_store(store)
                return

            if action == "release_task":
                item_id = str(body.get("id") or "").strip()
                agent_id = str(body.get("agentId") or "").strip()
                if not item_id or not agent_id:
                    self._send_json({"ok": False, "error": "id and agentId required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                item = find_item(items, item_id)
                if not item:
                    self._send_json({"ok": False, "error": "item not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                current_owner = str(item.get("claimedBy") or "").strip()
                if current_owner and current_owner != agent_id:
                    self._send_json({"ok": False, "error": f"claimed by {current_owner}"}, status=HTTPStatus.CONFLICT)
                    return
                item.pop("claimedBy", None)
                item.pop("claimedAt", None)
                if str(item.get("status") or "").lower() == "doing":
                    item["status"] = "todo"
                    item["order"] = next_order(items, "todo")
                item["updatedAt"] = now
                agent = agents.get(agent_id) if isinstance(agents.get(agent_id), dict) else {}
                agent["state"] = "idle"
                agent["taskId"] = ""
                agent["lastSeenAt"] = now
                agent["lastSeenEpoch"] = now_ep
                agents[agent_id] = agent
                write_store(store)
                log_telemetry(cfg, {"type": "release_task", "agentId": agent_id, "taskId": item_id})
                self._send_store(store)
                return

            if action == "add":
                text = str(body.get("text") or "").strip()
                if not text:
                    self._send_json({"ok": False, "error": "text required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                priority = str(body.get("priority") or "P1").strip().upper()
                if priority not in {"P0", "P1", "P2"}:
                    priority = "P1"
                project = normalize_project_name(body.get("project") or FALLBACK_PROJECT)
                items.append(
                    {
                        "id": f"todo-{uuid4().hex[:10]}",
                        "text": text,
                        "priority": priority,
                        "project": project,
                        "status": "todo",
                        "order": next_order(items, "todo"),
                        "createdAt": now,
                        "updatedAt": now,
                    }
                )
                write_store(store)
                log_telemetry(cfg, {"type": "add_task", "project": project, "priority": priority})
                self._send_store(store)
                return

            if action == "add_iteration":
                project = normalize_project_name(body.get("project") or FALLBACK_PROJECT)
                title = str(body.get("title") or "").strip()
                if not title:
                    self._send_json({"ok": False, "error": "title required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                summary = str(body.get("summary") or "").strip()
                it_type = str(body.get("type") or "manual").strip() or "manual"
                source = str(body.get("source") or "manual").strip() or "manual"
                task_id = str(body.get("taskId") or "").strip()
                machine_by = str(body.get("machineBy") or "").strip()
                status_text = str(body.get("status") or "").strip()
                created = append_iteration(
                    iteration_store,
                    project=project,
                    it_type=it_type,
                    title=title,
                    summary=summary,
                    task_id=task_id,
                    machine_by=machine_by,
                    status=status_text,
                    source=source,
                )
                write_iteration_store(iteration_store)
                try:
                    sync_project_docs(project, items, iteration_store.get("items") or [])
                except Exception:
                    pass
                log_telemetry(cfg, {"type": "add_iteration", "project": project, "it_type": it_type, "source": source})
                self._send_json(
                    {
                        "ok": True,
                        "created": created,
                        "data": iteration_store,
                        "defaultProject": FALLBACK_PROJECT,
                    }
                )
                return

            if action == "set_status":
                item_id = str(body.get("id") or "").strip()
                status = str(body.get("status") or "").strip().lower()
                if status not in STATUSES:
                    self._send_json({"ok": False, "error": "invalid status"}, status=HTTPStatus.BAD_REQUEST)
                    return
                item = find_item(items, item_id)
                if not item:
                    self._send_json({"ok": False, "error": "item not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                current = str(item.get("status") or "todo").lower()
                # 用户侧 set_status 只允许 todo -> doing（开始执行）
                if current == status:
                    self._send_store(store)
                    return
                if not (current == "todo" and status == "doing"):
                    self._send_json(
                        {"ok": False, "error": "set_status only supports todo -> doing"},
                        status=HTTPStatus.BAD_REQUEST,
                    )
                    return
                item["status"] = status
                item["order"] = next_order(items, status)
                item["updatedAt"] = now
                write_store(store)
                log_telemetry(cfg, {"type": "set_status", "taskId": item_id, "from": current, "to": status, "project": item.get("project")})
                self._send_store(store)
                return

            if action == "request_done":
                item_id = str(body.get("id") or "").strip()
                item = find_item(items, item_id)
                if not item:
                    self._send_json({"ok": False, "error": "item not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                current = str(item.get("status") or "todo").lower()
                if current != "doing":
                    self._send_json({"ok": False, "error": "only doing item can request_done"}, status=HTTPStatus.BAD_REQUEST)
                    return
                item["status"] = "done_requested"
                item["order"] = next_order(items, "done_requested")
                item["doneRequestedAt"] = now
                item["updatedAt"] = now
                write_store(store)
                log_telemetry(cfg, {"type": "request_done", "taskId": item_id, "project": item.get("project")})
                self._send_store(store)
                return

            if action == "confirm_done":
                item_id = str(body.get("id") or "").strip()
                machine_by = str(body.get("machineBy") or "codex").strip() or "codex"
                item = find_item(items, item_id)
                if not item:
                    self._send_json({"ok": False, "error": "item not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                current = str(item.get("status") or "todo").lower()
                if current not in {"doing", "done_requested", "done"}:
                    self._send_json({"ok": False, "error": "confirm_done requires doing/done_requested/done"}, status=HTTPStatus.BAD_REQUEST)
                    return
                should_log = current != "done"
                if current != "done":
                    item["order"] = next_order(items, "done")
                apply_done_context_from_payload(item, body)
                item["status"] = "done"
                item["doneAt"] = now
                item["machineBy"] = machine_by
                item["machineAction"] = "confirm_done"
                item["machineAt"] = now
                item.pop("claimedBy", None)
                item.pop("claimedAt", None)
                item["updatedAt"] = now
                agent = agents.get(machine_by) if isinstance(agents.get(machine_by), dict) else {}
                agent["state"] = "idle"
                agent["taskId"] = ""
                agent["lastSeenAt"] = now
                agent["lastSeenEpoch"] = now_ep
                agents[machine_by] = agent
                write_store(store)
                if should_log:
                    project = normalize_project_name(item.get("project"))
                    snap: Dict[str, Any] = {}
                    try:
                        snap = git_snapshot(project)
                        if snap:
                            item["git"] = snap
                            item["updatedAt"] = now
                            write_store(store)
                    except Exception:
                        snap = {}
                    summary = build_done_summary(item, item_id, machine_by, snap=snap)
                    append_iteration(
                        iteration_store,
                        project=project,
                        it_type="done",
                        title=str(item.get("text") or item_id),
                        summary=summary,
                        task_id=item_id,
                        machine_by=machine_by,
                        status="done",
                        source="machine",
                    )
                    write_iteration_store(iteration_store)
                    try:
                        sync_project_docs(project, items, iteration_store.get("items") or [])
                    except Exception:
                        pass
                log_telemetry(cfg, {"type": "confirm_done", "taskId": item_id, "project": item.get("project"), "machineBy": machine_by})
                self._send_store(store)
                return

            if action == "request_rollback":
                item_id = str(body.get("id") or "").strip()
                item = find_item(items, item_id)
                if not item:
                    self._send_json({"ok": False, "error": "item not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                current = str(item.get("status") or "todo").lower()
                if current != "done":
                    self._send_json({"ok": False, "error": "only done item can request_rollback"}, status=HTTPStatus.BAD_REQUEST)
                    return
                item["status"] = "rollback_requested"
                item["order"] = next_order(items, "rollback_requested")
                item["rollbackRequestedAt"] = now
                item["updatedAt"] = now
                write_store(store)
                log_telemetry(cfg, {"type": "request_rollback", "taskId": item_id, "project": item.get("project")})
                self._send_store(store)
                return

            if action == "cancel_rollback_request":
                item_id = str(body.get("id") or "").strip()
                item = find_item(items, item_id)
                if not item:
                    self._send_json({"ok": False, "error": "item not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                current = str(item.get("status") or "todo").lower()
                if current != "rollback_requested":
                    self._send_json({"ok": False, "error": "cancel_rollback_request requires rollback_requested"}, status=HTTPStatus.BAD_REQUEST)
                    return
                item["status"] = "done"
                item["order"] = next_order(items, "done")
                item["rollbackRequestCanceledAt"] = now
                item["updatedAt"] = now
                write_store(store)
                log_telemetry(cfg, {"type": "cancel_rollback_request", "taskId": item_id, "project": item.get("project")})
                self._send_store(store)
                return

            if action == "confirm_rollback":
                item_id = str(body.get("id") or "").strip()
                machine_by = str(body.get("machineBy") or "codex").strip() or "codex"
                item = find_item(items, item_id)
                if not item:
                    self._send_json({"ok": False, "error": "item not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                current = str(item.get("status") or "todo").lower()
                if current != "rollback_requested":
                    self._send_json({"ok": False, "error": "confirm_rollback requires rollback_requested"}, status=HTTPStatus.BAD_REQUEST)
                    return
                item["status"] = "todo"
                item["order"] = next_order(items, "todo")
                item["rollbackCount"] = int(item.get("rollbackCount") or 0) + 1
                item["lastRollbackAt"] = now
                item["machineBy"] = machine_by
                item["machineAction"] = "confirm_rollback"
                item["machineAt"] = now
                item.pop("claimedBy", None)
                item.pop("claimedAt", None)
                item["updatedAt"] = now
                agent = agents.get(machine_by) if isinstance(agents.get(machine_by), dict) else {}
                agent["state"] = "idle"
                agent["taskId"] = ""
                agent["lastSeenAt"] = now
                agent["lastSeenEpoch"] = now_ep
                agents[machine_by] = agent
                write_store(store)
                project = normalize_project_name(item.get("project"))
                summary = f"任务 {item_id} 已由 {machine_by} 机器确认回滚到待办"
                append_iteration(
                    iteration_store,
                    project=project,
                    it_type="rollback",
                    title=str(item.get("text") or item_id),
                    summary=summary,
                    task_id=item_id,
                    machine_by=machine_by,
                    status="todo",
                    source="machine",
                )
                write_iteration_store(iteration_store)
                try:
                    sync_project_docs(project, items, iteration_store.get("items") or [])
                except Exception:
                    pass
                log_telemetry(cfg, {"type": "confirm_rollback", "taskId": item_id, "project": item.get("project"), "machineBy": machine_by})
                self._send_store(store)
                return

            if action == "capture_git":
                item_id = str(body.get("id") or "").strip()
                item = find_item(items, item_id)
                if not item:
                    self._send_json({"ok": False, "error": "item not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                project = normalize_project_name(item.get("project"))
                snap = git_snapshot(project)
                if not snap:
                    self._send_json({"ok": False, "error": f"no git repo for project {project}"}, status=HTTPStatus.BAD_REQUEST)
                    return
                item["git"] = snap
                item["updatedAt"] = now
                write_store(store)
                log_telemetry(cfg, {"type": "capture_git", "taskId": item_id, "project": project})
                self._send_store(store)
                return

            if action == "set_check":
                item_id = str(body.get("id") or "").strip()
                key = str(body.get("key") or "").strip()
                value = str(body.get("value") or "").strip()
                if key not in CHECK_KEYS:
                    self._send_json({"ok": False, "error": "invalid check key"}, status=HTTPStatus.BAD_REQUEST)
                    return
                if value not in TEST_STATUSES:
                    self._send_json({"ok": False, "error": "invalid check value"}, status=HTTPStatus.BAD_REQUEST)
                    return
                item = find_item(items, item_id)
                if not item:
                    self._send_json({"ok": False, "error": "item not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                checks = item.get("checks")
                if not isinstance(checks, dict):
                    checks = {}
                    item["checks"] = checks
                checks[key] = value
                item["updatedAt"] = now
                write_store(store)
                log_telemetry(cfg, {"type": "set_check", "taskId": item_id, "project": item.get("project"), "key": key, "value": value})
                self._send_store(store)
                return

            if action == "reorder":
                status = str(body.get("status") or "").strip().lower()
                ordered_ids = body.get("orderedIds")
                project = normalize_optional_project(body.get("project") or "")
                if status not in STATUSES:
                    self._send_json({"ok": False, "error": "invalid status"}, status=HTTPStatus.BAD_REQUEST)
                    return
                if not isinstance(ordered_ids, list):
                    self._send_json({"ok": False, "error": "orderedIds required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                target_items = [
                    x
                    for x in items
                    if str(x.get("status") or "").lower() == status
                    and (not project or normalize_project_name(x.get("project")) == project)
                ]
                current_ids = [str(x.get("id")) for x in target_items]
                incoming_ids = [str(x) for x in ordered_ids]
                if sorted(current_ids) != sorted(incoming_ids):
                    self._send_json(
                        {"ok": False, "error": "orderedIds must exactly match current status items"},
                        status=HTTPStatus.BAD_REQUEST,
                    )
                    return
                for idx, item_id in enumerate(incoming_ids):
                    item = find_item(items, item_id)
                    if not item:
                        continue
                    item["order"] = (idx + 1) * 10
                    item["updatedAt"] = now
                write_store(store)
                log_telemetry(cfg, {"type": "reorder", "status": status, "project": project or "__all__", "count": len(incoming_ids)})
                self._send_store(store)
                return

            if action == "update_text":
                item_id = str(body.get("id") or "").strip()
                text = str(body.get("text") or "").strip()
                if not text:
                    self._send_json({"ok": False, "error": "text required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                item = find_item(items, item_id)
                if not item:
                    self._send_json({"ok": False, "error": "item not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                item["text"] = text
                item["updatedAt"] = now
                write_store(store)
                log_telemetry(cfg, {"type": "update_text", "taskId": item_id, "project": item.get("project")})
                self._send_store(store)
                return

            if action == "set_project":
                item_id = str(body.get("id") or "").strip()
                project = str(body.get("project") or "").strip()
                if not project:
                    self._send_json({"ok": False, "error": "project required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                item = find_item(items, item_id)
                if not item:
                    self._send_json({"ok": False, "error": "item not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                item["project"] = normalize_project_name(project)
                item["updatedAt"] = now
                write_store(store)
                log_telemetry(cfg, {"type": "set_project", "taskId": item_id, "project": item.get("project")})
                self._send_store(store)
                return

            if action == "set_agent_alias":
                agent_id = str(body.get("agentId") or "").strip()
                if not agent_id:
                    self._send_json({"ok": False, "error": "agentId required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                alias = str(body.get("alias") or "").strip()
                alias_map = store.get("agentAliases")
                if not isinstance(alias_map, dict):
                    alias_map = {}
                    store["agentAliases"] = alias_map
                if alias:
                    alias_map[agent_id] = alias
                else:
                    alias_map.pop(agent_id, None)
                write_store(store)
                log_telemetry(cfg, {"type": "set_agent_alias", "agentId": agent_id})
                self._send_store(store)
                return

            if action == "set_agent_project":
                agent_id = str(body.get("agentId") or "").strip()
                if not agent_id:
                    self._send_json({"ok": False, "error": "agentId required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                project = normalize_optional_project(body.get("project") or "")
                project_map = store.get("agentProjects")
                if not isinstance(project_map, dict):
                    project_map = {}
                    store["agentProjects"] = project_map
                if project:
                    project_map[agent_id] = project
                else:
                    project_map.pop(agent_id, None)
                write_store(store)
                log_telemetry(cfg, {"type": "set_agent_project", "agentId": agent_id, "project": project})
                self._send_store(store)
                return

            if action == "delete":
                item_id = str(body.get("id") or "").strip()
                before = len(items)
                store["items"] = [x for x in items if str(x.get("id")) != item_id]
                if len(store["items"]) == before:
                    self._send_json({"ok": False, "error": "item not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                write_store(store)
                log_telemetry(cfg, {"type": "delete_task", "taskId": item_id})
                self._send_store(store)
                return

            self._send_json({"ok": False, "error": f"unsupported action: {action}"}, status=HTTPStatus.BAD_REQUEST)


def main() -> None:
    host = os.environ.get("PM_HOST") or os.environ.get("LIVE_VIEW_HOST") or "127.0.0.1"
    port = int(os.environ.get("PM_PORT") or os.environ.get("LIVE_VIEW_PORT") or "8765")
    # One-time migration: if you used the older PM board under coach-feishu-suite/docs,
    # copy its stores into the new global DATA_DIR. Keep the old files intact.
    try:
        legacy_dir = Path.home() / "coach-feishu-suite" / "docs"
        legacy_map = {
            "project-todos.json": TODOS_PATH,
            "project-iterations.json": ITERATIONS_PATH,
            "pm-config.json": CONFIG_PATH,
            "telemetry-events.jsonl": TELEMETRY_PATH,
        }
        for name, dst in legacy_map.items():
            src = legacy_dir / name
            if dst.exists():
                continue
            if not src.exists():
                continue
            try:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
            except Exception:
                continue
    except Exception:
        pass
    with _LOCK:
        if not TODOS_PATH.exists():
            write_store(default_store())
        if not ITERATIONS_PATH.exists():
            write_iteration_store(default_iteration_store())
        if not CONFIG_PATH.exists():
            write_config(default_config())
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Live server running on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
