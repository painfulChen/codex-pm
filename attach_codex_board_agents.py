#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


HOME = Path.home()
REPO = Path(__file__).resolve().parent
BOARD_AGENT = REPO / "board_agent.py"
DATA_DIR = Path(os.environ.get("PM_DATA_DIR", str(HOME / ".clawdbot" / "pm"))).expanduser()
DEFAULT_CONFIG_PATH = DATA_DIR / "pm-attach.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_attach_config(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def write_attach_config(path: Path, cfg: dict) -> None:
    cfg = dict(cfg or {})
    cfg.setdefault("version", 1)
    cfg["updatedAt"] = now_iso()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run(cmd: list[str]) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return p.stdout or ""


def list_codex_sessions() -> list[tuple[int, str]]:
    out = run(["ps", "-ax", "-o", "pid=,tty=,command="])
    rows: list[tuple[int, str]] = []
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        if "node /Users/Zhuanz/.npm-global/bin/codex" not in s:
            continue
        m = re.match(r"^\s*(\d+)\s+(\S+)\s+(.+)$", line)
        if not m:
            continue
        pid = int(m.group(1))
        tty = m.group(2)
        rows.append((pid, tty))
    return rows


def cwd_of_pid(pid: int) -> Path | None:
    out = run(["lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"])
    for ln in out.splitlines():
        if ln.startswith("n"):
            p = ln[1:].strip()
            if p:
                return Path(p)
    return None


def infer_project(cwd: Path | None, default_project: str) -> str:
    if cwd is None:
        return default_project
    if cwd == HOME:
        return HOME.name or default_project
    cur = cwd
    while True:
        if (cur / ".git").exists():
            return cur.name
        if cur == cur.parent:
            break
        if str(cur).startswith(str(HOME)):
            cur = cur.parent
            continue
        break
    if cwd.name and cwd != HOME:
        return cwd.name
    return default_project


def list_agent_procs() -> dict[str, list[int]]:
    out = run(["ps", "-ax", "-o", "pid=,command="])
    result: dict[str, list[int]] = {}
    for line in out.splitlines():
        # board_agent.py 会 exec 到 board_cli.py，因此两种命令行都要识别，确保重复运行本脚本不会反复拉起 daemon。
        if ("docs/board_agent.py" not in line) and ("docs/board_cli.py daemon" not in line):
            continue
        m = re.search(r"--agent\s+([^\s]+)", line)
        p = re.match(r"^\s*(\d+)\s+(.+)$", line)
        if not m or not p:
            continue
        aid = m.group(1).strip()
        pid = int(p.group(1))
        result.setdefault(aid, []).append(pid)
    return result


def start_agent(
    agent_id: str,
    title: str,
    project: str,
    agent_cwd: Path | None,
    observe_only: bool,
    offline: bool,
    interval: int,
    claim_interval: int,
) -> int:
    log_dir = REPO / "logs"
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / f"board-agent-{agent_id}.log"
    cmd = [
        sys.executable,
        str(BOARD_AGENT),
        "--agent",
        agent_id,
        "--title",
        title,
        "--project",
        project,
        "--interval",
        str(interval),
        "--claim-interval",
        str(claim_interval),
        "--cwd",
        str(agent_cwd or HOME),
    ]
    if observe_only:
        cmd.append("--observe-only")
    if offline:
        cmd.append("--offline")
    with log_file.open("a", encoding="utf-8") as fh:
        proc = subprocess.Popen(cmd, cwd=str(REPO), stdout=fh, stderr=subprocess.STDOUT, start_new_session=True)
    return proc.pid


def main() -> int:
    ap = argparse.ArgumentParser(description="Attach running codex sessions to board_agent daemons")
    ap.add_argument("--observe-only", action="store_true", help="Do not auto-claim tasks")
    ap.add_argument("--managed", action="store_true", help="Auto-claim tasks (overrides --observe-only)")
    ap.add_argument("--restart", action="store_true", help="Restart existing attached daemons")
    ap.add_argument("--offline", action="store_true", help="Force offline mode (no localhost HTTP)")
    ap.add_argument("--interval", type=int, default=15)
    ap.add_argument("--claim-interval", type=int, default=20)
    ap.add_argument("--default-project", default="")
    ap.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="persisted tty bindings json")
    ap.add_argument("--save-bindings", action="store_true", help="persist tty bindings to --config")
    ap.add_argument("--clear-bindings", action="store_true", help="clear persisted tty bindings in --config")
    ap.add_argument(
        "--tty-project",
        action="append",
        default=[],
        help="Bind tty to project, format: ttys001:TrendRadar",
    )
    ap.add_argument(
        "--tty-title",
        action="append",
        default=[],
        help="Bind tty to title, format: ttys001:终端B-守护",
    )
    args = ap.parse_args()

    cfg_path = Path(str(args.config or str(DEFAULT_CONFIG_PATH))).expanduser()
    cfg = read_attach_config(cfg_path)
    cfg_tty_project = cfg.get("ttyProject") if isinstance(cfg.get("ttyProject"), dict) else {}
    cfg_tty_title = cfg.get("ttyTitle") if isinstance(cfg.get("ttyTitle"), dict) else {}
    cfg_default_project = str(cfg.get("defaultProject") or "").strip()
    default_project = (str(args.default_project or "").strip() or cfg_default_project or "coach-feishu-suite")

    observe_only = True
    if args.managed:
        observe_only = False
    elif args.observe_only:
        observe_only = True

    sessions = list_codex_sessions()
    existing = list_agent_procs()
    tty_bind: dict[str, str] = {}
    tty_title_bind: dict[str, str] = {}
    if isinstance(cfg_tty_project, dict):
        for t, p in cfg_tty_project.items():
            tt = str(t or "").strip()
            pp = str(p or "").strip()
            if tt and pp:
                tty_bind[tt] = pp
    if isinstance(cfg_tty_title, dict):
        for t, title in cfg_tty_title.items():
            tt = str(t or "").strip()
            lab = str(title or "").strip()
            if tt and lab:
                tty_title_bind[tt] = lab
    for raw in args.tty_project:
        if ":" not in raw:
            continue
        tty, proj = raw.split(":", 1)
        t = tty.strip()
        p = proj.strip()
        if t and p:
            tty_bind[t] = p
    for raw in args.tty_title:
        if ":" not in raw:
            continue
        tty, title = raw.split(":", 1)
        t = tty.strip()
        label = title.strip()
        if t and label:
            tty_title_bind[t] = label

    if args.clear_bindings:
        write_attach_config(cfg_path, {"ttyProject": {}, "ttyTitle": {}, "defaultProject": default_project})
    elif args.save_bindings:
        write_attach_config(
            cfg_path,
            {
                "ttyProject": tty_bind,
                "ttyTitle": tty_title_bind,
                "defaultProject": default_project,
            },
        )

    attached = []
    skipped = []
    for pid, tty in sessions:
        cwd = cwd_of_pid(pid)
        project = tty_bind.get(tty) or infer_project(cwd, default_project)
        safe_tty = tty.replace("/", "_")
        agent_id = f"codex-{safe_tty}"
        title = tty_title_bind.get(tty) or f"Codex {tty}"
        existing_pids = existing.get(agent_id, [])
        if existing_pids and not args.restart:
            skipped.append({"agentId": agent_id, "reason": "already_running", "pids": existing_pids, "project": project})
            continue
        if existing_pids and args.restart:
            for old_pid in existing_pids:
                try:
                    os.kill(old_pid, 15)
                except Exception:
                    pass
        new_pid = start_agent(agent_id, title, project, cwd, observe_only, bool(args.offline), args.interval, args.claim_interval)
        attached.append(
            {
                "agentId": agent_id,
                "title": title,
                "project": project,
                "cwd": str(cwd) if cwd else "",
                "pid": new_pid,
                "observeOnly": observe_only,
            }
        )

    print(json.dumps({"sessions": len(sessions), "attached": attached, "skipped": skipped}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
