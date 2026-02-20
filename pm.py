#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


REPO = Path("/Users/Zhuanz/codex-pm")
PLIST = Path.home() / "Library" / "LaunchAgents" / "com.zhuanz.codex-pm.plist"
LABEL = "com.zhuanz.codex-pm"
URL = "http://127.0.0.1:8765/pm"
LEGACY_LABEL = "com.zhuanz.coach-live-viewer"
LEGACY_PLIST = Path.home() / "Library" / "LaunchAgents" / "com.zhuanz.coach-live-viewer.plist"
DATA_DIR = Path(os.environ.get("PM_DATA_DIR", str(Path.home() / ".clawdbot" / "pm"))).expanduser()
STORE_JSON = DATA_DIR / "project-todos.json"


def sh(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, check=check)


def uid() -> str:
    return str(os.getuid())


def domain_label() -> str:
    return f"gui/{uid()}/{LABEL}"


def is_loaded() -> bool:
    # launchctl print returns non-zero when missing.
    p = sh(["launchctl", "print", domain_label()])
    return p.returncode == 0


def is_listening() -> bool:
    p = sh(["lsof", "-nP", "-iTCP:8765", "-sTCP:LISTEN"])
    return p.returncode == 0 and "LISTEN" in (p.stdout or "")


def start_service() -> None:
    if not PLIST.exists():
        raise RuntimeError(f"plist not found: {PLIST}")
    # Avoid port conflicts with the legacy PM agent.
    try:
        sh(["launchctl", "bootout", f"gui/{uid()}/{LEGACY_LABEL}"], check=False)
    except Exception:
        pass
    if is_loaded():
        # Kickstart will restart if needed.
        sh(["launchctl", "kickstart", "-k", domain_label()])
        return
    sh(["launchctl", "bootstrap", f"gui/{uid()}", str(PLIST)], check=False)
    sh(["launchctl", "kickstart", "-k", domain_label()], check=False)


def stop_service() -> None:
    # Bootout unloads the agent (full stop). Start will bootstrap again.
    sh(["launchctl", "bootout", domain_label()], check=False)


def attach_agents(observe_only: bool, restart: bool) -> None:
    script = REPO / "attach_codex_board_agents.py"
    if not script.exists():
        raise RuntimeError(f"missing: {script}")
    cmd = [sys.executable, str(script), "--default-project", "coach-feishu-suite"]
    if restart:
        cmd.append("--restart")
    if observe_only:
        cmd.append("--observe-only")
    else:
        cmd.append("--managed")
    sh(cmd, check=False)


def run_board_cli(args: list[str]) -> subprocess.CompletedProcess:
    script = REPO / "board_cli.py"
    if not script.exists():
        raise RuntimeError(f"missing: {script}")
    cmd = [sys.executable, str(script), *args]
    return sh(cmd, check=False)


def open_board(chrome: bool) -> None:
    if chrome:
        sh(["open", "-a", "Google Chrome", URL], check=False)
    else:
        sh(["open", URL], check=False)


def read_store() -> dict:
    try:
        return json.loads(STORE_JSON.read_text(encoding="utf-8"))
    except Exception:
        return {}


def print_status() -> None:
    loaded = is_loaded()
    listening = is_listening()
    store = read_store()
    agents = store.get("agents") if isinstance(store.get("agents"), dict) else {}
    now_ep = int(datetime.now(timezone.utc).timestamp())
    online = 0
    for payload in agents.values():
        if not isinstance(payload, dict):
            continue
        seen = int(payload.get("lastSeenEpoch") or 0)
        if seen and now_ep - seen <= 180:
            online += 1
    total = len(agents) if isinstance(agents, dict) else 0

    print(f"service_loaded: {loaded}")
    print(f"port_listening: {listening}")
    print(f"agents_online: {online}/{total}")
    print(f"url: {URL}")


def main() -> int:
    ap = argparse.ArgumentParser(description="pm: local Codex project management board helper")
    sub = ap.add_subparsers(dest="cmd")

    p_start = sub.add_parser("start", help="start board service + attach agents + open page")
    p_start.add_argument("--managed", action="store_true", help="allow attached agents to auto-claim tasks")
    p_start.add_argument("--no-attach", action="store_true", help="do not auto attach codex sessions")
    p_start.add_argument("--no-open", action="store_true", help="do not open browser")
    p_start.add_argument("--chrome", action="store_true", help="open with Google Chrome")

    p_stop = sub.add_parser("stop", help="stop (bootout) board service")

    p_status = sub.add_parser("status", help="print service status")

    p_open = sub.add_parser("open", help="open board page")
    p_open.add_argument("--chrome", action="store_true", help="open with Google Chrome")

    p_attach = sub.add_parser("attach", help="attach running codex sessions to board_agent daemons")
    p_attach.add_argument("--managed", action="store_true", help="auto-claim tasks")
    p_attach.add_argument("--restart", action="store_true", help="restart existing attached daemons")
    p_attach.add_argument("--save-bindings", action="store_true", help="persist tty bindings to config (attach script)")
    p_attach.add_argument("--config", default="", help="attach config path override")
    p_attach.add_argument(
        "--tty-project",
        action="append",
        default=[],
        help="Bind tty to project, format: ttys001:TrendRadar",
    )
    p_attach.add_argument(
        "--tty-title",
        action="append",
        default=[],
        help="Bind tty to title, format: ttys001:终端B-守护",
    )

    p_ls = sub.add_parser("ls", help="list tasks (offline by default)")
    p_ls.add_argument("--project", default="", help="filter by project")
    p_ls.add_argument("--status", default="", help="filter by status")
    p_ls.add_argument("--http", action="store_true", help="use HTTP instead of offline store read")

    p_add = sub.add_parser("add", help="add a task (offline by default)")
    p_add.add_argument("text", help="task text")
    p_add.add_argument("--project", default="", help="task project")
    p_add.add_argument("--priority", default="P1", help="P0/P1/P2")
    p_add.add_argument("--http", action="store_true", help="use HTTP instead of offline store write")

    p_begin = sub.add_parser("begin", help="todo -> doing")
    p_begin.add_argument("id", help="task id")
    p_begin.add_argument("--http", action="store_true")

    p_done_req = sub.add_parser("done-req", help="doing -> done_requested")
    p_done_req.add_argument("id", help="task id")
    p_done_req.add_argument("--http", action="store_true")

    p_done = sub.add_parser("done", help="machine confirm done")
    p_done.add_argument("id", help="task id")
    p_done.add_argument("--machine", default="", help="machine/agent id (default: BOARD_AGENT_ID or codex-ttysXXX)")
    p_done.add_argument("--http", action="store_true")

    p_rb_req = sub.add_parser("rb-req", help="done -> rollback_requested")
    p_rb_req.add_argument("id", help="task id")
    p_rb_req.add_argument("--http", action="store_true")

    p_rb_cancel = sub.add_parser("rb-cancel", help="rollback_requested -> done")
    p_rb_cancel.add_argument("id", help="task id")
    p_rb_cancel.add_argument("--http", action="store_true")

    p_rb = sub.add_parser("rb", help="machine confirm rollback (rollback_requested -> todo)")
    p_rb.add_argument("id", help="task id")
    p_rb.add_argument("--machine", default="", help="machine/agent id")
    p_rb.add_argument("--http", action="store_true")

    p_it_add = sub.add_parser("it-add", help="add iteration log (sync docs)")
    p_it_add.add_argument("--project", default="", help="project")
    p_it_add.add_argument("--type", default="manual", help="manual/fix/optimize/architecture/milestone/done/rollback")
    p_it_add.add_argument("--title", required=True, help="title")
    p_it_add.add_argument("--summary", default="", help="summary")
    p_it_add.add_argument("--http", action="store_true")

    p_it_ls = sub.add_parser("it-ls", help="list iterations")
    p_it_ls.add_argument("--project", default="", help="project")
    p_it_ls.add_argument("--limit", type=int, default=30, help="limit")
    p_it_ls.add_argument("--http", action="store_true")

    args = ap.parse_args()
    if args.cmd == "start":
        start_service()
        if not args.no_attach:
            attach_agents(observe_only=(not args.managed), restart=True)
        if not args.no_open:
            open_board(chrome=bool(args.chrome))
        print_status()
        return 0
    if args.cmd == "stop":
        stop_service()
        print_status()
        return 0
    if args.cmd == "status":
        print_status()
        return 0
    if args.cmd == "open":
        open_board(chrome=bool(args.chrome))
        return 0
    if args.cmd == "attach":
        script = REPO / "attach_codex_board_agents.py"
        cmd = [sys.executable, str(script), "--default-project", "coach-feishu-suite"]
        if bool(args.restart):
            cmd.append("--restart")
        if bool(args.managed):
            cmd.append("--managed")
        else:
            cmd.append("--observe-only")
        if args.config:
            cmd.extend(["--config", str(args.config)])
        for x in args.tty_project or []:
            cmd.extend(["--tty-project", x])
        for x in args.tty_title or []:
            cmd.extend(["--tty-title", x])
        if bool(args.save_bindings):
            cmd.append("--save-bindings")
        sh(cmd, check=False)
        return 0
    if args.cmd == "ls":
        cmd = ["list"]
        if args.project:
            cmd.extend(["--project", args.project])
        if args.status:
            cmd.extend(["--status", args.status])
        if not args.http:
            cmd.append("--offline")
        p = run_board_cli(cmd)
        sys.stdout.write(p.stdout or "")
        sys.stderr.write(p.stderr or "")
        return int(p.returncode or 0)
    if args.cmd == "add":
        cmd = ["add", "--text", args.text, "--priority", args.priority, "--project", args.project]
        if not args.http:
            cmd.append("--offline")
        p = run_board_cli(cmd)
        sys.stdout.write(p.stdout or "")
        sys.stderr.write(p.stderr or "")
        return int(p.returncode or 0)
    if args.cmd == "begin":
        cmd = ["set-status", "--id", args.id, "--status", "doing"]
        if not args.http:
            cmd.append("--offline")
        p = run_board_cli(cmd)
        sys.stdout.write(p.stdout or "")
        sys.stderr.write(p.stderr or "")
        return int(p.returncode or 0)
    if args.cmd == "done-req":
        cmd = ["request-done", "--id", args.id]
        if not args.http:
            cmd.append("--offline")
        p = run_board_cli(cmd)
        sys.stdout.write(p.stdout or "")
        sys.stderr.write(p.stderr or "")
        return int(p.returncode or 0)
    if args.cmd == "done":
        cmd = ["confirm-done", "--id", args.id]
        if args.machine:
            cmd.extend(["--agent", args.machine])
        if not args.http:
            cmd.append("--offline")
        p = run_board_cli(cmd)
        sys.stdout.write(p.stdout or "")
        sys.stderr.write(p.stderr or "")
        return int(p.returncode or 0)
    if args.cmd == "rb-req":
        cmd = ["request-rollback", "--id", args.id]
        if not args.http:
            cmd.append("--offline")
        p = run_board_cli(cmd)
        sys.stdout.write(p.stdout or "")
        sys.stderr.write(p.stderr or "")
        return int(p.returncode or 0)
    if args.cmd == "rb-cancel":
        cmd = ["cancel-rollback-request", "--id", args.id]
        if not args.http:
            cmd.append("--offline")
        p = run_board_cli(cmd)
        sys.stdout.write(p.stdout or "")
        sys.stderr.write(p.stderr or "")
        return int(p.returncode or 0)
    if args.cmd == "rb":
        cmd = ["confirm-rollback", "--id", args.id]
        if args.machine:
            cmd.extend(["--agent", args.machine])
        if not args.http:
            cmd.append("--offline")
        p = run_board_cli(cmd)
        sys.stdout.write(p.stdout or "")
        sys.stderr.write(p.stderr or "")
        return int(p.returncode or 0)
    if args.cmd == "it-add":
        cmd = [
            "add-iteration",
            "--project",
            args.project,
            "--type",
            args.type,
            "--title",
            args.title,
            "--summary",
            args.summary,
            "--source",
            "manual",
        ]
        if not args.http:
            cmd.append("--offline")
        p = run_board_cli(cmd)
        sys.stdout.write(p.stdout or "")
        sys.stderr.write(p.stderr or "")
        return int(p.returncode or 0)
    if args.cmd == "it-ls":
        cmd = ["list-iterations", "--project", args.project, "--limit", str(args.limit)]
        if not args.http:
            cmd.append("--offline")
        p = run_board_cli(cmd)
        sys.stdout.write(p.stdout or "")
        sys.stderr.write(p.stderr or "")
        return int(p.returncode or 0)
    ap.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
