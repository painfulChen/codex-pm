#!/usr/bin/env python3
from __future__ import annotations

"""
Offline board admin helper (no HTTP).

Why: In some restricted environments (e.g. sandboxed agents), localhost HTTP may
be blocked. This script mutates the same on-disk stores as live_server.py and
reuses its sync logic to keep:
  - project-todos.json
  - project-iterations.json
  - docs/project-live.md + ARCHITECTURE.md (AUTO section)
in sync.
"""

import argparse
import contextlib
import json
from typing import Any, Dict

import live_server as srv


def _print_json(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def _find_item(items: list[Dict[str, Any]], item_id: str) -> Dict[str, Any] | None:
    for x in items:
        if str(x.get("id")) == item_id:
            return x
    return None


def _lock():
    lk = getattr(srv, "file_lock", None)
    if callable(lk):
        try:
            return lk()
        except Exception:
            return contextlib.nullcontext()
    return contextlib.nullcontext()


def cmd_set_status(args: argparse.Namespace) -> int:
    with _lock():
        item_id = str(args.id or "").strip()
        status = str(args.status or "").strip().lower()
        if not item_id or not status:
            raise SystemExit("id and status required")
        if status not in getattr(srv, "STATUSES", {"todo", "doing", "done_requested", "rollback_requested", "done"}):
            raise SystemExit("invalid status")

        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item = _find_item(items, item_id)
        if not item:
            raise SystemExit(f"item not found: {item_id}")
        current = str(item.get("status") or "todo").lower()
        if current == status:
            return 0
        if not (current == "todo" and status == "doing"):
            raise SystemExit(f"set-status only supports todo -> doing (current={current} target={status})")
        now = srv.now_iso()
        item["status"] = status
        item["order"] = srv.next_order(items, status)
        item["updatedAt"] = now
        srv.write_store(store)
        return 0


def cmd_request_done(args: argparse.Namespace) -> int:
    with _lock():
        item_id = str(args.id or "").strip()
        if not item_id:
            raise SystemExit("id required")

        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item = _find_item(items, item_id)
        if not item:
            raise SystemExit(f"item not found: {item_id}")
        current = str(item.get("status") or "todo").lower()
        if current != "doing":
            raise SystemExit(f"only doing item can request_done (current={current})")
        now = srv.now_iso()
        item["status"] = "done_requested"
        item["order"] = srv.next_order(items, "done_requested")
        item["doneRequestedAt"] = now
        item["updatedAt"] = now
        srv.write_store(store)
        return 0


def cmd_request_rollback(args: argparse.Namespace) -> int:
    with _lock():
        item_id = str(args.id or "").strip()
        if not item_id:
            raise SystemExit("id required")
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item = _find_item(items, item_id)
        if not item:
            raise SystemExit(f"item not found: {item_id}")
        current = str(item.get("status") or "todo").lower()
        if current != "done":
            raise SystemExit(f"only done item can request_rollback (current={current})")
        now = srv.now_iso()
        item["status"] = "rollback_requested"
        item["order"] = srv.next_order(items, "rollback_requested")
        item["rollbackRequestedAt"] = now
        item["updatedAt"] = now
        srv.write_store(store)
        return 0


def cmd_cancel_rollback_request(args: argparse.Namespace) -> int:
    with _lock():
        item_id = str(args.id or "").strip()
        if not item_id:
            raise SystemExit("id required")
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item = _find_item(items, item_id)
        if not item:
            raise SystemExit(f"item not found: {item_id}")
        current = str(item.get("status") or "todo").lower()
        if current != "rollback_requested":
            raise SystemExit(f"cancel-rollback-request requires rollback_requested (current={current})")
        now = srv.now_iso()
        item["status"] = "done"
        item["order"] = srv.next_order(items, "done")
        item["rollbackRequestCanceledAt"] = now
        item["updatedAt"] = now
        srv.write_store(store)
        return 0


def cmd_list(args: argparse.Namespace) -> int:
    project = str(args.project or "").strip()
    status = str(args.status or "").strip().lower()
    with _lock():
        store = srv.read_store()
    items = store.get("items") if isinstance(store.get("items"), list) else []
    out = []
    for item in items:
        if project and str(item.get("project") or "").strip() != project:
            continue
        if status and str(item.get("status") or "").strip().lower() != status:
            continue
        out.append(
            {
                "id": item.get("id"),
                "project": item.get("project"),
                "status": item.get("status"),
                "priority": item.get("priority"),
                "claimedBy": item.get("claimedBy"),
                "text": item.get("text"),
            }
        )
    _print_json({"count": len(out), "items": out, "updatedAt": store.get("updatedAt")})
    return 0


def cmd_list_iterations(args: argparse.Namespace) -> int:
    project = str(args.project or "").strip()
    limit = int(args.limit or 50)
    with _lock():
        data = srv.read_iteration_store()
    items = data.get("items") if isinstance(data.get("items"), list) else []
    if project:
        items = [x for x in items if str(x.get("project") or "").strip() == project]
    items.sort(key=lambda x: str(x.get("createdAt") or ""), reverse=True)
    if limit > 0:
        items = items[:limit]
    _print_json({"count": len(items), "items": items, "updatedAt": data.get("updatedAt")})
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    """
    Offline equivalent of:
      - claim_task (optional) + set_status(todo->doing)

    Note: In the "board governance" model, starting is a user action. This helper
    exists for restricted environments where localhost HTTP is blocked; treat it
    as an explicit user-requested action.
    """
    with _lock():
        item_id = str(args.id or "").strip()
        agent = str(args.agent or "").strip() or "codex"
        if not item_id:
            raise SystemExit("id required")
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item = _find_item(items, item_id)
        if not item:
            raise SystemExit(f"item not found: {item_id}")
        current = str(item.get("status") or "todo").lower()
        if current != "todo":
            raise SystemExit(f"start requires todo (current={current})")
        now = srv.now_iso()
        item["status"] = "doing"
        item["order"] = srv.next_order(items, "doing")
        item["claimedBy"] = agent
        item["claimedAt"] = now
        item["updatedAt"] = now
        srv.write_store(store)
        return 0


def cmd_set_agent_project(args: argparse.Namespace) -> int:
    agent_id = str(args.agent_id or "").strip()
    project = str(args.project or "").strip()
    if not agent_id:
        raise SystemExit("agent-id required")
    with _lock():
        store = srv.read_store()
        overrides = store.get("agentProjects")
        if not isinstance(overrides, dict):
            overrides = {}
            store["agentProjects"] = overrides
        if project:
            overrides[agent_id] = project
        else:
            overrides.pop(agent_id, None)
        srv.write_store(store)
    return 0


def cmd_confirm_done(args: argparse.Namespace) -> int:
    item_id = str(args.id or "").strip()
    machine_by = str(args.machine_by or "").strip() or "codex"
    if not item_id:
        raise SystemExit("id required")

    with _lock():
        store = srv.read_store()
        iteration_store = srv.read_iteration_store()
        cfg = srv.read_config()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        agents = store.get("agents") if isinstance(store.get("agents"), dict) else {}

        item = _find_item(items, item_id)
        if not item:
            raise SystemExit(f"item not found: {item_id}")

        now = srv.now_iso()
        now_ep = srv.now_epoch()
        current = str(item.get("status") or "todo").lower()
        if current not in {"doing", "done_requested", "done"}:
            raise SystemExit(f"confirm_done requires doing/done_requested/done (current={current})")

        should_log = current != "done"
        if current != "done":
            item["order"] = srv.next_order(items, "done")
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
        store["agents"] = agents
        srv.write_store(store)

        if should_log:
            project = srv.normalize_project_name(item.get("project"))
            summary = f"任务 {item_id} 已由 {machine_by} 机器确认完成"
            try:
                snap = srv.git_snapshot(project)
                if snap:
                    item["git"] = snap
                    item["updatedAt"] = now
                    srv.write_store(store)
                    head = snap.get("commitShort") or (snap.get("commit") or "")[:8]
                    br = snap.get("branch") or "-"
                    summary += f"（git: {br}@{head}{'*' if snap.get('dirty') else ''} files={snap.get('changedCount', 0)} tests={item.get('checks', {}).get('tests', 'unknown')}）"
            except Exception:
                pass

            srv.append_iteration(
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
            srv.write_iteration_store(iteration_store)
            try:
                srv.sync_project_docs(project, items, iteration_store.get("items") or [])
            except Exception:
                pass

        srv.log_telemetry(cfg, {"type": "confirm_done_offline", "taskId": item_id, "project": item.get("project"), "machineBy": machine_by})
        return 0


def cmd_confirm_rollback(args: argparse.Namespace) -> int:
    item_id = str(args.id or "").strip()
    machine_by = str(args.machine_by or "").strip() or "codex"
    if not item_id:
        raise SystemExit("id required")

    with _lock():
        store = srv.read_store()
        iteration_store = srv.read_iteration_store()
        cfg = srv.read_config()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        agents = store.get("agents") if isinstance(store.get("agents"), dict) else {}

        item = _find_item(items, item_id)
        if not item:
            raise SystemExit(f"item not found: {item_id}")
        current = str(item.get("status") or "todo").lower()
        if current != "rollback_requested":
            raise SystemExit(f"confirm-rollback requires rollback_requested (current={current})")

        now = srv.now_iso()
        now_ep = srv.now_epoch()
        item["status"] = "todo"
        item["order"] = srv.next_order(items, "todo")
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
        store["agents"] = agents
        srv.write_store(store)

        project = srv.normalize_project_name(item.get("project"))
        summary = f"任务 {item_id} 已由 {machine_by} 机器确认回滚到待办"
        srv.append_iteration(
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
        srv.write_iteration_store(iteration_store)
        try:
            srv.sync_project_docs(project, items, iteration_store.get("items") or [])
        except Exception:
            pass
        srv.log_telemetry(cfg, {"type": "confirm_rollback_offline", "taskId": item_id, "project": item.get("project"), "machineBy": machine_by})
        return 0


def cmd_add(args: argparse.Namespace) -> int:
    text = str(args.text or "").strip()
    if not text:
        raise SystemExit("text required")
    priority = str(args.priority or "P1").strip().upper()
    if priority not in {"P0", "P1", "P2"}:
        priority = "P1"
    project = srv.normalize_project_name(args.project)
    with _lock():
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        now = srv.now_iso()
        items.append(
            {
                "id": f"todo-{srv.uuid4().hex[:10]}",
                "text": text,
                "priority": priority,
                "project": project,
                "status": "todo",
                "order": srv.next_order(items, "todo"),
                "createdAt": now,
                "updatedAt": now,
            }
        )
        store["items"] = items
        srv.write_store(store)
        return 0


def cmd_update_text(args: argparse.Namespace) -> int:
    item_id = str(args.id or "").strip()
    text = str(args.text or "").strip()
    if not item_id or not text:
        raise SystemExit("id and text required")
    with _lock():
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item = _find_item(items, item_id)
        if not item:
            raise SystemExit(f"item not found: {item_id}")
        now = srv.now_iso()
        item["text"] = text
        item["updatedAt"] = now
        srv.write_store(store)
        return 0


def cmd_set_project(args: argparse.Namespace) -> int:
    item_id = str(args.id or "").strip()
    project = str(args.project or "").strip()
    if not item_id or not project:
        raise SystemExit("id and project required")
    with _lock():
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item = _find_item(items, item_id)
        if not item:
            raise SystemExit(f"item not found: {item_id}")
        now = srv.now_iso()
        item["project"] = srv.normalize_project_name(project)
        item["updatedAt"] = now
        srv.write_store(store)
        return 0


def cmd_delete(args: argparse.Namespace) -> int:
    item_id = str(args.id or "").strip()
    if not item_id:
        raise SystemExit("id required")
    with _lock():
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        before = len(items)
        store["items"] = [x for x in items if str(x.get("id")) != item_id]
        if len(store["items"]) == before:
            raise SystemExit(f"item not found: {item_id}")
        srv.write_store(store)
        return 0


def cmd_cleanup_agents(args: argparse.Namespace) -> int:
    with _lock():
        store = srv.read_store()
        agents = store.get("agents") if isinstance(store.get("agents"), dict) else {}
        ttl = int(getattr(srv, "AGENT_TTL_SEC", 180))
        max_age = int(args.max_age_sec or ttl)
        if max_age < ttl:
            max_age = ttl
        cutoff = srv.now_epoch() - max_age
        stale = []
        for aid, payload in list(agents.items()):
            if not isinstance(payload, dict):
                stale.append(aid)
                continue
            seen = int(payload.get("lastSeenEpoch") or 0)
            if not seen or seen < cutoff:
                stale.append(aid)
        for aid in stale:
            agents.pop(aid, None)
        store["agents"] = agents
        srv.write_store(store)
        return 0


def cmd_set_agent_alias(args: argparse.Namespace) -> int:
    agent_id = str(args.agent_id or "").strip()
    alias = str(args.alias or "").strip()
    if not agent_id:
        raise SystemExit("agent-id required")
    with _lock():
        store = srv.read_store()
        aliases = store.get("agentAliases")
        if not isinstance(aliases, dict):
            aliases = {}
            store["agentAliases"] = aliases
        if alias:
            aliases[agent_id] = alias
        else:
            aliases.pop(agent_id, None)
        srv.write_store(store)
        return 0


def cmd_set_check(args: argparse.Namespace) -> int:
    item_id = str(args.id or "").strip()
    key = str(args.key or "").strip()
    value = str(args.value or "").strip()
    if not item_id or not key:
        raise SystemExit("id and key required")
    with _lock():
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item = _find_item(items, item_id)
        if not item:
            raise SystemExit(f"item not found: {item_id}")
        checks = item.get("checks")
        if not isinstance(checks, dict):
            checks = {}
            item["checks"] = checks
        checks[key] = value
        item["updatedAt"] = srv.now_iso()
        srv.write_store(store)
        return 0


def cmd_capture_git(args: argparse.Namespace) -> int:
    item_id = str(args.id or "").strip()
    if not item_id:
        raise SystemExit("id required")
    with _lock():
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item = _find_item(items, item_id)
        if not item:
            raise SystemExit(f"item not found: {item_id}")
        project = srv.normalize_project_name(item.get("project"))
        snap = srv.git_snapshot(project)
        if snap:
            item["git"] = snap
            item["updatedAt"] = srv.now_iso()
            srv.write_store(store)
        return 0


def cmd_add_iteration(args: argparse.Namespace) -> int:
    with _lock():
        project = srv.normalize_project_name(args.project)
        it_type = str(args.type or "manual").strip() or "manual"
        title = str(args.title or "").strip()
        if not title:
            raise SystemExit("title required")

        iteration_store = srv.read_iteration_store()
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        now = srv.now_iso()
        machine_by = str(args.machine_by or "").strip()
        summary = str(args.summary or "").strip()
        task_id = str(args.task_id or "").strip()
        status = str(args.status or "").strip()

        if machine_by and task_id and not summary:
            summary = f"任务 {task_id} 已由 {machine_by} 机器确认完成"

        srv.append_iteration(
            iteration_store,
            project=project,
            it_type=it_type,
            title=title,
            summary=summary,
            task_id=task_id,
            machine_by=machine_by,
            status=status,
            source=str(args.source or "manual").strip() or "manual",
        )
        srv.write_iteration_store(iteration_store)
        try:
            srv.sync_project_docs(project, items, iteration_store.get("items") or [])
        except Exception:
            pass
        return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Offline board admin helper (no HTTP)")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list")
    p_list.add_argument("--project", default="")
    p_list.add_argument("--status", default="")
    p_list.set_defaults(func=cmd_list)

    p_list_it = sub.add_parser("list-iterations")
    p_list_it.add_argument("--project", default="")
    p_list_it.add_argument("--limit", type=int, default=50)
    p_list_it.set_defaults(func=cmd_list_iterations)

    p_status = sub.add_parser("set-status")
    p_status.add_argument("--id", required=True)
    p_status.add_argument("--status", default="doing")
    p_status.set_defaults(func=cmd_set_status)

    p_start = sub.add_parser("start")
    p_start.add_argument("--id", required=True)
    p_start.add_argument("--agent", default="codex")
    p_start.set_defaults(func=cmd_start)

    p_req = sub.add_parser("request-done")
    p_req.add_argument("--id", required=True)
    p_req.set_defaults(func=cmd_request_done)

    p_req_rb = sub.add_parser("request-rollback")
    p_req_rb.add_argument("--id", required=True)
    p_req_rb.set_defaults(func=cmd_request_rollback)

    p_cancel = sub.add_parser("cancel-rollback-request")
    p_cancel.add_argument("--id", required=True)
    p_cancel.set_defaults(func=cmd_cancel_rollback_request)

    p_done = sub.add_parser("confirm-done")
    p_done.add_argument("--id", required=True)
    p_done.add_argument("--machine-by", default="codex")
    p_done.set_defaults(func=cmd_confirm_done)

    p_rb = sub.add_parser("confirm-rollback")
    p_rb.add_argument("--id", required=True)
    p_rb.add_argument("--machine-by", default="codex")
    p_rb.set_defaults(func=cmd_confirm_rollback)

    p_add = sub.add_parser("add")
    p_add.add_argument("--text", required=True)
    p_add.add_argument("--priority", default="P1")
    p_add.add_argument("--project", default="")
    p_add.set_defaults(func=cmd_add)

    p_ut = sub.add_parser("update-text")
    p_ut.add_argument("--id", required=True)
    p_ut.add_argument("--text", required=True)
    p_ut.set_defaults(func=cmd_update_text)

    p_sp = sub.add_parser("set-project")
    p_sp.add_argument("--id", required=True)
    p_sp.add_argument("--project", required=True)
    p_sp.set_defaults(func=cmd_set_project)

    p_del = sub.add_parser("delete")
    p_del.add_argument("--id", required=True)
    p_del.set_defaults(func=cmd_delete)

    p_ca = sub.add_parser("cleanup-agents")
    p_ca.add_argument("--max-age-sec", type=int, default=0)
    p_ca.set_defaults(func=cmd_cleanup_agents)

    p_alias = sub.add_parser("set-agent-alias")
    p_alias.add_argument("--agent-id", required=True)
    p_alias.add_argument("--alias", default="")
    p_alias.set_defaults(func=cmd_set_agent_alias)

    p_ap = sub.add_parser("set-agent-project")
    p_ap.add_argument("--agent-id", required=True)
    p_ap.add_argument("--project", default="")
    p_ap.set_defaults(func=cmd_set_agent_project)

    p_git = sub.add_parser("capture-git")
    p_git.add_argument("--id", required=True)
    p_git.set_defaults(func=cmd_capture_git)

    p_check = sub.add_parser("set-check")
    p_check.add_argument("--id", required=True)
    p_check.add_argument("--key", required=True)
    p_check.add_argument("--value", default="")
    p_check.set_defaults(func=cmd_set_check)

    p_it = sub.add_parser("add-iteration")
    p_it.add_argument("--project", default="")
    p_it.add_argument("--type", default="manual")
    p_it.add_argument("--title", required=True)
    p_it.add_argument("--summary", default="")
    p_it.add_argument("--task-id", default="")
    p_it.add_argument("--machine-by", default="")
    p_it.add_argument("--status", default="")
    p_it.add_argument("--source", default="manual")
    p_it.set_defaults(func=cmd_add_iteration)

    return p


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
