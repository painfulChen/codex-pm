#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import socket
import sys
import time
from typing import Any, Dict, List
from uuid import uuid4
from urllib.parse import quote
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE_URL = os.environ.get("BOARD_API_URL", "http://127.0.0.1:8765/api/todos")
PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2}


class BoardError(RuntimeError):
    pass


def _read_json(resp: Any) -> Dict[str, Any]:
    raw = resp.read()
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def api_get() -> Dict[str, Any]:
    try:
        with urlopen(BASE_URL, timeout=8) as resp:
            data = _read_json(resp)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise BoardError(f"GET failed: {exc}") from exc
    if not data.get("ok"):
        raise BoardError(str(data.get("error") or "GET returned error"))
    return data


def api_post(payload: Dict[str, Any]) -> Dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = Request(BASE_URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=8) as resp:
            data = _read_json(resp)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise BoardError(f"POST failed: {exc}") from exc
    if not data.get("ok"):
        raise BoardError(str(data.get("error") or "POST returned error"))
    return data


def _offline_srv():
    """
    Lazy import of live_server for offline mode (no localhost HTTP).

    In some sandboxed environments, Python -> 127.0.0.1 is blocked (Operation not permitted),
    while browser access still works. Offline mode mutates the same on-disk stores as the server:
      - project-todos.json (store + agents)
    """
    try:
        import live_server as srv  # type: ignore

        return srv
    except Exception:
        return None


def _offline_lock(srv: Any):
    lock = getattr(srv, "file_lock", None)
    if callable(lock):
        try:
            return lock()
        except Exception:
            return contextlib.nullcontext()
    return contextlib.nullcontext()


def _offline_ping(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")

    with _offline_lock(srv):
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        agents = store.get("agents") if isinstance(store.get("agents"), dict) else {}

        agent_id = str(payload.get("agentId") or "").strip()
        if not agent_id:
            raise BoardError("agentId required")

        now = srv.now_iso()
        now_ep = srv.now_epoch()
        agent = agents.get(agent_id) if isinstance(agents.get(agent_id), dict) else {}

        raw_project = payload.get("project") or agent.get("project") or ""
        raw_cwd = str(payload.get("cwd") or agent.get("cwd") or "").strip()
        agent["project"] = srv.effective_agent_project({"project": raw_project, "cwd": raw_cwd})
        agent["title"] = str(payload.get("title") or agent.get("title") or agent_id).strip() or agent_id
        agent["state"] = str(payload.get("state") or agent.get("state") or "idle").strip() or "idle"
        agent["taskId"] = str(payload.get("taskId") or "").strip()
        agent["cwd"] = raw_cwd
        agent["note"] = str(payload.get("note") or "").strip()
        agent["lastSeenAt"] = now
        agent["lastSeenEpoch"] = now_ep
        agents[agent_id] = agent

        store["items"] = items
        store["agents"] = agents
        srv.write_store(store)
        return {"ok": True, "data": store}


def _offline_claim_next(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")

    with _offline_lock(srv):
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        agents = store.get("agents") if isinstance(store.get("agents"), dict) else {}

        agent_id = str(payload.get("agentId") or "").strip()
        project = srv.normalize_optional_project(payload.get("project") or "")
        if not agent_id:
            raise BoardError("agentId required")

        candidates = []
        for item in items:
            if str(item.get("status") or "").lower() != "todo":
                continue
            if project and srv.normalize_project_name(item.get("project")) != project:
                continue
            owner = str(item.get("claimedBy") or "").strip()
            if owner and owner != agent_id:
                continue
            candidates.append(item)

        if not candidates:
            return {"ok": True, "data": store, "claimed": None}

        candidates.sort(
            key=lambda x: (
                srv.priority_rank(x.get("priority")),
                srv.order_value(x.get("order"), 999999),
                str(x.get("createdAt") or ""),
            )
        )

        now = srv.now_iso()
        now_ep = srv.now_epoch()
        item = candidates[0]
        item_id = str(item.get("id"))
        item["status"] = "doing"
        item["order"] = srv.next_order(items, "doing")
        item["claimedBy"] = agent_id
        item["claimedAt"] = now
        item["updatedAt"] = now

        agent = agents.get(agent_id) if isinstance(agents.get(agent_id), dict) else {}
        agent["project"] = srv.normalize_project_name(item.get("project") or project or getattr(srv, "DEFAULT_PROJECT", ""))
        agent["title"] = str(payload.get("title") or agent.get("title") or agent_id).strip() or agent_id
        agent["state"] = "busy"
        agent["taskId"] = item_id
        agent["cwd"] = str(payload.get("cwd") or agent.get("cwd") or "").strip()
        agent["note"] = str(payload.get("note") or agent.get("note") or "").strip()
        agent["lastSeenAt"] = now
        agent["lastSeenEpoch"] = now_ep
        agents[agent_id] = agent

        store["items"] = items
        store["agents"] = agents
        srv.write_store(store)
        return {"ok": True, "data": store, "claimed": item}


def _offline_release(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")

    with _offline_lock(srv):
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        agents = store.get("agents") if isinstance(store.get("agents"), dict) else {}

        item_id = str(payload.get("id") or "").strip()
        agent_id = str(payload.get("agentId") or "").strip()
        if not item_id or not agent_id:
            raise BoardError("id and agentId required")

        item = srv.find_item(items, item_id)
        if not item:
            raise BoardError("item not found")

        current_owner = str(item.get("claimedBy") or "").strip()
        if current_owner and current_owner != agent_id:
            raise BoardError(f"claimed by {current_owner}")

        now = srv.now_iso()
        now_ep = srv.now_epoch()

        item.pop("claimedBy", None)
        item.pop("claimedAt", None)
        if str(item.get("status") or "").lower() == "doing":
            item["status"] = "todo"
            item["order"] = srv.next_order(items, "todo")
        item["updatedAt"] = now

        agent = agents.get(agent_id) if isinstance(agents.get(agent_id), dict) else {}
        agent["state"] = "idle"
        agent["taskId"] = ""
        agent["lastSeenAt"] = now
        agent["lastSeenEpoch"] = now_ep
        agents[agent_id] = agent

        store["items"] = items
        store["agents"] = agents
        srv.write_store(store)
        return {"ok": True, "data": store}


def _offline_find_item(items: list[Dict[str, Any]], item_id: str) -> Dict[str, Any] | None:
    for x in items:
        if str(x.get("id")) == item_id:
            return x
    return None


def _offline_set_status(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")

    with _offline_lock(srv):
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item_id = str(payload.get("id") or "").strip()
        status = str(payload.get("status") or "").strip().lower()
        if not item_id or not status:
            raise BoardError("id and status required")
        if status not in getattr(srv, "STATUSES", {"todo", "doing", "done_requested", "rollback_requested", "done"}):
            raise BoardError("invalid status")
        item = _offline_find_item(items, item_id)
        if not item:
            raise BoardError("item not found")
        current = str(item.get("status") or "todo").lower()
        if current == status:
            return {"ok": True, "data": store}
        # Mirror server governance: user can only start (todo->doing).
        if not (current == "todo" and status == "doing"):
            raise BoardError("set_status only supports todo -> doing")
        now = srv.now_iso()
        item["status"] = status
        item["order"] = srv.next_order(items, status)
        item["updatedAt"] = now
        srv.write_store(store)
        return {"ok": True, "data": store}


def _offline_request_done(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")
    with _offline_lock(srv):
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item_id = str(payload.get("id") or "").strip()
        if not item_id:
            raise BoardError("id required")
        item = _offline_find_item(items, item_id)
        if not item:
            raise BoardError("item not found")
        current = str(item.get("status") or "todo").lower()
        if current != "doing":
            raise BoardError("only doing item can request_done")
        now = srv.now_iso()
        item["status"] = "done_requested"
        item["order"] = srv.next_order(items, "done_requested")
        item["doneRequestedAt"] = now
        item["updatedAt"] = now
        srv.write_store(store)
        return {"ok": True, "data": store}


def _offline_request_rollback(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")
    with _offline_lock(srv):
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item_id = str(payload.get("id") or "").strip()
        if not item_id:
            raise BoardError("id required")
        item = _offline_find_item(items, item_id)
        if not item:
            raise BoardError("item not found")
        current = str(item.get("status") or "todo").lower()
        if current != "done":
            raise BoardError("only done item can request_rollback")
        now = srv.now_iso()
        item["status"] = "rollback_requested"
        item["order"] = srv.next_order(items, "rollback_requested")
        item["rollbackRequestedAt"] = now
        item["updatedAt"] = now
        srv.write_store(store)
        return {"ok": True, "data": store}


def _offline_cancel_rollback_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")
    with _offline_lock(srv):
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item_id = str(payload.get("id") or "").strip()
        if not item_id:
            raise BoardError("id required")
        item = _offline_find_item(items, item_id)
        if not item:
            raise BoardError("item not found")
        current = str(item.get("status") or "todo").lower()
        if current != "rollback_requested":
            raise BoardError("cancel_rollback_request requires rollback_requested")
        now = srv.now_iso()
        item["status"] = "done"
        item["order"] = srv.next_order(items, "done")
        item["rollbackRequestCanceledAt"] = now
        item["updatedAt"] = now
        srv.write_store(store)
        return {"ok": True, "data": store}


def _offline_update_text(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")
    with _offline_lock(srv):
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item_id = str(payload.get("id") or "").strip()
        text = str(payload.get("text") or "").strip()
        if not item_id or not text:
            raise BoardError("id and text required")
        item = _offline_find_item(items, item_id)
        if not item:
            raise BoardError("item not found")
        now = srv.now_iso()
        item["text"] = text
        item["updatedAt"] = now
        srv.write_store(store)
        return {"ok": True, "data": store}


def _offline_set_project(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")
    with _offline_lock(srv):
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item_id = str(payload.get("id") or "").strip()
        project = str(payload.get("project") or "").strip()
        if not item_id or not project:
            raise BoardError("id and project required")
        item = _offline_find_item(items, item_id)
        if not item:
            raise BoardError("item not found")
        now = srv.now_iso()
        item["project"] = srv.normalize_project_name(project)
        item["updatedAt"] = now
        srv.write_store(store)
        return {"ok": True, "data": store}


def _offline_add(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")
    with _offline_lock(srv):
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        text = str(payload.get("text") or "").strip()
        if not text:
            raise BoardError("text required")
        priority = str(payload.get("priority") or "P1").strip().upper()
        if priority not in {"P0", "P1", "P2"}:
            priority = "P1"
        fallback = getattr(srv, "FALLBACK_PROJECT", "coach-feishu-suite")
        project = srv.normalize_project_name(payload.get("project") or fallback)
        now = srv.now_iso()
        items.append(
            {
                "id": f"todo-{uuid4().hex[:10]}",
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
        return {"ok": True, "data": store}


def _offline_delete(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")
    with _offline_lock(srv):
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item_id = str(payload.get("id") or "").strip()
        if not item_id:
            raise BoardError("id required")
        before = len(items)
        items2 = [x for x in items if str(x.get("id")) != item_id]
        if len(items2) == before:
            raise BoardError("item not found")
        store["items"] = items2
        srv.write_store(store)
        return {"ok": True, "data": store}


def _offline_cleanup_agents(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")
    with _offline_lock(srv):
        store = srv.read_store()
        agents = store.get("agents") if isinstance(store.get("agents"), dict) else {}
        max_age = int(payload.get("maxAgeSec") or getattr(srv, "AGENT_TTL_SEC", 180))
        ttl = int(getattr(srv, "AGENT_TTL_SEC", 180))
        if max_age < ttl:
            max_age = ttl
        now_ep = srv.now_epoch()
        cutoff = now_ep - max_age
        stale_ids: list[str] = []
        for aid, ap in list(agents.items()):
            if not isinstance(ap, dict):
                stale_ids.append(aid)
                continue
            seen = int(ap.get("lastSeenEpoch") or 0)
            if not seen or seen < cutoff:
                stale_ids.append(aid)
        for aid in stale_ids:
            agents.pop(aid, None)
        store["agents"] = agents
        srv.write_store(store)
        return {"ok": True, "data": store, "removed": len(stale_ids)}


def _offline_set_agent_alias(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")
    with _offline_lock(srv):
        store = srv.read_store()
        agent_id = str(payload.get("agentId") or "").strip()
        alias = str(payload.get("alias") or "").strip()
        if not agent_id:
            raise BoardError("agentId required")
        aliases = store.get("agentAliases")
        if not isinstance(aliases, dict):
            aliases = {}
            store["agentAliases"] = aliases
        if alias:
            aliases[agent_id] = alias
        else:
            aliases.pop(agent_id, None)
        srv.write_store(store)
        return {"ok": True, "data": store}


def _offline_set_agent_project(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")
    with _offline_lock(srv):
        store = srv.read_store()
        agent_id = str(payload.get("agentId") or "").strip()
        project = str(payload.get("project") or "").strip()
        if not agent_id:
            raise BoardError("agentId required")
        project_overrides = store.get("agentProjects")
        if not isinstance(project_overrides, dict):
            project_overrides = {}
            store["agentProjects"] = project_overrides
        if project:
            project_overrides[agent_id] = project
        else:
            project_overrides.pop(agent_id, None)
        srv.write_store(store)
        return {"ok": True, "data": store}


def _offline_set_check(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")
    with _offline_lock(srv):
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item_id = str(payload.get("id") or "").strip()
        key = str(payload.get("key") or "").strip()
        value = str(payload.get("value") or "").strip()
        if not item_id or not key:
            raise BoardError("id and key required")
        item = _offline_find_item(items, item_id)
        if not item:
            raise BoardError("item not found")
        checks = item.get("checks")
        if not isinstance(checks, dict):
            checks = {}
            item["checks"] = checks
        checks[key] = value
        item["updatedAt"] = srv.now_iso()
        srv.write_store(store)
        return {"ok": True, "data": store}


def _offline_capture_git(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")
    with _offline_lock(srv):
        store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        item_id = str(payload.get("id") or "").strip()
        if not item_id:
            raise BoardError("id required")
        item = _offline_find_item(items, item_id)
        if not item:
            raise BoardError("item not found")
        project = srv.normalize_project_name(item.get("project"))
        snap = srv.git_snapshot(project)
        if snap:
            item["git"] = snap
            item["updatedAt"] = srv.now_iso()
            srv.write_store(store)
        return {"ok": True, "data": store, "git": snap}


def _offline_confirm_done(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")
    with _offline_lock(srv):
        store = srv.read_store()
        iteration_store = srv.read_iteration_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        agents = store.get("agents") if isinstance(store.get("agents"), dict) else {}
        item_id = str(payload.get("id") or "").strip()
        machine_by = str(payload.get("machineBy") or "codex").strip() or "codex"
        if not item_id:
            raise BoardError("id required")
        item = _offline_find_item(items, item_id)
        if not item:
            raise BoardError("item not found")
        now = srv.now_iso()
        now_ep = srv.now_epoch()
        current = str(item.get("status") or "todo").lower()
        if current not in {"doing", "done_requested", "done"}:
            raise BoardError("confirm_done requires doing/done_requested/done")
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
                    dirty = "*" if snap.get("dirty") else ""
                    tests = (item.get("checks") or {}).get("tests", "unknown") if isinstance(item.get("checks"), dict) else "unknown"
                    summary += f"（git: {br}@{head}{dirty} files={snap.get('changedCount', 0)} tests={tests}）"
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
        return {"ok": True, "data": store}


def _offline_confirm_rollback(payload: Dict[str, Any]) -> Dict[str, Any]:
    srv = _offline_srv()
    if not srv:
        raise BoardError("offline mode unavailable: cannot import live_server")
    with _offline_lock(srv):
        store = srv.read_store()
        iteration_store = srv.read_iteration_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        agents = store.get("agents") if isinstance(store.get("agents"), dict) else {}
        item_id = str(payload.get("id") or "").strip()
        machine_by = str(payload.get("machineBy") or "codex").strip() or "codex"
        if not item_id:
            raise BoardError("id required")
        item = _offline_find_item(items, item_id)
        if not item:
            raise BoardError("item not found")
        now = srv.now_iso()
        now_ep = srv.now_epoch()
        current = str(item.get("status") or "todo").lower()
        if current != "rollback_requested":
            raise BoardError("confirm_rollback requires rollback_requested")
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
        return {"ok": True, "data": store}


def iterations_url(project: str = "") -> str:
    base = BASE_URL.strip()
    if base.endswith("/api/todos"):
        url = base[: -len("/api/todos")] + "/api/iterations"
    elif "/api/" in base:
        url = base.split("/api/", 1)[0] + "/api/iterations"
    else:
        url = base.rstrip("/") + "/api/iterations"
    if project:
        return f"{url}?project={quote(project)}"
    return url


def iterations_get(project: str = "") -> Dict[str, Any]:
    url = iterations_url(project)
    try:
        with urlopen(url, timeout=8) as resp:
            data = _read_json(resp)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise BoardError(f"GET iterations failed: {exc}") from exc
    if not data.get("ok"):
        raise BoardError(str(data.get("error") or "GET iterations returned error"))
    return data


def get_items(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = payload.get("data")
    if not isinstance(data, dict):
        return []
    items = data.get("items")
    return items if isinstance(items, list) else []


def norm_project(v: Any) -> str:
    return str(v or "").strip()


def choose_next(items: List[Dict[str, Any]], project: str, agent_id: str) -> Dict[str, Any] | None:
    filtered = []
    for item in items:
        if str(item.get("status") or "").lower() != "todo":
            continue
        item_project = norm_project(item.get("project"))
        if project and item_project != project:
            continue
        owner = str(item.get("claimedBy") or "").strip()
        if owner and owner != agent_id:
            continue
        filtered.append(item)
    if not filtered:
        return None
    filtered.sort(
        key=lambda x: (
            PRIORITY_RANK.get(str(x.get("priority") or "P9").upper(), 9),
            int(x.get("order") or 999999),
            str(x.get("createdAt") or ""),
        )
    )
    return filtered[0]


def print_json(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def default_agent_id() -> str:
    forced = str(os.environ.get("BOARD_AGENT_ID") or "").strip()
    if forced:
        return forced
    host = socket.gethostname().split(".")[0]
    try:
        tty = os.path.basename(os.ttyname(sys.stdin.fileno()))
    except Exception:
        tty = "no-tty"
    # 统一与 attach_codex_board_agents.py / board_agent 的命名，做到零配置可对齐：
    # - 常见交互终端：ttys000/ttys001... -> codex-ttys000
    # - 其他场景再回退到 host+tty，避免冲突
    if tty.startswith("ttys") or tty.startswith("pts"):
        return f"codex-{tty}"
    return f"codex-{host}-{tty}"


def default_title() -> str:
    v = str(os.environ.get("BOARD_AGENT_TITLE") or "").strip()
    if v:
        return v
    term = str(os.environ.get("TERM_PROGRAM") or "terminal").strip()
    try:
        tty = os.path.basename(os.ttyname(sys.stdin.fileno()))
    except Exception:
        tty = "no-tty"
    return f"{term}:{tty}"


def cmd_whoami(args: argparse.Namespace) -> int:
    print_json(
        {
            "agentId": args.agent,
            "title": args.title,
            "project": args.project or "",
            "cwd": args.cwd or os.getcwd(),
            "api": BASE_URL,
        }
    )
    return 0


def cmd_my_task(args: argparse.Namespace) -> int:
    data = api_get()
    store = data.get("data") if isinstance(data.get("data"), dict) else {}
    agents = store.get("agents") if isinstance(store.get("agents"), dict) else {}
    agent = agents.get(args.agent) if isinstance(agents.get(args.agent), dict) else {}
    task_id = str(agent.get("taskId") or "").strip()
    if not task_id:
        print("NO_TASK")
        return 2
    items = get_items(data)
    task = None
    for it in items:
        if str(it.get("id")) == task_id:
            task = it
            break
    if not isinstance(task, dict) or not task:
        print("NO_TASK")
        return 2
    print_json({"ok": True, "agentId": args.agent, "taskId": task_id, "task": task})
    return 0


def cmd_ping(args: argparse.Namespace) -> int:
    payload = {
        "action": "agent_ping",
        "agentId": args.agent,
        "project": args.project,
        "title": args.title,
        "state": args.state,
        "taskId": args.task_id or "",
        "cwd": args.cwd or os.getcwd(),
        "note": args.note or "",
    }
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_ping(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "agentId": args.agent, "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_claim_next(args: argparse.Namespace) -> int:
    payload = {
        "action": "claim_next",
        "agentId": args.agent,
        "project": args.project or "",
        "title": args.title,
        "cwd": args.cwd or os.getcwd(),
        "note": args.note or "",
    }
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        claim = _offline_claim_next(payload)
    else:
        claim = api_post(payload)
    task = claim.get("claimed")
    if not isinstance(task, dict) or not task:
        print("NO_TASK")
        return 2
    print_json({"ok": True, "claimed": task})
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    offline_mode = bool(getattr(args, "offline", False)) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}
    if offline_mode:
        srv = _offline_srv()
        if not srv:
            raise BoardError("offline mode unavailable: cannot import live_server")
        with _offline_lock(srv):
            store = srv.read_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
    else:
        data = api_get()
        items = get_items(data)
    out = []
    for item in items:
        if args.project and norm_project(item.get("project")) != args.project:
            continue
        if args.status and str(item.get("status") or "").lower() != args.status:
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
    print_json({"count": len(out), "items": out})
    return 0


def cmd_release(args: argparse.Namespace) -> int:
    payload = {"action": "release_task", "id": args.id, "agentId": args.agent}
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_release(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_daemon(args: argparse.Namespace) -> int:
    interval = max(2, int(args.interval))
    claim_interval = max(2, int(args.claim_interval))
    current_task = str(args.task_id or "").strip()
    next_claim_at = 0.0
    stopping = False
    offline_mode = bool(getattr(args, "offline", False)) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}

    def _stop(_signum: int, _frame: Any) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    print(
        f"[board-agent] start agent={args.agent} title={args.title} project={args.project or '(all)'}"
        f"{' offline' if offline_mode else ''}",
        flush=True,
    )
    try:
        while not stopping:
            state = "busy" if current_task else "idle"
            ping_payload = {
                "action": "agent_ping",
                "agentId": args.agent,
                "project": args.project or "",
                "title": args.title,
                "state": state,
                "taskId": current_task,
                "cwd": args.cwd or os.getcwd(),
                "note": args.note or "",
            }
            try:
                if offline_mode:
                    _offline_ping(ping_payload)
                else:
                    api_post(ping_payload)
            except BoardError as exc:
                # Auto-fallback to offline mode on common localhost blocks.
                if not offline_mode and _offline_srv():
                    offline_mode = True
                    print(f"[board-agent] switch to offline mode (ping failed: {exc})", file=sys.stderr, flush=True)
                    try:
                        _offline_ping(ping_payload)
                    except Exception:
                        pass
                else:
                    print(f"[board-agent] ping failed: {exc}", file=sys.stderr, flush=True)
            now = time.time()
            if not current_task and not args.observe_only and now >= next_claim_at:
                try:
                    claim_payload = {
                        "action": "claim_next",
                        "agentId": args.agent,
                        "project": args.project or "",
                        "title": args.title,
                        "cwd": args.cwd or os.getcwd(),
                        "note": args.note or "",
                    }
                    if offline_mode:
                        resp = _offline_claim_next(claim_payload)
                    else:
                        resp = api_post(claim_payload)
                    claimed = resp.get("claimed")
                    if isinstance(claimed, dict) and claimed.get("id"):
                        current_task = str(claimed.get("id"))
                        print(f"[board-agent] claimed {current_task}", flush=True)
                    else:
                        next_claim_at = now + claim_interval
                except BoardError as exc:
                    if not offline_mode and _offline_srv():
                        offline_mode = True
                        print(f"[board-agent] switch to offline mode (claim_next failed: {exc})", file=sys.stderr, flush=True)
                    else:
                        print(f"[board-agent] claim_next failed: {exc}", file=sys.stderr, flush=True)
                    next_claim_at = now + claim_interval
            if current_task:
                try:
                    if offline_mode:
                        srv = _offline_srv()
                        store = srv.read_store() if srv else {}
                        items = store.get("items") if isinstance(store.get("items"), list) else []
                        item = None
                        for x in items:
                            if str(x.get("id")) == current_task:
                                item = x
                                break
                    else:
                        data = api_get()
                        item = None
                        for x in get_items(data):
                            if str(x.get("id")) == current_task:
                                item = x
                                break
                    owner = str(item.get("claimedBy") or "").strip() if isinstance(item, dict) else ""
                    if not item or owner != args.agent:
                        print(f"[board-agent] released externally: {current_task}", flush=True)
                        current_task = ""
                        next_claim_at = time.time() + claim_interval
                except BoardError:
                    pass
            time.sleep(interval)
    finally:
        if current_task and not args.no_release_on_exit:
            try:
                rel_payload = {"action": "release_task", "id": current_task, "agentId": args.agent}
                if offline_mode:
                    _offline_release(rel_payload)
                else:
                    api_post(rel_payload)
                print(f"[board-agent] released on exit: {current_task}", flush=True)
            except BoardError:
                pass
        try:
            end_payload = {
                "action": "agent_ping",
                "agentId": args.agent,
                "project": args.project or "",
                "title": args.title,
                "state": "idle",
                "taskId": "",
                "cwd": args.cwd or os.getcwd(),
                "note": args.note or "",
            }
            if offline_mode:
                _offline_ping(end_payload)
            else:
                api_post(end_payload)
        except BoardError:
            pass
    print("[board-agent] stopped", flush=True)
    return 0


def cmd_request_done(args: argparse.Namespace) -> int:
    payload = {"action": "request_done", "id": args.id}
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_request_done(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_confirm_done(args: argparse.Namespace) -> int:
    payload = {"action": "confirm_done", "id": args.id, "machineBy": args.agent}
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_confirm_done(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_request_rollback(args: argparse.Namespace) -> int:
    payload = {"action": "request_rollback", "id": args.id}
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_request_rollback(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_confirm_rollback(args: argparse.Namespace) -> int:
    payload = {"action": "confirm_rollback", "id": args.id, "machineBy": args.agent}
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_confirm_rollback(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_set_project(args: argparse.Namespace) -> int:
    payload = {"action": "set_project", "id": args.id, "project": args.project}
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_set_project(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_set_status(args: argparse.Namespace) -> int:
    payload = {"action": "set_status", "id": args.id, "status": args.status}
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_set_status(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_cancel_rollback_request(args: argparse.Namespace) -> int:
    payload = {"action": "cancel_rollback_request", "id": args.id}
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_cancel_rollback_request(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_update_text(args: argparse.Namespace) -> int:
    payload = {"action": "update_text", "id": args.id, "text": args.text}
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_update_text(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    payload = {"action": "add", "text": args.text, "priority": args.priority, "project": args.project}
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_add(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    payload = {"action": "delete", "id": args.id}
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_delete(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_cleanup_agents(args: argparse.Namespace) -> int:
    payload: Dict[str, Any] = {"action": "cleanup_agents"}
    if args.max_age_sec:
        payload["maxAgeSec"] = int(args.max_age_sec)
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_cleanup_agents(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "removed": resp.get("removed"), "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_set_agent_alias(args: argparse.Namespace) -> int:
    payload = {"action": "set_agent_alias", "agentId": args.agent_id, "alias": args.alias}
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_set_agent_alias(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_set_agent_project(args: argparse.Namespace) -> int:
    payload = {"action": "set_agent_project", "agentId": args.agent_id, "project": args.project}
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_set_agent_project(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_capture_git(args: argparse.Namespace) -> int:
    payload = {"action": "capture_git", "id": args.id}
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_capture_git(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "git": resp.get("git"), "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_set_check(args: argparse.Namespace) -> int:
    payload = {"action": "set_check", "id": args.id, "key": args.key, "value": args.value}
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        resp = _offline_set_check(payload)
    else:
        resp = api_post(payload)
    print_json({"ok": True, "updatedAt": resp.get("data", {}).get("updatedAt")})
    return 0


def cmd_add_iteration(args: argparse.Namespace) -> int:
    project = (args.project or "").strip() or ""
    title = (args.title or "").strip()
    if not title:
        raise BoardError("title is required")
    payload = {
        "action": "add_iteration",
        "project": project,
        "type": args.type,
        "title": title,
        "summary": (args.summary or "").strip(),
        "taskId": (args.task_id or "").strip(),
        "machineBy": (args.machine_by or "").strip(),
        "source": args.source or "manual",
        "status": (args.status or "").strip(),
    }
    if getattr(args, "offline", False) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}:
        srv = _offline_srv()
        if not srv:
            raise BoardError("offline mode unavailable: cannot import live_server")
        with _offline_lock(srv):
            iteration_store = srv.read_iteration_store()
            store = srv.read_store()
            items = store.get("items") if isinstance(store.get("items"), list) else []
            created = srv.append_iteration(
                iteration_store,
                project=srv.normalize_project_name(project),
                it_type=str(args.type or "manual").strip() or "manual",
                title=title,
                summary=(args.summary or "").strip(),
                task_id=(args.task_id or "").strip(),
                machine_by=(args.machine_by or "").strip(),
                status=(args.status or "").strip(),
                source=(args.source or "manual").strip() or "manual",
            )
            srv.write_iteration_store(iteration_store)
            try:
                srv.sync_project_docs(srv.normalize_project_name(project), items, iteration_store.get("items") or [])
            except Exception:
                pass
        resp = {"ok": True, "created": created}
    else:
        resp = api_post(payload)
    print_json({"ok": True, "created": resp.get("created")})
    return 0


def cmd_list_iterations(args: argparse.Namespace) -> int:
    offline_mode = bool(getattr(args, "offline", False)) or str(os.environ.get("BOARD_OFFLINE") or "").strip() in {"1", "true", "yes"}
    if offline_mode:
        srv = _offline_srv()
        if not srv:
            raise BoardError("offline mode unavailable: cannot import live_server")
        with _offline_lock(srv):
            data = srv.read_iteration_store()
        items = data.get("items") if isinstance(data.get("items"), list) else []
        project = (args.project or "").strip()
        if project:
            items = [x for x in items if str(x.get("project") or "").strip() == project]
        items.sort(key=lambda x: str(x.get("createdAt") or ""), reverse=True)
    else:
        resp = iterations_get((args.project or "").strip())
        data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
        items = data.get("items") if isinstance(data.get("items"), list) else []
    if args.limit > 0:
        items = items[: args.limit]
    print_json({"count": len(items), "items": items, "updatedAt": data.get("updatedAt")})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Board CLI for multi-Codex task coordination")
    parser.set_defaults(func=None)
    parser.add_argument("--api", default=BASE_URL, help="Board API URL")

    sub = parser.add_subparsers(dest="command")

    p_who = sub.add_parser("whoami", help="print effective agent identity defaults")
    p_who.add_argument("--agent", default=default_agent_id())
    p_who.add_argument("--project", default="")
    p_who.add_argument("--title", default=default_title())
    p_who.add_argument("--cwd", default="")
    p_who.set_defaults(func=cmd_whoami)

    p_my = sub.add_parser("my-task", help="get current task claimed by this agent (via agent.taskId)")
    p_my.add_argument("--agent", default=default_agent_id())
    p_my.set_defaults(func=cmd_my_task)

    p_ping = sub.add_parser("ping", help="send agent heartbeat")
    p_ping.add_argument("--agent", default=default_agent_id())
    p_ping.add_argument("--project", default="")
    p_ping.add_argument("--title", default=default_title())
    p_ping.add_argument("--state", default="idle")
    p_ping.add_argument("--task-id", default="")
    p_ping.add_argument("--cwd", default="")
    p_ping.add_argument("--note", default="")
    p_ping.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_ping.set_defaults(func=cmd_ping)

    p_claim = sub.add_parser("claim-next", help="claim next todo task")
    p_claim.add_argument("--agent", default=default_agent_id())
    p_claim.add_argument("--project", default="")
    p_claim.add_argument("--title", default=default_title())
    p_claim.add_argument("--cwd", default="")
    p_claim.add_argument("--note", default="")
    p_claim.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_claim.set_defaults(func=cmd_claim_next)

    p_daemon = sub.add_parser("daemon", help="auto heartbeat + auto claim-next loop")
    p_daemon.add_argument("--agent", default=default_agent_id())
    p_daemon.add_argument("--project", default="")
    p_daemon.add_argument("--title", default=default_title())
    p_daemon.add_argument("--interval", type=int, default=15)
    p_daemon.add_argument("--claim-interval", type=int, default=20)
    p_daemon.add_argument("--task-id", default="")
    p_daemon.add_argument("--cwd", default="")
    p_daemon.add_argument("--note", default="")
    p_daemon.add_argument("--no-release-on-exit", action="store_true")
    p_daemon.add_argument("--observe-only", action="store_true")
    p_daemon.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_daemon.set_defaults(func=cmd_daemon)

    p_list = sub.add_parser("list", help="list tasks")
    p_list.add_argument("--project", default="")
    p_list.add_argument("--status", default="")
    p_list.add_argument("--offline", action="store_true", help="Bypass HTTP and read stores directly (for restricted localhost)")
    p_list.set_defaults(func=cmd_list)

    p_release = sub.add_parser("release", help="release a claimed task")
    p_release.add_argument("--id", required=True)
    p_release.add_argument("--agent", default=default_agent_id())
    p_release.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_release.set_defaults(func=cmd_release)

    p_req_done = sub.add_parser("request-done", help="request done for a task")
    p_req_done.add_argument("--id", required=True)
    p_req_done.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_req_done.set_defaults(func=cmd_request_done)

    p_done = sub.add_parser("confirm-done", help="machine confirm task done")
    p_done.add_argument("--id", required=True)
    p_done.add_argument("--agent", default=default_agent_id())
    p_done.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_done.set_defaults(func=cmd_confirm_done)

    p_req_rb = sub.add_parser("request-rollback", help="request rollback for a task")
    p_req_rb.add_argument("--id", required=True)
    p_req_rb.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_req_rb.set_defaults(func=cmd_request_rollback)

    p_cancel_rb = sub.add_parser("cancel-rollback-request", help="cancel rollback request (rollback_requested -> done)")
    p_cancel_rb.add_argument("--id", required=True)
    p_cancel_rb.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_cancel_rb.set_defaults(func=cmd_cancel_rollback_request)

    p_rb = sub.add_parser("confirm-rollback", help="machine confirm rollback")
    p_rb.add_argument("--id", required=True)
    p_rb.add_argument("--agent", default=default_agent_id())
    p_rb.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_rb.set_defaults(func=cmd_confirm_rollback)

    p_status = sub.add_parser("set-status", help="set status (user action: todo -> doing)")
    p_status.add_argument("--id", required=True)
    p_status.add_argument("--status", default="doing")
    p_status.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_status.set_defaults(func=cmd_set_status)

    p_sp = sub.add_parser("set-project", help="set task project")
    p_sp.add_argument("--id", required=True)
    p_sp.add_argument("--project", required=True)
    p_sp.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_sp.set_defaults(func=cmd_set_project)

    p_ut = sub.add_parser("update-text", help="update task text")
    p_ut.add_argument("--id", required=True)
    p_ut.add_argument("--text", required=True)
    p_ut.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_ut.set_defaults(func=cmd_update_text)

    p_add = sub.add_parser("add", help="add a new task")
    p_add.add_argument("--text", required=True)
    p_add.add_argument("--priority", default="P1")
    p_add.add_argument("--project", default="")
    p_add.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_add.set_defaults(func=cmd_add)

    p_del = sub.add_parser("delete", help="delete a task")
    p_del.add_argument("--id", required=True)
    p_del.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_del.set_defaults(func=cmd_delete)

    p_ca = sub.add_parser("cleanup-agents", help="cleanup stale agents")
    p_ca.add_argument("--max-age-sec", type=int, default=0)
    p_ca.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_ca.set_defaults(func=cmd_cleanup_agents)

    p_alias = sub.add_parser("set-agent-alias", help="set agent display alias (empty to clear)")
    p_alias.add_argument("--agent-id", required=True)
    p_alias.add_argument("--alias", default="")
    p_alias.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_alias.set_defaults(func=cmd_set_agent_alias)

    p_ap = sub.add_parser("set-agent-project", help="override agent project (empty to clear)")
    p_ap.add_argument("--agent-id", required=True)
    p_ap.add_argument("--project", default="")
    p_ap.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_ap.set_defaults(func=cmd_set_agent_project)

    p_git = sub.add_parser("capture-git", help="capture git snapshot for a task")
    p_git.add_argument("--id", required=True)
    p_git.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_git.set_defaults(func=cmd_capture_git)

    p_check = sub.add_parser("set-check", help="set a task check key/value (e.g. tests=pass)")
    p_check.add_argument("--id", required=True)
    p_check.add_argument("--key", required=True)
    p_check.add_argument("--value", default="")
    p_check.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_check.set_defaults(func=cmd_set_check)

    p_add_it = sub.add_parser("add-iteration", help="append iteration/version log and sync docs")
    p_add_it.add_argument("--project", default="")
    p_add_it.add_argument("--type", default="manual")
    p_add_it.add_argument("--title", required=True)
    p_add_it.add_argument("--summary", default="")
    p_add_it.add_argument("--task-id", default="")
    p_add_it.add_argument("--machine-by", default="")
    p_add_it.add_argument("--source", default="manual")
    p_add_it.add_argument("--status", default="")
    p_add_it.add_argument("--offline", action="store_true", help="Bypass HTTP and write stores directly (for restricted localhost)")
    p_add_it.set_defaults(func=cmd_add_iteration)

    p_list_it = sub.add_parser("list-iterations", help="list iteration/version logs")
    p_list_it.add_argument("--project", default="")
    p_list_it.add_argument("--limit", type=int, default=50)
    p_list_it.add_argument("--offline", action="store_true", help="Bypass HTTP and read stores directly (for restricted localhost)")
    p_list_it.set_defaults(func=cmd_list_iterations)

    return parser


def main() -> int:
    global BASE_URL
    parser = build_parser()
    args = parser.parse_args()
    BASE_URL = args.api
    if not args.func:
        parser.print_help()
        return 1
    try:
        return int(args.func(args) or 0)
    except BoardError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
