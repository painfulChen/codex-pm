#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import json
from typing import Any, Dict

import live_server as srv


def _lock():
    lk = getattr(srv, "file_lock", None)
    if callable(lk):
        try:
            return lk()
        except Exception:
            return contextlib.nullcontext()
    return contextlib.nullcontext()


def _project_match(value: Any, project: str) -> bool:
    if not project:
        return True
    return srv.normalize_project_name(value) == project


def _needs_backfill(summary: Any) -> bool:
    s = str(summary or "").strip()
    if not s:
        return True
    return ("做了什么：" not in s) or ("优化点：" not in s) or ("影响：" not in s)


def _task_index(items: list[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for item in items:
        task_id = str(item.get("id") or "").strip()
        if not task_id:
            continue
        out[task_id] = item
    return out


def backfill(*, project: str = "", dry_run: bool = False, only_missing: bool = False, limit: int = 0) -> Dict[str, Any]:
    target_project = srv.normalize_optional_project(project)
    max_patch = max(0, int(limit or 0))
    with _lock():
        store = srv.read_store()
        it_store = srv.read_iteration_store()
        items = store.get("items") if isinstance(store.get("items"), list) else []
        it_items = it_store.get("items") if isinstance(it_store.get("items"), list) else []
        idx = _task_index(items)

        patched = 0
        scanned = 0
        skipped = 0
        hit_limit = False
        touched_projects: set[str] = set()

        done_candidates = [
            it
            for it in it_items
            if str(it.get("type") or "").strip().lower() == "done" and _project_match(it.get("project"), target_project)
        ]
        done_candidates.sort(key=lambda x: str(x.get("createdAt") or ""), reverse=True)

        for it in done_candidates:
            scanned += 1
            old = str(it.get("summary") or "").strip()
            need = (not old) if only_missing else _needs_backfill(old)
            if not need:
                skipped += 1
                continue

            if max_patch > 0 and patched >= max_patch:
                hit_limit = True
                break

            task_id = str(it.get("taskId") or "").strip()
            machine_by = str(it.get("machineBy") or "codex").strip() or "codex"
            item = idx.get(task_id)

            if item:
                snap = item.get("git") if isinstance(item.get("git"), dict) else {}
                item_id = task_id or str(item.get("id") or "").strip() or str(it.get("id") or "").strip()
                new_summary = srv.build_done_summary(item, item_id, machine_by, snap=snap)
            else:
                item_id = task_id or str(it.get("id") or "").strip()
                pseudo: Dict[str, Any] = {
                    "text": str(it.get("title") or item_id).strip(),
                    "checks": {"tests": "unknown"},
                }
                new_summary = srv.build_done_summary(pseudo, item_id, machine_by, snap={})

            if not new_summary or new_summary == old:
                skipped += 1
                continue

            it["summary"] = new_summary
            patched += 1
            touched_projects.add(srv.normalize_project_name(it.get("project")))

        if patched > 0 and not dry_run:
            srv.write_iteration_store(it_store)
            for p in sorted(x for x in touched_projects if x):
                with contextlib.suppress(Exception):
                    srv.sync_project_docs(p, items, it_items)

        return {
            "ok": True,
            "project": target_project or "__all__",
            "dryRun": bool(dry_run),
            "onlyMissing": bool(only_missing),
            "limit": max_patch,
            "hitLimit": bool(hit_limit),
            "scannedDoneIterations": scanned,
            "patched": patched,
            "skipped": skipped,
            "touchedProjects": sorted(x for x in touched_projects if x),
        }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Backfill old done iteration summaries to structured format")
    p.add_argument("--project", default="", help="project name (default: all projects)")
    p.add_argument("--dry-run", action="store_true", help="preview only, do not write files")
    p.add_argument("--only-missing", action="store_true", help="only backfill when summary is empty")
    p.add_argument("--limit", type=int, default=0, help="max patched items per run (0 = no limit)")
    return p


def main() -> int:
    args = build_parser().parse_args()
    result = backfill(
        project=args.project,
        dry_run=bool(args.dry_run),
        only_missing=bool(args.only_missing),
        limit=int(args.limit or 0),
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

