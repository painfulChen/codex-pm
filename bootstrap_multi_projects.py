#!/usr/bin/env python3
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


HOME = Path.home()
DATA_DIR = Path(os.environ.get("PM_DATA_DIR", str(HOME / ".clawdbot" / "pm"))).expanduser()
BOARD_JSON = DATA_DIR / "project-todos.json"
SKIP_PROJECTS = {"node_modules", ".git", "Library"}


@dataclass
class ProjectSpec:
    name: str
    path: Path
    init_commands: list[str]


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def discover_projects() -> list[ProjectSpec]:
    out: list[ProjectSpec] = []
    for git_dir in sorted(HOME.glob("*/.git")):
        project_path = git_dir.parent
        name = project_path.name
        if name in SKIP_PROJECTS:
            continue
        init_commands: list[str] = []
        candidates = [
            "start-background.sh",
            "start-launchd.sh",
            "start.sh",
            "run_gui.sh",
            "run_cli.sh",
            "docker-compose.yml",
            "scripts/codex_launch_macos.sh",
            "status_dashboard/start-dashboard.sh",
            "package.json",
        ]
        for rel in candidates:
            p = project_path / rel
            if p.exists():
                init_commands.append(rel)
        out.append(ProjectSpec(name=name, path=project_path, init_commands=init_commands))
    return out


def ensure_architecture(spec: ProjectSpec) -> bool:
    file = spec.path / "ARCHITECTURE.md"
    if file.exists():
        return False
    init_line = "、".join(spec.init_commands) if spec.init_commands else "（待补充）"
    content = f"""# ARCHITECTURE ({spec.name})

## 定位
{spec.name} 的主工程文档，统一沉淀架构边界、运行入口与协作约定。

## 分层约定
- 应用层：业务页面/接口/命令入口。
- 防腐层：服务编排、外部依赖适配、任务流程控制。
- 基建层：配置、部署、守护进程、日志与运行时观测。

## 运行入口（初始化）
- 发现的主入口：{init_line}
- 约定：所有新入口需同步更新本文件与 `docs/project-live.md`。

## 协作约定
- 任务统一进入 PM 看板（`project={spec.name}`）。
- Codex 会话启动后先 heartbeat，再 claim 任务，完成后回写状态。
"""
    file.write_text(content, encoding="utf-8")
    return True


def ensure_project_live(spec: ProjectSpec) -> bool:
    docs_dir = spec.path / "docs"
    docs_dir.mkdir(exist_ok=True)
    file = docs_dir / "project-live.md"
    if file.exists():
        return False
    init_list = "\n".join([f"- `{x}`" for x in spec.init_commands]) if spec.init_commands else "- （待补充）"
    content = f"""# {spec.name} 项目文档（实时版）

> 用途：按项目持续记录目标、当前进展、风险、运维与交接。

## 1. 项目介绍
- 项目名：`{spec.name}`
- 根目录：`{spec.path}`
- 当前阶段：初始化接入看板

## 2. 初始化进程清单
{init_list}

## 3. 协作方式
- 任务进入统一看板：`project={spec.name}`
- 领取/释放/完成状态由看板 API 统一管理。
- 纯 Codex 模式：使用 `board_agent --observe-only` 只上报进度，不自动抢单。

## 4. 今日记录
- {datetime.now().strftime("%Y-%m-%d")}：补齐实时文档模板并接入统一看板。
"""
    file.write_text(content, encoding="utf-8")
    return True


def ensure_pm_services(spec: ProjectSpec) -> bool:
    """
    Create a per-project service catalog for the PM board's "服务状态" tab.
    This file is optional; if missing the board will fall back to built-in defaults.
    """
    docs_dir = spec.path / "docs"
    docs_dir.mkdir(exist_ok=True)
    file = docs_dir / "pm-services.json"
    if file.exists():
        return False
    content = {
        "version": 1,
        "updatedAt": now_iso(),
        "project": spec.name,
        "services": [],
    }
    file.write_text(json.dumps(content, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return True


def _read_board() -> dict:
    if not BOARD_JSON.exists():
        return {"version": 1, "updatedAt": now_iso(), "items": []}
    try:
        data = json.loads(BOARD_JSON.read_text(encoding="utf-8"))
    except Exception:
        data = {"version": 1, "updatedAt": now_iso(), "items": []}
    if not isinstance(data.get("items"), list):
        data["items"] = []
    return data


def _write_board(data: dict) -> None:
    data["updatedAt"] = now_iso()
    BOARD_JSON.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _has_item(items: Iterable[dict], item_id: str) -> bool:
    for x in items:
        if str(x.get("id")) == item_id:
            return True
    return False


def ensure_init_tasks(specs: list[ProjectSpec]) -> int:
    board = _read_board()
    items: list[dict] = board["items"]
    created = 0
    now = now_iso()
    for spec in specs:
        if spec.name == "codex-pm":
            continue
        if not spec.init_commands:
            continue
        item_id = f"todo-init-{spec.name.lower().replace(' ', '-').replace('_', '-')}"
        if _has_item(items, item_id):
            continue
        cmd_txt = " / ".join(spec.init_commands[:3])
        items.append(
            {
                "id": item_id,
                "text": f"[init] {spec.name} 启动链路检查：{cmd_txt}",
                "priority": "P1",
                "project": spec.name,
                "status": "todo",
                "order": 9990 + created * 10,
                "createdAt": now,
                "updatedAt": now,
            }
        )
        created += 1
    if created:
        _write_board(board)
    return created


def main() -> int:
    specs = discover_projects()
    created_arch = 0
    created_live = 0
    created_services = 0
    for spec in specs:
        created_arch += 1 if ensure_architecture(spec) else 0
        created_live += 1 if ensure_project_live(spec) else 0
        created_services += 1 if ensure_pm_services(spec) else 0
    created_tasks = ensure_init_tasks(specs)
    print(
        json.dumps(
            {
                "projects": [s.name for s in specs],
                "createdArchitecture": created_arch,
                "createdProjectLive": created_live,
                "createdPmServices": created_services,
                "createdInitTasks": created_tasks,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
