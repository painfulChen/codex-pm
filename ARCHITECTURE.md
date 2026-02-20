# ARCHITECTURE (codex-pm)

> codex-pm 是一个本地优先的“多项目 + 多终端”看板工具，用来把 Codex 的工作流规范化：任务流转、机器确认完成/回滚、迭代日志、项目文档、服务状态聚合。

## 核心结构

- `pm_server.py`
  - 本地 HTTP 服务（默认 `127.0.0.1:8765`），提供：
    - UI：`/pm`
    - API：`/api/todos`、`/api/iterations`、`/api/project-doc`、`/api/services`、`/api/config`
  - 数据落盘：`~/.clawdbot/pm/*`
- `docs/live-view-v3.html`
  - 单页应用（不依赖打包），包含：
    - 任务看板（拖拽流转 + 机器确认）
    - 日程/版本日志（含日期快速跳转）
    - 项目文档（只读可视化 + 圈选建议 -> Todo）
    - 服务状态（LaunchAgent + 端口探测）
    - 设置/命令速查
- `board_cli.py` / `board_offline.py`
  - 给其它终端/其它 Codex 进程“接入/心跳/抢单/确认”的命令行入口

## 数据与边界

- **工具自身不算业务项目**：项目根目录按 `~/` 下同名目录解析（例如 `coach-feishu-suite` -> `~/coach-feishu-suite`）。
- **任务/迭代日志是全局共享**，但所有显示与同步都按 `project` 维度分组/过滤。
- **项目文档同步（AUTO 区）**：
  - 机器确认完成/回滚、或手动“记录迭代”会把摘要写入：
    - `<project>/docs/project-live.md`
    - `<project>/ARCHITECTURE.md`

## 自动架构同步状态（机器维护）

<!-- AUTO_ARCH_START -->
- 暂无（等待第一次机器确认完成/回滚或记录迭代后自动写入）
<!-- AUTO_ARCH_END -->

## 自动架构同步状态（机器维护）
<!-- AUTO_ARCH_STATUS_START -->
- 最近自动同步：2026-02-16T10:17:54+08:00
- 项目：codex-pm
- 版本日志（最近 12 条）：
  - v20260216.01 · optimize · 文档圈选浮窗增加拖拽把手与位置持久化
- 最近完成项（最近 8 条）：
  - 暂无
<!-- AUTO_ARCH_STATUS_END -->
