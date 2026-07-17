# 变更记录

本项目遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## 0.1.5 - 2026-07-17

### 修复

- 修复相对路径判断：约 45% 的相对路径操作此前被误判为 system scope，现通过标准化路径处理使相对路径与绝对路径得到一致判断。
- 修复 `apply_patch` 命令在工作区内被错误屏蔽的问题，正确提取其中的文件路径并归入 workspace scope。
- 修复 Glob 工具的 `pattern` 被误判为路径导致权限计算错误（如 `Glob(path=/etc, pattern=**)` 被计算为 4004 而非 4000），`policy_probe` 现仅包含 path。
- 修复 URL 与 scp 远程路径格式被误识别为本地路径的问题。
- 修复相同命令在不同执行时得到不同权限模式的不稳定问题。

## 0.1.4 - 2026-07-13

### 新增

- 将权限防护范围从 `Bash` 扩展到 `Read`、`Edit`、`Write`、`Glob` 和 `Grep`，覆盖 Claude Code 与 Codex 的受支持原生工具调用。
- 审计记录新增 `tool_name`、`operation` 和 `tool_input_summary` 字段；写入内容、编辑替换文本和 Grep 模式仅记录 UTF-8 字节长度，避免记录正文。

### 变更

- 原生工具调用复用 system/external/network/workspace 四组八进制权限模型；字段缺失、类型错误、关键路径为空或 Glob 范围不确定时均默认拒绝。
- Claude Code 插件 Hook 匹配器与 Codex 注册匹配器均更新为 `Bash|Read|Edit|Write|Glob|Grep`。

## 0.1.3 - 2026-07-11

### 新增

- 增加 Codex CLI 的 `PreToolUse` / `Bash` Hook 适配，可使用 `bash-guard codex register`、`unregister` 与 `status` 管理用户或 Git 项目作用域注册。
- Codex 与 Claude Code Hook 复用同一失败关闭策略判定、审计与标准拒绝输出。
- 审计记录新增 `client` 字段，记录调用来源为 `claude` 或 `codex`。

### 变更

- 默认审计日志按客户端隔离：Claude Code 写入 `$HOME/.claude/bash-guard-audit.jsonl`，Codex 写入 `$HOME/.codex/bash-guard-audit.jsonl`。
- `BASH_GUARD_AUDIT_LOG` 仍可覆盖默认路径；共用自定义路径时可通过 `client` 字段追溯来源。

## 0.1.2 - 2026-03-23

### 变更

- 审计日志默认写入 `$HOME/.claude/bash-guard-audit.jsonl`，无需设置环境变量即可记录决策。
- `BASH_GUARD_AUDIT_LOG` 设置为非空值时，继续使用其指定的自定义日志路径。
- 空值 `BASH_GUARD_AUDIT_LOG` 回退到默认日志路径。
- 无法解析或写入审计日志时保持失败关闭，拒绝对应 Bash 命令。
- 移除插件启动脚本；静态插件通过 `PATH` 直接调用 `bash-guard claude hook`，注册生成的适配器则直接调用记录的绝对二进制路径。
