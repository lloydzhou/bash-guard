# 变更记录

本项目遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## 0.3.0 - 2026-10-19

### 变更

- Jev 判断输出从 `allow`/`deny` 改为 **required 权限数字**：一次请求发送 12 个校准概率问题（4 范围 × 读/写/执行，每问概率 ≥0.5 记该位），组装出四位八进制 `required` 后，与 `BASH_GUARD_MODE` 用与本地策略完全相同的位比较得出最终放行/拒绝。Jev 不再拥有独立的否决权。
- 模式为 `7777` 时完全放行，不调用 Jev 也不调用本地策略（审计记录 `decision_source: mode_7777`）。
- Jev 请求的 `state` 不再携带 `allowed_mode`：需求分类与已授予模式完全解耦，7777 等宽松模式不会干扰判断。
- Jev 拒绝信息从 `source=jev decision=deny local_policy=unknown` 改为统一格式 `source=jev required=<需求位> allowed=<当前模式>`，与本地策略一样可解释缺哪个位。
- Jev 审计记录以 `required_mode` 替代 `jev_choice`/`jev_probability`，保留 `jev_model`。

### 新增

- Jev 回退本地策略时，拒绝信息附带 `required/allowed` 位计算与回退原因。

## 0.2.0 - 2026-09-21

### 新增

- 可选接入 TypeSafe Jev 作为 Claude Code 与 Codex Hook 的语义拦截关卡；Jev 仅输出 `allow` 或 `deny`，`allow` 直接放行，`deny` 阻断工具调用。
- 支持 `JEV_API_KEY`、`JEV_BASE_URL`、`JEV_MODEL`，并兼容官方 `TYPESAFE_API_KEY`、`TYPESAFE_BASE_URL`、`TYPESAFE_DEFAULT_MODEL` 配置。
- Jev 审计记录增加决策来源、选择、概率、模型和回退错误；命令摘要会脱敏常见凭据参数。
- Jev 请求新增显式 `workspace_path`，将 Hook 提供的绝对工作目录作为路径判断边界。
- Jev 请求新增规范化的权限模式、四个 scope 的精确定义及读写执行位说明，使语义判断按当前 `BASH_GUARD_MODE` 拒绝未授权能力。

### 变更

- 未配置 Jev key 或 Jev 请求失败时回退到原有本地权限策略；Jev 正常路径不运行本地策略。
- Jev 拦截使用 `source=jev decision=deny local_policy=unknown` 文案，不虚构本地权限或 Jev 未返回的风险解释。
- 中英文 README 增加 Jev 决策流程、配置、审计和贡献说明。

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
