<p align="center">
  <img src="docs/assets/logo.svg" alt="Bash Guard 标识" width="112" height="112">
</p>

# Bash Guard

<p align="center">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-safety_runtime-dea584?logo=rust&logoColor=white">
  <img alt="Claude Code Hook" src="https://img.shields.io/badge/Claude_Code-PreToolUse_Hook-77a8ff">
  <img alt="Codex Hook" src="https://img.shields.io/badge/Codex-PreToolUse_Bash_Hook-10a37f">
  <img alt="失败关闭" src="https://img.shields.io/badge/安全策略-失败关闭-42d39b">
  <img alt="MIT 许可证" src="https://img.shields.io/badge/许可证-MIT-42d39b">
  <img alt="预览状态" src="https://img.shields.io/badge/状态-预览-f59e68">
</p>

[English](README.md) · [权限策略](https://github.com/lloydzhou/bash-agent/blob/main/docs/bash-tool-policy.md) · [发布页](https://github.com/lloydzhou/claude-bash-guard/releases) · [Homebrew Tap](https://github.com/lloydzhou/homebrew-tap)

**面向 Claude Code 和 Codex 的失败关闭工具安全闸门。** Bash Guard 借鉴 Linux 文件权限的表述方式，采用最小权限、显式授予和默认拒绝：敏感操作未被策略明确允许时一律拒绝。它会在每次受支持客户端调用 `Bash`、`Read`、`Edit`、`Write`、`Glob` 或 `Grep` 前检查权限；Claude Code 即使启用 `bypassPermissions` 或 `--dangerously-skip-permissions`，检查仍会执行。

```bash
brew tap lloydzhou/tap
brew install bash-guard
bash-guard claude register --scope user
# 或直接注册 Codex。
bash-guard codex register --scope user
```

注册后检查状态：

```bash
bash-guard claude status
```

## 为什么使用 Bash Guard

- **绕过权限时依然生效。** `PreToolUse` Hook 早于受支持客户端的权限判定执行。
- **失败关闭。** 二进制缺失、Hook 输入无效或审计写入失败时，都会拒绝受保护工具调用，绝不静默放行。
- **借鉴权限语义的最小权限。** 策略使用类似 Linux 文件权限的权限位表达敏感能力；必须显式授予，未授予的能力保持拒绝。它是应用层策略模型，不会实现或修改操作系统文件权限。
- **运行痕迹极小。** 注册只生成极小的本地 Claude Code 插件适配器，记录二进制路径，不复制二进制。
- **默认审计。** JSONL 审计日志记录客户端来源、工具名、每次判定、操作摘要、调用方工作目录与所需权限；写入内容和编辑替换文本只记录长度，不记录原文。
- **策略语义一致。** 命令分类和拒绝文案与 Bash Agent 使用同一份 Rust 策略实现。

## 三步开始

### 一、安装

通过 Homebrew：

```bash
brew tap lloydzhou/tap
brew install bash-guard
```

也可以从 [GitHub 发布页](https://github.com/lloydzhou/claude-bash-guard/releases) 下载对应平台的压缩包。

### 二、注册到 Claude Code

```bash
bash-guard claude register --scope user
```

可用作用域为 `user`、`project`、`local`，默认是 `user`。注册会调用 Claude Code 官方插件命令，添加本地 Marketplace 并安装适配器。

### 三、检查状态

```bash
bash-guard claude status
bash-guard codex status --scope user
```

随后按常规方式启动 Claude Code 或 Codex。已注册作用域内的每个 `Bash`、`Read`、`Edit`、`Write`、`Glob`、`Grep` 工具调用都会自动经过 Bash Guard。`Read`、`Glob`、`Grep` 需要读权限；`Edit`、`Write` 需要写权限；`Bash` 保持原有的命令分类。

### 注册到 Codex

```bash
bash-guard codex register --scope user
# 或写入当前 Git 仓库的 .codex/hooks.json。
bash-guard codex register --scope project
```

Codex 注册仅处理 `PreToolUse` 事件中匹配 `^(Bash|Read|Edit|Write|Glob|Grep)$` 的调用。`user` 作用域会将带标识的命令钩子合并到 `~/.codex/hooks.json`；`project` 作用域会合并到 Git 项目根目录的 `.codex/hooks.json`，已有钩子不会被覆盖。配置命令使用注册时记录的二进制精确路径加 `codex hook`，超时为五秒。Codex 对非托管钩子有审核与信任流程时，应通过其 `/hooks` 工作流完成审核与信任。

`unregister` 只会移除同时具备 Bash Guard 标识、且命令精确匹配注册二进制路径的条目；其它配置一律保留，仅当 `hooks.json` 其余内容为空时才删除该文件。

## 配置权限与审计日志

默认权限模式为 `0467`。四位八进制数从左至右分别控制 system、external、network、workspace 四个作用域；每组内读、写、执行对应 `4`、`2`、`1`：

```text
BASH_GUARD_MODE = 0 4 6 7
                  | | | |
                  | | | `- workspace
                  | | `--- network
                  | `----- external
                  `------- system
```

权限位含义、命令分类、推荐模式及完整示例请查看 [Bash 工具权限策略](https://github.com/lloydzhou/bash-agent/blob/main/docs/bash-tool-policy.md)。

仅为新启动的客户端进程设置权限模式：

```bash
BASH_GUARD_MODE=4447 claude
BASH_GUARD_MODE=4447 codex
```

无效的权限模式会按 `0000` 失败关闭处理。

审计日志默认启用：Claude Code 写入 `$HOME/.claude/bash-guard-audit.jsonl`；Codex 写入 `$HOME/.codex/bash-guard-audit.jsonl`。如需使用其他路径，请在启动客户端前设置 `BASH_GUARD_AUDIT_LOG`：

```bash
BASH_GUARD_AUDIT_LOG="$HOME/logs/bash-guard.jsonl" codex
tail -f "$HOME/logs/bash-guard.jsonl"
```

日志每行是一条 JSON 记录，并含有 `client` 字段（`claude` 或 `codex`）；即使通过环境变量刻意让两个客户端共用同一日志，仍可追溯来源。`cwd` 是客户端为该工具调用提供的工作目录，用于识别命令从哪个项目发起，**并不是**命令实际访问的目标路径。若日志目录无法创建、日志无法写入或同步，Bash Guard 会拒绝该命令。

典型的策略拒绝信息：

```text
command blocked by bash safety policy (required=4000 allowed=0467; mode=system/external/network/workspace bits=4:read,2:write,1:execute)
```

## 注册管理

```bash
# 取消 Claude Code 集成。
bash-guard claude unregister --scope user

# 取消 Codex 集成。
bash-guard codex unregister --scope user

# 如有需要，再卸载 Homebrew 软件包。
brew uninstall bash-guard
```

自动化或非标准安装可使用以下环境变量：

- `BASH_GUARD_BINARY`：覆盖注册时记录的二进制路径。
- `BASH_GUARD_STATE_DIR`：覆盖注册目录；默认是 `~/.claude/bash-guard`。

## 安全边界

Bash Guard 仅保护已注册 Claude Code 或 Codex 钩子发起的 `Bash`、`Read`、`Edit`、`Write`、`Glob`、`Grep` 工具调用。Codex 的 `PreToolUse` 钩子是一项保护措施，并非完整安全边界；Codex 可能存在该钩子未完整覆盖的类 Shell 执行路径或其它工具。拥有主机控制权的用户仍可直接执行系统命令、修改自己的客户端配置，或移除用户级集成。

如需组织级强制策略，管理员应通过受管客户端设置和可信分发渠道强制相应集成，并限制不受信任的配置变更。

## 本地开发

```bash
cargo fmt --check
cargo test
cargo build --release

printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/tmp/project","tool_input":{"command":"cat README.md"}}' \
  ./target/debug/bash-guard codex hook

sh tests/hook.sh ./target/debug/bash-guard
sh tests/codex-registration.sh ./target/debug/bash-guard
```

直接测试仓库适配器前，先构建二进制，并将调试二进制以 `bash-guard` 名称加入 `PATH`：

```bash
PATH="$PWD/target/debug:$PATH" claude --plugin-dir ./plugins/bash-guard
claude plugin validate ./plugins/bash-guard
claude plugin validate .
```

## 项目结构

```text
src/
├── main.rs       # Hook 协议、审计、注册与状态管理
└── policy.rs     # 与 Bash Agent 对齐的权限分类
plugins/bash-guard/
└── hooks/hooks.json  # 直接调用 bash-guard claude hook
```

采用 [MIT 许可证](LICENSE)。
