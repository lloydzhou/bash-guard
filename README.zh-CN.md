<p align="center">
  <img src="docs/assets/logo.svg" alt="Bash Guard 标识" width="112" height="112">
</p>

# Bash Guard

<p align="center">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-safety_runtime-dea584?logo=rust&logoColor=white">
  <img alt="Jev" src="https://img.shields.io/badge/Jev-optional_decision_layer-7c3aed">
  <img alt="Claude Code Hook" src="https://img.shields.io/badge/Claude_Code-PreToolUse_Hook-77a8ff">
  <img alt="Codex Hook" src="https://img.shields.io/badge/Codex-PreToolUse_Bash_Hook-10a37f">
  <img alt="失败关闭" src="https://img.shields.io/badge/安全策略-失败关闭-42d39b">
  <img alt="MIT 许可证" src="https://img.shields.io/badge/许可证-MIT-42d39b">
  <img alt="预览状态" src="https://img.shields.io/badge/状态-预览-f59e68">
</p>

[English](README.md) · [权限策略](https://github.com/lloydzhou/bash-agent/blob/main/docs/bash-tool-policy.md) · [发布页](https://github.com/lloydzhou/claude-bash-guard/releases) · [Homebrew Tap](https://github.com/lloydzhou/homebrew-tap)

> **让 Coding Agent 保持高效，不必把每次工具调用都押上信任。**

**Bash Guard 是面向 Claude Code 和 Codex 的本地优先安全闸门。** 它会在 `Bash`、`Read`、`Edit`、`Write`、`Glob`、`Grep` 执行前拦截调用，执行可审查、可调节的 Rust 权限策略。配置 Jev API key 后，可额外获得带置信度的语义判断；移除 key 后，原有本地策略仍按原样工作。

## 为什么使用 Bash Guard

- **绕过权限时依然生效。** `PreToolUse` Hook 早于受支持客户端的权限判定执行。
- **失败关闭。** 二进制缺失、Hook 输入无效或审计写入失败时，都会拒绝受保护工具调用，绝不静默放行。
- **借鉴权限语义的最小权限。** 策略使用类似 Linux 文件权限的权限位表达敏感能力；必须显式授予，未授予的能力保持拒绝。它是应用层策略模型，不会实现或修改操作系统文件权限。
- **需要语义判断时接入 Jev。** 配置 key 后，Jev 会对准确的操作输出 `allow` 或 `deny` 并返回概率。这正好对应 Codex/Claude Hook：`deny` 输出拦截结果，`allow` 不输出内容并放行。未配置 key 或 Jev 不可用时，Bash Guard 使用本地策略。
- **运行痕迹极小。** 注册只生成极小的本地 Claude Code 插件适配器，记录二进制路径，不复制二进制。
- **默认审计。** JSONL 审计日志记录客户端来源、工具名、每次判定、操作摘要、调用方工作目录与所需权限；写入内容和编辑替换文本只记录长度，不记录原文。
- **策略语义一致。** 命令分类和拒绝文案与 Bash Agent 使用同一份 Rust 策略实现。

## 一次工具调用如何判定

```text
Agent 工具调用
      │
      ├── 未配置 Jev key ───────────► 本地 Rust 策略 ──► 允许 / 拒绝
      │
      └── 已配置 Jev key ───────────► Jev allow / deny + 概率
                                            │
                              API 出错 ────┴──► 本地 Rust 策略
                              deny ───────────────────────► 拒绝
```

本地策略从未被移除：这让 Hook 在离线时仍可用，也为 Jev 错误提供了可预测、可审查的回退路径。

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

## 配置权限、Jev 与审计日志

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

### 可选 Jev 决策层

[Jev](https://typesafe.ai/blog/introducing-system-one-models-and-jev) 是 TypeSafe AI 面向带概率的类型化决策推出的 System One 模型。原有本地策略始终保留为基础路径。未配置 Jev API key 时，Bash Guard 的行为与此前完全一致；配置 key 后，会在工具调用前额外请求 Jev 的 `allow` / `deny` 判断：

```bash
JEV_API_KEY=... JEV_BASE_URL=https://api.typesafe.ai JEV_MODEL=jev-latest claude
```

`JEV_API_KEY` 优先于 `TYPESAFE_API_KEY`；`JEV_BASE_URL`（或 `TYPESAFE_BASE_URL`）会自动拼接 `/v1/systemone`；`JEV_MODEL`（或 `TYPESAFE_DEFAULT_MODEL`）未配置时使用 `jev-latest`。`BASH_GUARD_JEV_API_KEY`、`BASH_GUARD_JEV_ENDPOINT`、`BASH_GUARD_JEV_MODEL` 是 Bash Guard 专用且优先级最高的覆盖项。已配置 Jev 但请求超时、失败或返回无效响应时，会记录错误并回退到原有本地策略。Hook 协议中，`deny` 会拦截，`allow` 会放行；可通过 `BASH_GUARD_JEV_TIMEOUT_MS`（`100`–`30000`）调整请求超时。

Hook 提供的绝对 `cwd` 会以 `workspace_path` 传给 Jev。提示词将其视为工作区边界：外部路径、上级目录逃逸路径或无法确定的目标都应拒绝。它是客户端声明的工作目录，并非另行发现的 Git 根目录。

Jev 还会收到规范化后的当前 `BASH_GUARD_MODE` 与完整策略契约：`system / external / network / workspace` 的 scope 顺序；受保护系统及凭据路径、外部路径、网络读写与远程执行、工作区操作的精确定义；以及 `read=4`、`write=2`、`execute=1` 的权限语义。提示词要求将该契约视为权威定义：操作所需的每一个能力都必须由四位八进制模式显式授予，否则选择 `deny`。

Jev 拦截时，文案会标明 `source=jev decision=deny local_policy=unknown`。正常 Jev 路径不会运行本地策略，因此不应虚构本地所需权限、当前授权或具体风险解释；只有无 key 与 Jev 出错后的回退路径才会输出原有策略文案。

审计日志默认启用：Claude Code 写入 `$HOME/.claude/bash-guard-audit.jsonl`；Codex 写入 `$HOME/.codex/bash-guard-audit.jsonl`。如需使用其他路径，请在启动客户端前设置 `BASH_GUARD_AUDIT_LOG`：

```bash
BASH_GUARD_AUDIT_LOG="$HOME/logs/bash-guard.jsonl" codex
tail -f "$HOME/logs/bash-guard.jsonl"
```

日志每行是一条 JSON 记录，并含有 `client` 字段（`claude` 或 `codex`）；即使通过环境变量刻意让两个客户端共用同一日志，仍可追溯来源。`cwd` 是客户端为该工具调用提供的工作目录，用于识别命令从哪个项目发起，**并不是**命令实际访问的目标路径。启用 Jev 后，日志还会记录 `decision_source`、选择、概率、模型，以及回退时的 `jev_error`；命令摘要在写入审计和发送 Jev 前会脱敏常见凭据参数。若日志目录无法创建、日志无法写入或同步，Bash Guard 会拒绝该命令。

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

## 参与贡献

欢迎提交 Issue 和 Pull Request。涉及策略或 Hook 协议的改动请补充覆盖，并在发起 PR 前运行下列检查。

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
├── jev.rs        # 可选 TypeSafe Jev 决策客户端与响应校验
└── policy.rs     # 与 Bash Agent 对齐的权限分类
plugins/bash-guard/
└── hooks/hooks.json  # 直接调用 bash-guard claude hook
```

采用 [MIT 许可证](LICENSE)。
