# Bash Guard

Bash Guard 是独立分发的 Rust 安全程序。它通过 Claude Code 的 `PreToolUse` Hook，在 `Bash` 工具执行前按权限模式分类命令并在超出允许范围时拒绝执行。

Hook 在 Claude Code 权限模式检查之前运行，因此即使启用 `bypassPermissions` 或 `--dangerously-skip-permissions`，策略拒绝仍然生效。

> 权限模型、分类边界、推荐模式和完整示例由 [Bash Agent 的 Bash 工具权限策略文档](https://github.com/lloydzhou/bash-agent/blob/main/docs/bash-tool-policy.md) 统一维护。Bash Guard 直接使用同一套 Rust 分类规则，不在此重复维护策略细节。

## 安装与注册

先用系统包管理器或发布压缩包安装 `bash-guard`，确保它位于稳定的可执行路径中：

```bash
bash-guard claude register --scope user
```

注册命令会生成一个极小的本地 Claude Code 插件源、调用 Claude Code 官方插件命令完成安装，并记录二进制绝对路径；它不会复制二进制。支持的作用域为 `user`、`project` 与 `local`，默认 `user`。

检查状态：

```bash
bash-guard claude status
```

取消注册后再卸载系统包：

```bash
bash-guard claude unregister --scope user
```

注册的适配器在二进制缺失、不可执行或异常退出时会明确拒绝 Bash，绝不静默放行。

## 配置与审计

保留原有环境变量兼容性：

```bash
# 默认值为 0467；权限位的含义见 Bash Agent 策略文档。
BASH_GUARD_MODE=4447 claude

# 每次判定追加一条 JSONL 审计记录；无法写入时按失败关闭处理。
BASH_GUARD_AUDIT_LOG="$HOME/.claude/bash-guard-audit.jsonl" claude
```

无效权限模式按 `0000` 处理。拒绝策略命令时，信息与 Bash Agent 保持一致：

```text
command blocked by bash safety policy (required=4000 allowed=0467; mode=system/external/network/workspace bits=4:read,2:write,1:execute)
```

## 本地开发

```bash
cargo fmt --check
cargo test
cargo build --release

# 直接以当前构建产物验证 Hook 协议。
printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/tmp/project","tool_input":{"command":"cat README.md"}}' \
  ./target/debug/bash-guard claude hook
```

开发时可用以下方式直接加载仓库插件适配器；需先构建并让 `bash-guard` 位于 `PATH`，或设置 `BASH_GUARD_BINARY`：

```bash
BASH_GUARD_BINARY="$PWD/target/debug/bash-guard" claude --plugin-dir ./plugins/bash-guard
claude plugin validate ./plugins/bash-guard
claude plugin validate .
```

## 发布与家酿

发布工作流构建苹果芯片、英特尔苹果系统、Linux x86_64 与 Linux ARM64 的压缩包，并为每个压缩包生成 SHA-256 摘要。发布家酿配方时，将 `Formula/bash-guard.rb` 中的占位摘要替换为对应 `.sha256` 文件内容，再提交到家酿软件源。

## 企业部署

普通用户安装的插件可以被用户禁用或卸载。如需组织级策略，请由管理员在受管设置中配置可信 Marketplace、强制启用插件、限制 Marketplace 来源并禁止侧载插件。插件 Hook 仅控制 Claude Code 的 Bash 工具调用，不能阻止拥有主机控制权的用户直接运行系统命令。

## 项目结构

```text
src/
├── main.rs       # Hook、审计、注册与状态管理
└── policy.rs     # 与 Bash Agent 对齐的权限分类
plugins/bash-guard/
└── scripts/bash-guard  # 仅负责启动二进制的失败关闭适配器
```
