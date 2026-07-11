<p align="center">
  <img src="docs/assets/logo.svg" alt="Bash Guard logo" width="112" height="112">
</p>

# Bash Guard

<p align="center">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-safety_runtime-dea584?logo=rust&logoColor=white">
  <img alt="Claude Code Hook" src="https://img.shields.io/badge/Claude_Code-PreToolUse_Hook-77a8ff">
  <img alt="fail closed" src="https://img.shields.io/badge/security-fail--closed-42d39b">
  <img alt="license MIT" src="https://img.shields.io/badge/license-MIT-42d39b">
  <img alt="status preview" src="https://img.shields.io/badge/status-preview-f59e68">
</p>

[中文说明](README.zh-CN.md) · [Security policy](https://github.com/lloydzhou/bash-agent/blob/main/docs/bash-tool-policy.md) · [Releases](https://github.com/lloydzhou/claude-bash-guard/releases) · [Homebrew Tap](https://github.com/lloydzhou/homebrew-tap)

**A fail-closed Bash safety gate for Claude Code.** Bash Guard checks every Claude Code `Bash` tool call before it runs, including when Claude Code uses `bypassPermissions` or `--dangerously-skip-permissions`.

```bash
brew tap lloydzhou/tap
brew install bash-guard
bash-guard claude register --scope user
```

After registration, verify the installation:

```bash
bash-guard claude status
```

## Why Bash Guard

- **Still enforced when permissions are bypassed.** The `PreToolUse` Hook runs before Claude Code's permission decision.
- **Fail closed.** A missing binary, invalid Hook input, or audit-write failure denies the Bash call instead of silently allowing it.
- **Small operational footprint.** Registration creates a minimal local Claude Code plugin adapter; it records the binary path and never copies the binary.
- **Auditable when you need it.** Optional JSONL audit records capture each decision, command, caller working directory, and policy requirement.
- **Shared policy semantics.** Command classification uses the same Rust policy implementation and denial wording as Bash Agent.

## Quick start

### 1. Install

Homebrew:

```bash
brew tap lloydzhou/tap
brew install bash-guard
```

Or download the archive for your platform from [GitHub Releases](https://github.com/lloydzhou/claude-bash-guard/releases).

### 2. Register with Claude Code

```bash
bash-guard claude register --scope user
```

Scopes are `user`, `project`, and `local`; `user` is the default. Registration uses the official Claude Code plugin CLI to add a local Marketplace and install the adapter.

### 3. Check it

```bash
bash-guard claude status
```

Start Claude Code normally. Bash Guard is invoked automatically for each `Bash` tool call in the registered scope.

## Configure policy and audit logging

The default policy mode is `0467`. See the [Bash tool policy](https://github.com/lloydzhou/bash-agent/blob/main/docs/bash-tool-policy.md) for permission bits, command categories, recommended modes, and examples.

Set a mode only for the Claude Code process you start:

```bash
BASH_GUARD_MODE=4447 claude
```

Invalid modes fail closed as `0000`.

Audit logging is **disabled by default**. To enable it, set a non-empty log path before launching Claude Code:

```bash
export BASH_GUARD_AUDIT_LOG="$HOME/.claude/bash-guard-audit.jsonl"
claude
tail -f "$BASH_GUARD_AUDIT_LOG"
```

Every line is one JSON object. `cwd` records the working directory supplied by Claude Code for that tool call; it is useful for identifying the originating project and is not the path being accessed by the command. If the log directory cannot be created, written, or synchronized, Bash Guard denies the command.

A typical policy denial is:

```text
command blocked by bash safety policy (required=4000 allowed=0467; mode=system/external/network/workspace bits=4:read,2:write,1:execute)
```

## Manage registration

```bash
# Remove the Claude Code integration.
bash-guard claude unregister --scope user

# Then remove the Homebrew package, if desired.
brew uninstall bash-guard
```

For automation or nonstandard installations:

- `BASH_GUARD_BINARY` overrides the binary path recorded by registration.
- `BASH_GUARD_STATE_DIR` overrides the registration directory (default: `~/.claude/bash-guard`).

## Security boundaries

Bash Guard protects only `Bash` tool calls issued through Claude Code. A user who controls the host can still run shell commands directly, alter their own Claude Code installation, or remove a user-installed plugin.

For organization-wide enforcement, administrators should use managed Claude Code settings to restrict Marketplace sources, configure a trusted Marketplace, require the plugin, and prevent sideloaded plugins where appropriate.

## Development

```bash
cargo fmt --check
cargo test
cargo build --release

printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/tmp/project","tool_input":{"command":"cat README.md"}}' \
  ./target/debug/bash-guard claude hook
```

To test the repository adapter directly, build the binary first and either expose `bash-guard` on `PATH` or set `BASH_GUARD_BINARY`:

```bash
BASH_GUARD_BINARY="$PWD/target/debug/bash-guard" claude --plugin-dir ./plugins/bash-guard
claude plugin validate ./plugins/bash-guard
claude plugin validate .
```

## Project layout

```text
src/
├── main.rs       # Hook protocol, audit logging, registration, and status
└── policy.rs     # Permission classification aligned with Bash Agent
plugins/bash-guard/
└── scripts/bash-guard  # Fail-closed binary launcher only
```

Licensed under the [MIT License](LICENSE).
