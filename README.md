<p align="center">
  <img src="docs/assets/logo.svg" alt="Bash Guard logo" width="112" height="112">
</p>

# Bash Guard

<p align="center">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-safety_runtime-dea584?logo=rust&logoColor=white">
  <img alt="Claude Code Hook" src="https://img.shields.io/badge/Claude_Code-PreToolUse_Hook-77a8ff">
  <img alt="Codex Hook" src="https://img.shields.io/badge/Codex-PreToolUse_Bash_Hook-10a37f">
  <img alt="fail closed" src="https://img.shields.io/badge/security-fail--closed-42d39b">
  <img alt="license MIT" src="https://img.shields.io/badge/license-MIT-42d39b">
  <img alt="status preview" src="https://img.shields.io/badge/status-preview-f59e68">
</p>

[中文说明](README.zh-CN.md) · [Security policy](https://github.com/lloydzhou/bash-agent/blob/main/docs/bash-tool-policy.md) · [Releases](https://github.com/lloydzhou/claude-bash-guard/releases) · [Homebrew Tap](https://github.com/lloydzhou/homebrew-tap)

**A fail-closed tool safety gate for Claude Code and Codex.** Inspired by Linux file permissions, Bash Guard uses least privilege, explicit grants, and default deny: sensitive operations are denied unless policy explicitly allows them. It checks every supported `Bash`, `Read`, `Edit`, `Write`, `Glob`, and `Grep` tool call before it runs, including when Claude Code uses `bypassPermissions` or `--dangerously-skip-permissions`.

```bash
brew tap lloydzhou/tap
brew install bash-guard
bash-guard claude register --scope user
# Or register Codex directly.
bash-guard codex register --scope user
```

After registration, verify the installation:

```bash
bash-guard claude status
```

## Why Bash Guard

- **Still enforced when permissions are bypassed.** The `PreToolUse` Hook runs before the supported client's permission decision.
- **Fail closed.** A missing binary, invalid Hook input, or audit-write failure denies the protected tool call instead of silently allowing it.
- **Permission-inspired least privilege.** The policy expresses sensitive capabilities with Linux-file-permission-inspired bits; grants must be explicit, and ungranted capabilities stay denied. It is an application policy model, not an operating-system file-permission implementation.
- **Small operational footprint.** Registration creates a minimal local Claude Code plugin adapter; it records the binary path and never copies the binary.
- **Auditable by default.** JSONL audit records capture the client, tool name, each decision, operation summary, caller working directory, and policy requirement. Write content and Edit replacement text are recorded only as lengths.
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
bash-guard codex status --scope user
```

Start Claude Code or Codex normally. Bash Guard is invoked automatically for each `Bash`, `Read`, `Edit`, `Write`, `Glob`, and `Grep` tool call in the registered scope. `Read`, `Glob`, and `Grep` require read permission; `Edit` and `Write` require write permission; `Bash` keeps its existing command classification.

### Register with Codex

```bash
bash-guard codex register --scope user
# Or write to the current Git repository's .codex/hooks.json.
bash-guard codex register --scope project
```

Codex registration only handles its `PreToolUse` event with matcher `^(Bash|Read|Edit|Write|Glob|Grep)$`. It merges a marked command hook into `~/.codex/hooks.json` for `user`, or the Git project root's `.codex/hooks.json` for `project`; existing hooks are preserved. The configured command is the exact registered binary path followed by `codex hook`, with a five-second timeout. Review and trust the unmanaged hook through Codex's `/hooks` workflow as required by Codex.

`unregister` removes only an entry that carries the Bash Guard marker and exactly matches the binary path recorded at registration. It preserves all other configuration, and deletes `hooks.json` only when the file would otherwise be empty.

## Configure policy and audit logging

The default policy mode is `0467`. The four octal digits control the system, external, network, and workspace scopes from left to right; within each group, read, write, and execute map to `4`, `2`, and `1`:

```text
BASH_GUARD_MODE = 0 4 6 7
                  | | | |
                  | | | `- workspace
                  | | `--- network
                  | `----- external
                  `------- system
```

See the [Bash tool policy](https://github.com/lloydzhou/bash-agent/blob/main/docs/bash-tool-policy.md) for permission bits, command categories, recommended modes, and examples.

Set a mode only for the client process you start:

```bash
BASH_GUARD_MODE=4447 claude
BASH_GUARD_MODE=4447 codex
```

Invalid modes fail closed as `0000`.

Audit logging is enabled by default. Claude Code writes to `$HOME/.claude/bash-guard-audit.jsonl`; Codex writes to `$HOME/.codex/bash-guard-audit.jsonl`. To use another path, set `BASH_GUARD_AUDIT_LOG` before launching the client:

```bash
BASH_GUARD_AUDIT_LOG="$HOME/logs/bash-guard.jsonl" codex
tail -f "$HOME/logs/bash-guard.jsonl"
```

Every line is one JSON object and includes `client` (`claude` or `codex`), so a deliberately shared override path remains attributable. `cwd` records the working directory supplied by the client for that tool call; it is useful for identifying the originating project and is not the path being accessed by the command. If the log directory cannot be created, written, or synchronized, Bash Guard denies the command.

A typical policy denial is:

```text
command blocked by bash safety policy (required=4000 allowed=0467; mode=system/external/network/workspace bits=4:read,2:write,1:execute)
```

## Manage registration

```bash
# Remove the Claude Code integration.
bash-guard claude unregister --scope user

# Remove the Codex integration.
bash-guard codex unregister --scope user

# Then remove the Homebrew package, if desired.
brew uninstall bash-guard
```

For automation or nonstandard installations:

- `BASH_GUARD_BINARY` overrides the binary path recorded by registration.
- `BASH_GUARD_STATE_DIR` overrides the registration directory (default: `~/.claude/bash-guard`).

## Security boundaries

Bash Guard protects only `Bash`, `Read`, `Edit`, `Write`, `Glob`, and `Grep` tool calls issued through registered Claude Code or Codex hooks. Codex `PreToolUse` hooks are a protective control, not a complete security boundary; Codex may expose shell-like execution paths or other tools not covered by this hook. A user who controls the host can still run shell commands directly, alter their own client configuration, or remove a user-installed integration.

For organization-wide enforcement, administrators should use managed client settings and trusted distribution channels to require the appropriate integration and restrict untrusted configuration changes.

## Development

```bash
cargo fmt --check
cargo test
cargo build --release

printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/tmp/project","tool_input":{"command":"cat README.md"}}' \
  ./target/debug/bash-guard codex hook

sh tests/hook.sh ./target/debug/bash-guard
sh tests/codex-registration.sh ./target/debug/bash-guard
```

To test the repository adapter directly, build the binary first and expose the debug binary as `bash-guard` on `PATH`:

```bash
PATH="$PWD/target/debug:$PATH" claude --plugin-dir ./plugins/bash-guard
claude plugin validate ./plugins/bash-guard
claude plugin validate .
```

## Project layout

```text
src/
├── main.rs       # Hook protocol, audit logging, registration, and status
└── policy.rs     # Permission classification aligned with Bash Agent
plugins/bash-guard/
└── hooks/hooks.json  # Directly invokes bash-guard claude hook
```

Licensed under the [MIT License](LICENSE).
