# Bash Guard

Bash Guard 是按 Claude Code 官方插件规范发布的 `PreToolUse` 安全 Hook。它在 `Bash` 工具执行前分类命令所需权限，并在超出允许模式时返回 `permissionDecision: "deny"`。

`PreToolUse` 先于 Claude Code 权限模式检查执行，因此拒绝结果在 `bypassPermissions` 和 `--dangerously-skip-permissions` 下仍然有效。

拒绝信息与 Bash Agent 保持一致，例如：

```text
command blocked by bash safety policy (required=4000 allowed=0467; mode=system/external/network/workspace bits=4:read,2:write,1:execute)
```

## 权限模式

模式是四位八进制数：

```text
system / external / network / workspace
```

每一位使用标准 `rwx` 位：

- `4`：读
- `2`：写
- `1`：执行

默认模式为 `0467`：

- 系统路径：禁止
- 工作区外路径：只读
- 网络：读写
- 工作区：读写执行

无效模式按 `0000` 处理，失败关闭。

## 官方开发方式

直接从源码目录加载插件：

```bash
claude --plugin-dir ./plugins/bash-guard
```

在 Claude Code 中运行 `/hooks`，确认 `PreToolUse` 下存在来自 `bash-guard` 插件且匹配 `Bash` 的 Hook。

## 官方 Marketplace 安装

本地验证 Marketplace：

```bash
claude plugin validate .
claude plugin marketplace add . --scope user
claude plugin install bash-guard@bash-guard-marketplace --scope user
```

交互界面中的等价命令：

```text
/plugin marketplace add /绝对路径/claude-bash-guard
/plugin install bash-guard@bash-guard-marketplace
/reload-plugins
```

卸载：

```bash
claude plugin uninstall bash-guard@bash-guard-marketplace --scope user
claude plugin marketplace remove bash-guard-marketplace --scope user
```

正式发布时，将本仓库推送到 GitHub，然后用户按官方方式安装：

```text
/plugin marketplace add 所有者/仓库
/plugin install bash-guard@bash-guard-marketplace
```

## 配置

当前最低兼容版本为本机已验证的 Claude Code `2.1.68`。该版本的插件清单尚不识别新版 `userConfig` 字段，因此策略配置使用进程环境变量，不手工修改 Hook 设置。

### `BASH_GUARD_MODE`

四位八进制权限模式，默认 `0467`：

```bash
BASH_GUARD_MODE=4447 claude
```

### `BASH_GUARD_AUDIT_LOG`

可选的审计日志文件。每次判定写入一条 JSON 记录：

```bash
BASH_GUARD_AUDIT_LOG="$HOME/.claude/bash-guard-audit.jsonl" claude
```

新版 Claude Code 已支持插件 `userConfig`。后续提高最低版本后，可把这两个环境变量迁移为官方安装/启用时的配置项。

## 测试

```bash
python3 -m unittest discover -s plugins/bash-guard/tests -p 'test_*.py' -v
claude plugin validate ./plugins/bash-guard
claude plugin validate .
```

## 企业强制部署

普通用户安装的插件可以被用户禁用或卸载。若要形成组织级策略，应由管理员：

1. 在受管设置中通过 `extraKnownMarketplaces` 配置可信 Marketplace。
2. 在受管设置的 `enabledPlugins` 中强制启用 `bash-guard@bash-guard-marketplace`。
3. 配置 `strictKnownMarketplaces` 限制 Marketplace 来源。
4. 配置 `disableSideloadFlags` 禁止通过启动参数侧载插件。
5. 需要时启用 `allowManagedHooksOnly`；由受管设置强制启用的插件 Hook 仍可执行。

插件 Hook 能阻止 Claude Code 的 Bash 工具调用，但不能防止拥有主机控制权的用户卸载插件、修改受管策略或直接在 Claude Code 外执行命令。

## 项目结构

```text
.claude-plugin/marketplace.json
plugins/bash-guard/
├── .claude-plugin/plugin.json
├── hooks/hooks.json
├── scripts/bash-guard
├── lib/bash_guard/policy.py
└── tests/test_policy.py
```
