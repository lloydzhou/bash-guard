# 变更记录

本项目遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## 0.1.2 - 2026-03-23

### 变更

- 审计日志默认写入 `$HOME/.claude/bash-guard-audit.jsonl`，无需设置环境变量即可记录决策。
- `BASH_GUARD_AUDIT_LOG` 设置为非空值时，继续使用其指定的自定义日志路径。
- 空值 `BASH_GUARD_AUDIT_LOG` 回退到默认日志路径。
- 无法解析或写入审计日志时保持失败关闭，拒绝对应 Bash 命令。
- 移除插件启动脚本；静态插件通过 `PATH` 直接调用 `bash-guard claude hook`，注册生成的适配器则直接调用记录的绝对二进制路径。
