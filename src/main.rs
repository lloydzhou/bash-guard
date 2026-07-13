mod policy;

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const MARKETPLACE_NAME: &str = "bash-guard-marketplace";
const PLUGIN_NAME: &str = "bash-guard";
const MAX_HOOK_INPUT_BYTES: u64 = 1024 * 1024;
const DEFAULT_AUDIT_LOG_FILE: &str = "bash-guard-audit.jsonl";
const CODEX_HOOK_MARKER: &str = "Bash Guard: checking native tool permissions";
const TOOL_MATCHER: &str = "Bash|Read|Edit|Write|Glob|Grep";
const CODEX_TOOL_MATCHER: &str = "^(Bash|Read|Edit|Write|Glob|Grep)$";
const CODEX_STATE_FILE_PREFIX: &str = "registration-";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Bash Guard：{error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [client, subcommand]
            if matches!(client.as_str(), "claude" | "codex") && subcommand == "hook" =>
        {
            hook(client)
        }
        [client, command, rest @ ..] if client == "claude" => claude_command(command, rest),
        [client, command, rest @ ..] if client == "codex" => codex_command(command, rest),
        _ => Err("用法：bash-guard <claude|codex> <hook|register|unregister|status> [--scope user|project|local]".to_string()),
    }
}

struct HookOperation<'a> {
    tool_name: &'a str,
    policy_probe: String,
    description: String,
    input_summary: Value,
    command: Option<&'a str>,
}

fn hook(client: &str) -> Result<(), String> {
    let mut payload = Vec::new();
    io::stdin()
        .take(MAX_HOOK_INPUT_BYTES + 1)
        .read_to_end(&mut payload)
        .map_err(|error| format!("读取 Hook 输入失败：{error}"))?;
    if payload.len() as u64 > MAX_HOOK_INPUT_BYTES {
        emit_deny("Bash Guard Hook 输入超过允许大小，已按失败关闭处理");
        return Ok(());
    }

    let event: Value = match serde_json::from_slice(&payload) {
        Ok(event) => event,
        Err(_) => {
            emit_deny("Bash Guard 无法解析 Hook 输入，已按失败关闭处理");
            return Ok(());
        }
    };
    if event.get("hook_event_name").and_then(Value::as_str) != Some("PreToolUse")
        || !event
            .get("tool_name")
            .and_then(Value::as_str)
            .is_some_and(is_supported_tool)
    {
        emit_deny("Bash Guard 收到非预期 Hook 事件，已按失败关闭处理");
        return Ok(());
    }
    let Some(cwd) = event
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|cwd| !cwd.is_empty())
    else {
        emit_deny("Bash Guard 未收到有效工作目录，已按失败关闭处理");
        return Ok(());
    };
    let operation = match parse_operation(&event) {
        Ok(operation) => operation,
        Err(reason) => {
            emit_deny(&reason);
            return Ok(());
        }
    };

    let decision = policy::evaluate(
        &operation.policy_probe,
        cwd,
        env::var("BASH_GUARD_MODE").ok().as_deref(),
    );
    let audit = json!({
        "time": OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_else(|_| "时间格式化失败".to_string()),
        "client": client,
        "session_id": event.get("session_id"),
        "tool_use_id": event.get("tool_use_id"),
        "permission_mode": event.get("permission_mode"),
        "tool_name": operation.tool_name,
        "cwd": cwd,
        "command": operation.command,
        "operation": operation.description,
        "tool_input_summary": operation.input_summary,
        "allowed": decision.allowed,
        "allowed_mode": decision.allowed_mode,
        "required_mode": decision.required_mode,
        "reason": decision.reason,
    });
    if let Err(error) = audit_log_path(client).and_then(|path| append_audit(path, &audit)) {
        emit_deny(&format!(
            "Bash Guard 审计日志写入失败，已按失败关闭处理：{error}"
        ));
        return Ok(());
    }
    if !decision.allowed {
        emit_deny(&decision.reason);
    }
    Ok(())
}

fn is_supported_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "Bash" | "Read" | "Edit" | "Write" | "Glob" | "Grep"
    )
}

fn parse_operation(event: &Value) -> Result<HookOperation<'_>, String> {
    let tool_name = event
        .get("tool_name")
        .and_then(Value::as_str)
        .expect("已验证 tool_name");
    let input = event
        .get("tool_input")
        .and_then(Value::as_object)
        .ok_or_else(|| "Bash Guard 未收到有效工具输入，已按失败关闭处理".to_string())?;
    let required_string = |field: &str| {
        input
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| format!("Bash Guard 未收到有效的 {tool_name}.{field}，已按失败关闭处理"))
    };
    let required_string_allow_empty = |field: &str| {
        input
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Bash Guard 未收到有效的 {tool_name}.{field}，已按失败关闭处理"))
    };

    match tool_name {
        "Bash" => {
            let command = required_string("command")
                .map_err(|_| "Bash Guard 未收到有效的 Bash 命令，已按失败关闭处理".to_string())?;
            Ok(HookOperation {
                tool_name,
                policy_probe: command.to_string(),
                description: "执行 Bash 命令".to_string(),
                input_summary: json!({"command": command}),
                command: Some(command),
            })
        }
        "Read" => {
            let path = required_string("file_path")?;
            Ok(read_operation(tool_name, path, json!({"file_path": path})))
        }
        "Write" => {
            let path = required_string("file_path")?;
            let content = required_string_allow_empty("content")?;
            Ok(write_operation(
                tool_name,
                path,
                json!({"file_path": path, "content_bytes": content.len()}),
            ))
        }
        "Edit" => {
            let path = required_string("file_path")?;
            let old_string = required_string_allow_empty("old_string")?;
            let new_string = required_string_allow_empty("new_string")?;
            Ok(write_operation(
                tool_name,
                path,
                json!({
                    "file_path": path,
                    "old_string_bytes": old_string.len(),
                    "new_string_bytes": new_string.len(),
                }),
            ))
        }
        "Grep" => {
            let path = required_string("path")?;
            let pattern = required_string_allow_empty("pattern")?;
            Ok(read_operation(
                tool_name,
                path,
                json!({"path": path, "pattern_bytes": pattern.len()}),
            ))
        }
        "Glob" => {
            let pattern = required_string("pattern")?;
            let path = input
                .get("path")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty());
            if path.is_none() && glob_pattern_requires_system_scope(pattern) {
                return Err("Bash Guard 无法安全确定 Glob 搜索范围，已按失败关闭处理".to_string());
            }
            let policy_probe = match path {
                Some(path) => format!("cat {path} {pattern}"),
                None => format!("cat {pattern}"),
            };
            Ok(HookOperation {
                tool_name,
                policy_probe,
                description: format!("读取 Glob 搜索范围：{}", path.unwrap_or("当前工作目录")),
                input_summary: json!({"path": path, "pattern": pattern}),
                command: None,
            })
        }
        _ => unreachable!("已验证 tool_name"),
    }
}

fn read_operation<'a>(
    tool_name: &'a str,
    path: &'a str,
    input_summary: Value,
) -> HookOperation<'a> {
    HookOperation {
        tool_name,
        policy_probe: format!("cat {path}"),
        description: format!("读取路径：{path}"),
        input_summary,
        command: None,
    }
}

fn write_operation<'a>(
    tool_name: &'a str,
    path: &'a str,
    input_summary: Value,
) -> HookOperation<'a> {
    HookOperation {
        tool_name,
        policy_probe: format!(": > {path}"),
        description: format!("写入路径：{path}"),
        input_summary,
        command: None,
    }
}

fn glob_pattern_requires_system_scope(pattern: &str) -> bool {
    pattern.starts_with('/') || pattern.split('/').any(|part| part == "..")
}

fn emit_deny(reason: &str) {
    let output = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    });
    println!(
        "{}",
        serde_json::to_string(&output).expect("固定 JSON 可序列化")
    );
}

fn audit_log_path(client: &str) -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("BASH_GUARD_AUDIT_LOG").filter(|path| !path.is_empty()) {
        return expand_path(PathBuf::from(path));
    }
    let home =
        env::var_os("HOME").ok_or_else(|| "未设置 HOME，无法确定审计日志路径".to_string())?;
    let client_dir = match client {
        "claude" => ".claude",
        "codex" => ".codex",
        _ => return Err(format!("未知审计客户端：{client}")),
    };
    Ok(PathBuf::from(home)
        .join(client_dir)
        .join(DEFAULT_AUDIT_LOG_FILE))
}

fn append_audit(path: PathBuf, record: &Value) -> Result<(), String> {
    let path = expand_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| "审计日志路径没有父目录".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    serde_json::to_writer(&mut file, record).map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    file.sync_data().map_err(|error| error.to_string())
}

fn claude_command(command: &str, args: &[String]) -> Result<(), String> {
    let scope = parse_scope(args)?;
    match command {
        "register" => register(&scope),
        "unregister" => unregister(&scope),
        "status" => status(),
        _ => Err("未知 Claude 子命令；可用值为 hook、register、unregister、status".to_string()),
    }
}

fn codex_command(command: &str, args: &[String]) -> Result<(), String> {
    let scope = parse_codex_scope(args)?;
    match command {
        "register" => register_codex(&scope),
        "unregister" => unregister_codex(&scope),
        "status" => status_codex(&scope),
        _ => Err("未知 Codex 子命令；可用值为 hook、register、unregister、status".to_string()),
    }
}

fn parse_scope(args: &[String]) -> Result<String, String> {
    match args {
        [] => Ok("user".to_string()),
        [flag, scope]
            if flag == "--scope" && matches!(scope.as_str(), "user" | "project" | "local") =>
        {
            Ok(scope.clone())
        }
        _ => Err("作用域必须是 --scope user、--scope project 或 --scope local".to_string()),
    }
}

fn parse_codex_scope(args: &[String]) -> Result<String, String> {
    match args {
        [] => Ok("user".to_string()),
        [flag, scope] if flag == "--scope" && matches!(scope.as_str(), "user" | "project") => {
            Ok(scope.clone())
        }
        _ => Err("Codex 作用域必须是 --scope user 或 --scope project".to_string()),
    }
}

fn register(scope: &str) -> Result<(), String> {
    let binary = stable_binary_path()?;
    let root = registration_root()?;
    write_adapter(&root, &binary)?;
    run_claude(["plugin", "validate", root.to_string_lossy().as_ref()])?;
    run_claude([
        "plugin",
        "validate",
        root.join("plugins/bash-guard").to_string_lossy().as_ref(),
    ])?;

    let marketplaces = claude_json(["plugin", "marketplace", "list", "--json"])?;
    let registered = marketplaces.as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item.get("name").and_then(Value::as_str) == Some(MARKETPLACE_NAME))
    });
    if !registered {
        run_claude([
            "plugin",
            "marketplace",
            "add",
            root.to_string_lossy().as_ref(),
            "--scope",
            scope,
        ])?;
    }

    if !plugin_installed_in_scope(scope)? {
        run_claude([
            "plugin",
            "install",
            &format!("{PLUGIN_NAME}@{MARKETPLACE_NAME}"),
            "--scope",
            scope,
        ])?;
    }
    write_registration_state(&root, scope, &binary)?;
    println!(
        "Bash Guard 已注册：作用域 {scope}，二进制 {}",
        binary.display()
    );
    Ok(())
}

fn unregister(scope: &str) -> Result<(), String> {
    if plugin_installed_in_scope(scope)? {
        run_claude([
            "plugin",
            "uninstall",
            &format!("{PLUGIN_NAME}@{MARKETPLACE_NAME}"),
            "--scope",
            scope,
        ])?;
    }
    let marketplaces = claude_json(["plugin", "marketplace", "list", "--json"])?;
    if marketplaces.as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item.get("name").and_then(Value::as_str) == Some(MARKETPLACE_NAME))
    }) {
        run_claude(["plugin", "marketplace", "remove", MARKETPLACE_NAME])?;
    }
    let root = registration_root()?;
    let _ = fs::remove_file(root.join("registration.json"));
    println!("Bash Guard 已取消注册：作用域 {scope}");
    Ok(())
}

fn status() -> Result<(), String> {
    let root = registration_root()?;
    let state = fs::read_to_string(root.join("registration.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let installed = plugin_installed()?;
    let marketplace = claude_json(["plugin", "marketplace", "list", "--json"])?
        .as_array()
        .is_some_and(|items| {
            items
                .iter()
                .any(|item| item.get("name").and_then(Value::as_str) == Some(MARKETPLACE_NAME))
        });
    println!("二进制：{}", stable_binary_path()?.display());
    println!("适配器：{}", root.display());
    println!(
        "本地插件源：{}",
        if marketplace {
            "已注册"
        } else {
            "未注册"
        }
    );
    println!("插件：{}", if installed { "已安装" } else { "未安装" });
    if let Some(state) = state {
        println!(
            "记录的作用域：{}",
            state.get("scope").and_then(Value::as_str).unwrap_or("未知")
        );
    }
    Ok(())
}

fn register_codex(scope: &str) -> Result<(), String> {
    let binary = stable_binary_path()?;
    let config = codex_hooks_path(scope)?;
    let mut root = read_codex_hooks_config(&config)?;
    let hooks = root
        .as_object_mut()
        .expect("已验证 Codex Hook 配置根节点为对象")
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let hooks = hooks
        .as_object_mut()
        .ok_or_else(|| format!("Codex Hook 配置 {} 的 hooks 必须是对象", config.display()))?;
    let pre_tool_use = hooks.entry("PreToolUse").or_insert_with(|| json!([]));
    let entries = pre_tool_use.as_array_mut().ok_or_else(|| {
        format!(
            "Codex Hook 配置 {} 的 hooks.PreToolUse 必须是数组",
            config.display()
        )
    })?;
    let command = codex_hook_command(&binary);
    let entry = codex_hook_entry(&command);
    if !entries
        .iter()
        .any(|existing| is_our_codex_hook(existing, &command))
    {
        entries.push(entry);
        write_json_file(&config, &root)?;
    }
    write_codex_registration_state(scope, &binary, &config)?;
    println!(
        "Bash Guard 已注册到 Codex：作用域 {scope}，配置 {}，二进制 {}",
        config.display(),
        binary.display()
    );
    Ok(())
}

fn unregister_codex(scope: &str) -> Result<(), String> {
    let state_path = codex_registration_state_path(scope)?;
    let state = fs::read_to_string(&state_path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let binary = state
        .as_ref()
        .and_then(|value| value.get("binary"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| "未找到 Codex 注册记录的二进制路径，拒绝修改 Hook 配置".to_string())?;
    let config = state
        .as_ref()
        .and_then(|value| value.get("config"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| "未找到 Codex 注册记录的配置路径，拒绝修改 Hook 配置".to_string())?;
    if config.exists() {
        let mut root = read_codex_hooks_config(&config)?;
        let command = codex_hook_command(&binary);
        let mut changed = false;
        if let Some(entries) = root
            .get_mut("hooks")
            .and_then(Value::as_object_mut)
            .and_then(|hooks| hooks.get_mut("PreToolUse"))
            .and_then(Value::as_array_mut)
        {
            entries.retain_mut(|entry| {
                if entry.get("matcher").and_then(Value::as_str) != Some(CODEX_TOOL_MATCHER) {
                    return true;
                }
                let Some(hooks) = entry.get_mut("hooks").and_then(Value::as_array_mut) else {
                    return true;
                };
                let old_len = hooks.len();
                hooks.retain(|hook| !is_our_codex_command_hook(hook, &command));
                if hooks.len() == old_len {
                    return true;
                }
                changed = true;
                !hooks.is_empty()
            });
        }
        if changed {
            if codex_hooks_config_is_empty(&root) {
                fs::remove_file(&config)
                    .map_err(|error| format!("删除 {} 失败：{error}", config.display()))?;
                remove_empty_parent(&config)?;
            } else {
                write_json_file(&config, &root)?;
            }
        }
    }
    let _ = fs::remove_file(&state_path);
    println!("Bash Guard 已从 Codex 取消注册：作用域 {scope}");
    Ok(())
}

fn status_codex(scope: &str) -> Result<(), String> {
    let state_path = codex_registration_state_path(scope)?;
    let state = fs::read_to_string(&state_path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let config = state
        .as_ref()
        .and_then(|value| value.get("config"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or(codex_hooks_path(scope)?);
    let binary = state
        .as_ref()
        .and_then(|value| value.get("binary"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or(stable_binary_path()?);
    let registered = config
        .exists()
        .then(|| read_codex_hooks_config(&config))
        .transpose()?
        .is_some_and(|root| {
            root.get("hooks")
                .and_then(Value::as_object)
                .and_then(|hooks| hooks.get("PreToolUse"))
                .and_then(Value::as_array)
                .is_some_and(|entries| {
                    entries
                        .iter()
                        .any(|entry| is_our_codex_hook(entry, &codex_hook_command(&binary)))
                })
        });
    println!("二进制：{}", binary.display());
    println!("配置：{}", config.display());
    println!("作用域：{scope}");
    println!("钩子：{}", if registered { "已注册" } else { "未注册" });
    Ok(())
}

fn codex_hooks_path(scope: &str) -> Result<PathBuf, String> {
    match scope {
        "user" => {
            let home = env::var_os("HOME")
                .ok_or_else(|| "未设置 HOME，无法确定 Codex 用户配置路径".to_string())?;
            Ok(PathBuf::from(home).join(".codex/hooks.json"))
        }
        "project" => Ok(codex_project_root()?.join(".codex/hooks.json")),
        _ => Err("Codex 作用域必须是 user 或 project".to_string()),
    }
}

fn codex_project_root() -> Result<PathBuf, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|error| format!("无法执行 git 以确定 Codex 项目目录：{error}"))?;
    if !output.status.success() {
        return Err("当前目录不在 Git 仓库中，无法使用 Codex project 作用域".to_string());
    }
    let root = String::from_utf8(output.stdout)
        .map_err(|error| format!("无法读取 Git 项目目录：{error}"))?;
    let root = root.trim();
    if root.is_empty() {
        return Err("Git 未返回项目目录，无法使用 Codex project 作用域".to_string());
    }
    Ok(PathBuf::from(root))
}

fn codex_registration_root() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("BASH_GUARD_STATE_DIR") {
        return expand_path(PathBuf::from(path)).map(|path| path.join("codex"));
    }
    let home =
        env::var_os("HOME").ok_or_else(|| "未设置 HOME，无法确定 Codex 注册目录".to_string())?;
    Ok(PathBuf::from(home).join(".codex/bash-guard"))
}

fn codex_registration_state_path(scope: &str) -> Result<PathBuf, String> {
    Ok(codex_registration_root()?.join(format!("{CODEX_STATE_FILE_PREFIX}{scope}.json")))
}

fn write_codex_registration_state(scope: &str, binary: &Path, config: &Path) -> Result<(), String> {
    write_json_file(
        &codex_registration_state_path(scope)?,
        &json!({"scope": scope, "binary": binary, "config": config}),
    )
}

fn codex_hook_command(binary: &Path) -> String {
    format!("{} codex hook", shell_quote(&binary.to_string_lossy()))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\\"'\\\"'"))
}

fn codex_hook_entry(command: &str) -> Value {
    json!({
        "matcher": CODEX_TOOL_MATCHER,
        "hooks": [{
            "type": "command",
            "command": command,
            "timeout": 5,
            "statusMessage": CODEX_HOOK_MARKER,
        }],
    })
}

fn is_our_codex_hook(entry: &Value, command: &str) -> bool {
    entry.get("matcher").and_then(Value::as_str) == Some(CODEX_TOOL_MATCHER)
        && entry
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|hooks| {
                hooks
                    .iter()
                    .any(|hook| is_our_codex_command_hook(hook, command))
            })
}

fn is_our_codex_command_hook(hook: &Value, command: &str) -> bool {
    hook.get("type").and_then(Value::as_str) == Some("command")
        && hook.get("command").and_then(Value::as_str) == Some(command)
        && hook.get("statusMessage").and_then(Value::as_str) == Some(CODEX_HOOK_MARKER)
}

fn read_codex_hooks_config(path: &Path) -> Result<Value, String> {
    if !path.exists() {
        return Ok(json!({}));
    }
    let text = fs::read_to_string(path)
        .map_err(|error| format!("读取 {} 失败：{error}", path.display()))?;
    if text.trim().is_empty() {
        return Err(format!("Codex Hook 配置 {} 为空，拒绝覆盖", path.display()));
    }
    let root: Value = serde_json::from_str(&text)
        .map_err(|error| format!("无法解析 Codex Hook 配置 {}：{error}", path.display()))?;
    if !root.is_object() {
        return Err(format!(
            "Codex Hook 配置 {} 根节点必须是对象",
            path.display()
        ));
    }
    Ok(root)
}

fn codex_hooks_config_is_empty(root: &Value) -> bool {
    root.as_object().is_some_and(|root| {
        root.is_empty()
            || (root.len() == 1
                && root
                    .get("hooks")
                    .and_then(Value::as_object)
                    .is_some_and(|hooks| {
                        hooks.is_empty()
                            || (hooks.len() == 1
                                && hooks
                                    .get("PreToolUse")
                                    .and_then(Value::as_array)
                                    .is_some_and(Vec::is_empty))
                    }))
    })
}

fn remove_empty_parent(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if fs::read_dir(parent)
        .map_err(|error| format!("读取 {} 失败：{error}", parent.display()))?
        .next()
        .is_none()
    {
        fs::remove_dir(parent)
            .map_err(|error| format!("删除 {} 失败：{error}", parent.display()))?;
    }
    Ok(())
}

fn plugin_installed() -> Result<bool, String> {
    let plugins = claude_json(["plugin", "list", "--json"])?;
    Ok(plugins.as_array().is_some_and(|items| {
        items.iter().any(|item| {
            item.get("id").and_then(Value::as_str) == Some("bash-guard@bash-guard-marketplace")
        })
    }))
}

fn plugin_installed_in_scope(scope: &str) -> Result<bool, String> {
    let plugins = claude_json(["plugin", "list", "--json"])?;
    Ok(plugins.as_array().is_some_and(|items| {
        items.iter().any(|item| {
            item.get("id").and_then(Value::as_str) == Some("bash-guard@bash-guard-marketplace")
                && item.get("scope").and_then(Value::as_str) == Some(scope)
        })
    }))
}

fn claude_json<const N: usize>(args: [&str; N]) -> Result<Value, String> {
    let output = Command::new("claude")
        .args(args)
        .output()
        .map_err(|error| format!("无法执行 claude：{error}"))?;
    if !output.status.success() {
        return Err(format!(
            "claude 命令失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| format!("无法解析 claude 输出：{error}"))
}

fn run_claude<const N: usize>(args: [&str; N]) -> Result<(), String> {
    let status = Command::new("claude")
        .args(args)
        .status()
        .map_err(|error| format!("无法执行 claude：{error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("claude 命令退出码 {status}"))
    }
}

fn registration_root() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("BASH_GUARD_STATE_DIR") {
        return Ok(expand_path(PathBuf::from(path))?);
    }
    let home = env::var_os("HOME").ok_or_else(|| "未设置 HOME，无法确定注册目录".to_string())?;
    Ok(PathBuf::from(home).join(".claude").join("bash-guard"))
}

fn stable_binary_path() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("BASH_GUARD_BINARY") {
        let path = expand_path(PathBuf::from(path))?;
        return validate_executable(path);
    }
    let executable = env::current_exe().map_err(|error| format!("无法确定当前二进制：{error}"))?;
    let canonical = fs::canonicalize(&executable).unwrap_or(executable.clone());
    let components: Vec<_> = canonical.components().collect();
    let cellar_index = components
        .iter()
        .position(|component| component.as_os_str() == "Cellar");
    if let Some(index) = cellar_index {
        if let (Some(prefix), Some(formula)) =
            (canonical.ancestors().last(), components.get(index + 1))
        {
            let stable = prefix
                .join("opt")
                .join(formula.as_os_str())
                .join("bin/bash-guard");
            if stable.is_file() {
                return validate_executable(stable);
            }
        }
    }
    validate_executable(executable)
}

fn validate_executable(path: PathBuf) -> Result<PathBuf, String> {
    if !path.is_file() {
        return Err(format!("二进制不存在：{}", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path
            .metadata()
            .map_err(|error| error.to_string())?
            .permissions()
            .mode()
            & 0o111
            == 0
        {
            return Err(format!("二进制不可执行：{}", path.display()));
        }
    }
    Ok(path)
}

fn expand_path(path: PathBuf) -> Result<PathBuf, String> {
    let text = path.to_string_lossy();
    let expanded = expand_environment_variables(&text)?;
    if expanded == "~" || expanded.starts_with("~/") {
        let home = env::var_os("HOME").ok_or_else(|| "未设置 HOME".to_string())?;
        return Ok(PathBuf::from(home).join(expanded.strip_prefix("~/").unwrap_or("")));
    }
    Ok(PathBuf::from(expanded))
}

fn expand_environment_variables(input: &str) -> Result<String, String> {
    let mut output = String::with_capacity(input.len());
    let mut characters = input.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '$' {
            output.push(character);
            continue;
        }
        let name = if characters.peek() == Some(&'{') {
            characters.next();
            let mut name = String::new();
            loop {
                match characters.next() {
                    Some('}') => break name,
                    Some(character) => name.push(character),
                    None => return Err("环境变量引用缺少右花括号".to_string()),
                }
            }
        } else {
            let mut name = String::new();
            while matches!(characters.peek(), Some(character) if character.is_ascii_alphanumeric() || *character == '_')
            {
                name.push(characters.next().expect("已检查字符存在"));
            }
            name
        };
        if name.is_empty() {
            output.push('$');
        } else {
            let value = env::var_os(&name)
                .ok_or_else(|| format!("未设置审计路径所引用的环境变量 {name}"))?;
            output.push_str(&value.to_string_lossy());
        }
    }
    Ok(output)
}

fn write_adapter(root: &Path, binary: &Path) -> Result<(), String> {
    let plugin = root.join("plugins/bash-guard");
    fs::create_dir_all(plugin.join(".claude-plugin")).map_err(|error| error.to_string())?;
    fs::create_dir_all(plugin.join("hooks")).map_err(|error| error.to_string())?;
    write_file(
        &root.join(".claude-plugin/marketplace.json"),
        &format!(
            r#"{{"$schema":"https://json.schemastore.org/claude-code-marketplace.json","name":"{MARKETPLACE_NAME}","owner":{{"name":"bash-agent maintainers"}},"metadata":{{"description":"Bash Guard 本地适配插件源"}},"plugins":[{{"name":"{PLUGIN_NAME}","source":"./plugins/bash-guard","description":"在 Bash 执行前实施权限策略","version":"0.1.4"}}]}}
"#
        ),
    )?;
    write_file(
        &plugin.join(".claude-plugin/plugin.json"),
        r#"{"name":"bash-guard","version":"0.1.4","description":"Bash Guard 本地失败关闭适配器","author":{"name":"bash-agent maintainers"},"license":"MIT"}
"#,
    )?;
    write_file(
        &plugin.join("hooks/hooks.json"),
        &format!(
            r#"{{"description":"在 Claude Code 执行受保护工具前检查权限","hooks":{{"PreToolUse":[{{"matcher":"{}","hooks":[{{"type":"command","command":{},"args":["claude","hook"],"timeout":5,"statusMessage":"正在检查工具权限"}}]}}]}}}}
"#,
            TOOL_MATCHER,
            serde_json::to_string(&binary.to_string_lossy()).map_err(|error| error.to_string())?
        ),
    )?;
    Ok(())
}

fn write_registration_state(root: &Path, scope: &str, binary: &Path) -> Result<(), String> {
    write_file(
        &root.join("registration.json"),
        &serde_json::to_string_pretty(&json!({"scope": scope, "binary": binary}))
            .map_err(|error| error.to_string())?,
    )
}

fn write_json_file(path: &Path, value: &Value) -> Result<(), String> {
    let contents = serde_json::to_string_pretty(value)
        .map_err(|error| format!("序列化 {} 失败：{error}", path.display()))?;
    write_file(path, &format!("{contents}\n"))
}

fn write_file(path: &Path, contents: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} 没有父目录", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("创建 {} 失败：{error}", parent.display()))?;
    let mut file =
        File::create(path).map_err(|error| format!("写入 {} 失败：{error}", path.display()))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| format!("写入 {} 失败：{error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("同步 {} 失败：{error}", path.display()))
}
