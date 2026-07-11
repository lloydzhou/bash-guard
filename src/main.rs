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
        [claude, subcommand] if claude == "claude" && subcommand == "hook" => hook(),
        [claude, command, rest @ ..] if claude == "claude" => claude_command(command, rest),
        _ => Err("用法：bash-guard claude <hook|register|unregister|status> [--scope user|project|local]".to_string()),
    }
}

fn hook() -> Result<(), String> {
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
        || event.get("tool_name").and_then(Value::as_str) != Some("Bash")
    {
        emit_deny("Bash Guard 收到非预期 Hook 事件，已按失败关闭处理");
        return Ok(());
    }
    let Some(command) = event
        .get("tool_input")
        .and_then(Value::as_object)
        .and_then(|input| input.get("command"))
        .and_then(Value::as_str)
        .filter(|command| !command.trim().is_empty())
    else {
        emit_deny("Bash Guard 未收到有效的 Bash 命令，已按失败关闭处理");
        return Ok(());
    };
    let Some(cwd) = event
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|cwd| !cwd.is_empty())
    else {
        emit_deny("Bash Guard 未收到有效工作目录，已按失败关闭处理");
        return Ok(());
    };

    let decision = policy::evaluate(command, cwd, env::var("BASH_GUARD_MODE").ok().as_deref());
    let audit = json!({
        "time": OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_else(|_| "时间格式化失败".to_string()),
        "session_id": event.get("session_id"),
        "tool_use_id": event.get("tool_use_id"),
        "permission_mode": event.get("permission_mode"),
        "cwd": cwd,
        "command": command,
        "allowed": decision.allowed,
        "allowed_mode": decision.allowed_mode,
        "required_mode": decision.required_mode,
        "reason": decision.reason,
    });
    if let Err(error) = append_audit(env::var_os("BASH_GUARD_AUDIT_LOG"), &audit) {
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

fn append_audit(path: Option<std::ffi::OsString>, record: &Value) -> Result<(), String> {
    let Some(path) = path.filter(|path| !path.is_empty()) else {
        return Ok(());
    };
    let path = expand_path(PathBuf::from(path))?;
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
    fs::create_dir_all(plugin.join("scripts")).map_err(|error| error.to_string())?;
    write_file(
        &root.join(".claude-plugin/marketplace.json"),
        &format!(
            r#"{{"$schema":"https://json.schemastore.org/claude-code-marketplace.json","name":"{MARKETPLACE_NAME}","owner":{{"name":"bash-agent maintainers"}},"metadata":{{"description":"Bash Guard 本地适配插件源"}},"plugins":[{{"name":"{PLUGIN_NAME}","source":"./plugins/bash-guard","description":"在 Bash 执行前实施权限策略","version":"0.1.1"}}]}}
"#
        ),
    )?;
    write_file(
        &plugin.join(".claude-plugin/plugin.json"),
        r#"{"name":"bash-guard","version":"0.1.1","description":"Bash Guard 本地失败关闭适配器","author":{"name":"bash-agent maintainers"},"license":"MIT"}
"#,
    )?;
    write_file(
        &plugin.join("hooks/hooks.json"),
        r#"{"description":"在 Claude Code 执行 Bash 工具前检查命令权限","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"${CLAUDE_PLUGIN_ROOT}/scripts/bash-guard","args":[],"timeout":5,"statusMessage":"正在检查 Bash 命令权限"}]}]}}
"#,
    )?;
    let launcher = format!(
        "#!/bin/sh\nset -eu\nBASH_GUARD_BIN={}\nemit_deny() {{\n  printf '%s\\n' '{{\"hookSpecificOutput\":{{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"Bash Guard 启动器无法执行安全检查，已按失败关闭处理\"}}}}'\n}}\nif [ ! -x \"$BASH_GUARD_BIN\" ]; then\n  emit_deny\n  exit 0\nfi\ntmp=$(mktemp \"${{TMPDIR:-/tmp}}/bash-guard-hook.XXXXXX\") || {{ emit_deny; exit 0; }}\ntrap 'rm -f \"$tmp\"' EXIT HUP INT TERM\nif ! \"$BASH_GUARD_BIN\" claude hook >\"$tmp\"; then\n  emit_deny\n  exit 0\nfi\ncat \"$tmp\"\n",
        shell_quote(binary)
    );
    write_file(&plugin.join("scripts/bash-guard"), &launcher)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            plugin.join("scripts/bash-guard"),
            fs::Permissions::from_mode(0o755),
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn write_registration_state(root: &Path, scope: &str, binary: &Path) -> Result<(), String> {
    write_file(
        &root.join("registration.json"),
        &serde_json::to_string_pretty(&json!({"scope": scope, "binary": binary}))
            .map_err(|error| error.to_string())?,
    )
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

fn shell_quote(path: &Path) -> String {
    let path = path.to_string_lossy();
    format!("'{}'", path.replace('\'', "'\\\"'\\\"'"))
}
