#!/bin/sh
set -eu

binary=${1:-./target/debug/bash-guard}
binary=$(cd "$(dirname "$binary")" && pwd)/$(basename "$binary")
pass=0
fail=0

tmp_home=$(mktemp -d)
tmp_project=$(mktemp -d)
trap 'rm -rf "$tmp_home" "$tmp_project"' EXIT HUP INT TERM

fail_case() {
  printf '失败：%s\n' "$1" >&2
  fail=$((fail + 1))
}

pass_case() {
  pass=$((pass + 1))
}

run() {
  env HOME="$tmp_home" BASH_GUARD_BINARY="$binary" BASH_GUARD_STATE_DIR="$tmp_home/state" "$binary" "$@"
}

user_config="$tmp_home/.codex/hooks.json"
mkdir -p "$(dirname "$user_config")"
cat >"$user_config" <<'JSON'
{
  "hooks": {
    "PostToolUse": [{"matcher":".*","hooks":[{"type":"command","command":"other post"}]}],
    "PreToolUse": [{"matcher":"^Bash$","hooks":[{"type":"command","command":"other bash"}]}]
  }
}
JSON

run codex register --scope user >/dev/null
python3 - "$user_config" "$binary" <<'PY'
import json
import sys
path, binary = sys.argv[1:]
with open(path) as f:
    config = json.load(f)
entries = config["hooks"]["PreToolUse"]
assert len(entries) == 2
assert config["hooks"]["PostToolUse"][0]["hooks"][0]["command"] == "other post"
ours = [entry for entry in entries if entry.get("matcher") == "^(Bash|Read|Edit|Write|Glob|Grep)$" and any(hook.get("statusMessage") == "Bash Guard: checking native tool permissions" for hook in entry.get("hooks", []))]
assert len(ours) == 1
hook = ours[0]["hooks"][0]
assert hook["type"] == "command"
assert hook["command"] == "'%s' codex hook" % binary
assert hook["timeout"] == 5
PY
pass_case

python3 - "$user_config" <<'PY'
import json
import sys
with open(sys.argv[1]) as f:
    config = json.load(f)
entry = config["hooks"]["PreToolUse"][-1]
entry["matcher"] = "^Bash$"
for hook in entry["hooks"]:
    hook["statusMessage"] = "Bash Guard: checking Bash command permissions"
with open(sys.argv[1], "w") as f:
    json.dump(config, f)
PY
run codex register --scope user >/dev/null
python3 - "$user_config" <<'PY'
import json
import sys
with open(sys.argv[1]) as f:
    entries = json.load(f)["hooks"]["PreToolUse"]
assert len(entries) == 3
legacy = [entry for entry in entries if entry.get("matcher") == "^Bash$" and any(hook.get("statusMessage") == "Bash Guard: checking Bash command permissions" for hook in entry.get("hooks", []))]
current = [entry for entry in entries if entry.get("matcher") == "^(Bash|Read|Edit|Write|Glob|Grep)$" and any(hook.get("statusMessage") == "Bash Guard: checking native tool permissions" for hook in entry.get("hooks", []))]
assert len(legacy) == 1
assert len(current) == 1
PY
pass_case

run codex register --scope user >/dev/null
python3 - "$user_config" <<'PY'
import json
import sys
with open(sys.argv[1]) as f:
    entries = json.load(f)["hooks"]["PreToolUse"]
ours = [entry for entry in entries if any(hook.get("statusMessage") == "Bash Guard: checking native tool permissions" for hook in entry.get("hooks", []))]
assert len(entries) == 3
assert len(ours) == 1
PY
pass_case

python3 - "$user_config" "$binary" <<'PY'
import json
import sys
path, binary = sys.argv[1:]
with open(path) as f:
    config = json.load(f)
command = "'%s' codex hook" % binary
for entry in config["hooks"]["PreToolUse"]:
    if entry.get("matcher") == "^(Bash|Read|Edit|Write|Glob|Grep)$" and any(hook.get("statusMessage") == "Bash Guard: checking native tool permissions" for hook in entry.get("hooks", [])):
        entry["hooks"].append({"type": "command", "command": "other nested bash"})
with open(path, "w") as f:
    json.dump(config, f)
PY

status=$(run codex status --scope user)
printf '%s\n' "$status" | grep -F "钩子：已注册" >/dev/null || fail_case '状态未报告已注册'
pass_case

run codex unregister --scope user >/dev/null
python3 - "$user_config" <<'PY'
import json
import sys
with open(sys.argv[1]) as f:
    config = json.load(f)
assert len(config["hooks"]["PreToolUse"]) == 3
assert config["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "other bash"
legacy = [entry for entry in config["hooks"]["PreToolUse"] if entry.get("matcher") == "^Bash$" and any(hook.get("statusMessage") == "Bash Guard: checking Bash command permissions" for hook in entry.get("hooks", []))]
assert len(legacy) == 1
remaining = [entry for entry in config["hooks"]["PreToolUse"] if entry.get("matcher") == "^(Bash|Read|Edit|Write|Glob|Grep)$" and any(hook.get("command") == "other nested bash" for hook in entry.get("hooks", []))]
assert len(remaining) == 1
assert all(hook.get("statusMessage") != "Bash Guard: checking native tool permissions" for hook in remaining[0]["hooks"])
assert "PostToolUse" in config["hooks"]
PY
pass_case

rm -f "$user_config"
run codex register --scope user >/dev/null
[ -f "$user_config" ] || fail_case '未创建空配置的注册文件'
run codex unregister --scope user >/dev/null
[ ! -e "$user_config" ] || fail_case '仅含 Guard 时未删除配置文件'
pass_case

mkdir -p "$(dirname "$user_config")"
printf '{ invalid' >"$user_config"
if run codex register --scope user >/dev/null 2>&1; then
  fail_case '无效配置被覆盖'
else
  pass_case
fi

if run codex register --scope local >/dev/null 2>&1; then
  fail_case '接受了不支持的 Codex local 作用域'
else
  pass_case
fi

project_config="$tmp_project/.codex/hooks.json"
(
  cd "$tmp_project"
  git init -q
  env HOME="$tmp_home" BASH_GUARD_BINARY="$binary" BASH_GUARD_STATE_DIR="$tmp_home/state-project" "$binary" codex register --scope project >/dev/null
)
[ -f "$project_config" ] || fail_case '未在 Git 项目根目录创建项目配置'
pass_case

if [ "$fail" -ne 0 ]; then
  exit 1
fi
printf '通过：%s 项 Codex 注册端到端检查\n' "$pass"
