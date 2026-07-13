#!/bin/sh
set -eu

binary=${1:-./target/debug/bash-guard}
pass=0
fail=0

tmp_home=$(mktemp -d)
trap 'rm -rf "$tmp_home"' EXIT HUP INT TERM

check() {
  name=$1
  input=$2
  expected=$3
  actual=$(printf '%s' "$input" | env HOME="$tmp_home" "$binary" claude hook)
  if [ "$actual" = "$expected" ]; then
    pass=$((pass + 1))
  else
    printf '%s\n实际：%s\n期望：%s\n' "失败：$name" "$actual" "$expected" >&2
    fail=$((fail + 1))
  fi
}

deny() {
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}' "$1"
}

check_hook() {
  client=$1
  name=$2
  input=$3
  expected=$4
  actual=$(printf '%s' "$input" | env HOME="$tmp_home" "$binary" "$client" hook)
  if [ "$actual" = "$expected" ]; then
    pass=$((pass + 1))
  else
    printf '%s\n实际：%s\n期望：%s\n' "失败：$name" "$actual" "$expected" >&2
    fail=$((fail + 1))
  fi
}

check '策略拒绝' \
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"sudo reboot"}}' \
  "$(deny 'command blocked by bash safety policy (required=1000 allowed=0467; mode=system/external/network/workspace bits=4:read,2:write,1:execute)')"
check_hook codex 'Codex 策略拒绝' \
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"sudo reboot"}}' \
  "$(deny 'command blocked by bash safety policy (required=1000 allowed=0467; mode=system/external/network/workspace bits=4:read,2:write,1:execute)')"
check_hook codex 'Codex 允许命令无输出' \
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"cat README.md"}}' \
  ''
check_hook codex 'Codex 原生工具敏感路径拒绝' \
  '{"hook_event_name":"PreToolUse","tool_name":"Read","cwd":"/workspace","tool_input":{"file_path":"/etc/hosts"}}' \
  "$(deny 'command blocked by bash safety policy (required=4000 allowed=0467; mode=system/external/network/workspace bits=4:read,2:write,1:execute)')"

check_env() {
  name=$1
  input=$2
  expected=$3
  env_spec=$4
  actual=$(printf '%s' "$input" | env HOME="$tmp_home" $env_spec "$binary" claude hook)
  if [ "$actual" = "$expected" ]; then
    pass=$((pass + 1))
  else
    printf '%s\n实际：%s\n期望：%s\n' "失败：$name" "$actual" "$expected" >&2
    fail=$((fail + 1))
  fi
}
check '无效输入失败关闭' \
  '无效 JSON' \
  "$(deny 'Bash Guard 无法解析 Hook 输入，已按失败关闭处理')"
check '允许命令无输出' \
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"cat README.md"}}' \
  ''
check '允许 Read 无输出' \
  '{"hook_event_name":"PreToolUse","tool_name":"Read","cwd":"/workspace","tool_input":{"file_path":"README.md"}}' \
  ''
check 'Read 敏感路径拒绝' \
  '{"hook_event_name":"PreToolUse","tool_name":"Read","cwd":"/workspace","tool_input":{"file_path":"/etc/hosts"}}' \
  "$(deny 'command blocked by bash safety policy (required=4000 allowed=0467; mode=system/external/network/workspace bits=4:read,2:write,1:execute)')"
check '允许 Write 无输出' \
  '{"hook_event_name":"PreToolUse","tool_name":"Write","cwd":"/workspace","tool_input":{"file_path":"README.md","content":"不应进入策略探针"}}' \
  ''
check 'Write 敏感路径拒绝' \
  '{"hook_event_name":"PreToolUse","tool_name":"Write","cwd":"/workspace","tool_input":{"file_path":"/etc/hosts","content":"内容不应影响权限判断"}}' \
  "$(deny 'command blocked by bash safety policy (required=2000 allowed=0467; mode=system/external/network/workspace bits=4:read,2:write,1:execute)')"
check '允许 Edit 无输出' \
  '{"hook_event_name":"PreToolUse","tool_name":"Edit","cwd":"/workspace","tool_input":{"file_path":"README.md","old_string":"旧文本","new_string":"新文本"}}' \
  ''
check 'Edit 敏感路径拒绝' \
  '{"hook_event_name":"PreToolUse","tool_name":"Edit","cwd":"/workspace","tool_input":{"file_path":"/etc/hosts","old_string":"旧文本","new_string":"新文本"}}' \
  "$(deny 'command blocked by bash safety policy (required=2000 allowed=0467; mode=system/external/network/workspace bits=4:read,2:write,1:execute)')"
check '允许 Glob 无输出' \
  '{"hook_event_name":"PreToolUse","tool_name":"Glob","cwd":"/workspace","tool_input":{"path":".","pattern":"**/*.rs"}}' \
  ''
check 'Glob 敏感模式失败关闭' \
  '{"hook_event_name":"PreToolUse","tool_name":"Glob","cwd":"/workspace","tool_input":{"pattern":"/etc/**/*"}}' \
  "$(deny 'Bash Guard 无法安全确定 Glob 搜索范围，已按失败关闭处理')"
check 'Glob 上级目录模式失败关闭' \
  '{"hook_event_name":"PreToolUse","tool_name":"Glob","cwd":"/workspace","tool_input":{"pattern":"../**/*.env"}}' \
  "$(deny 'Bash Guard 无法安全确定 Glob 搜索范围，已按失败关闭处理')"
check 'Glob 指定敏感搜索根拒绝' \
  '{"hook_event_name":"PreToolUse","tool_name":"Glob","cwd":"/workspace","tool_input":{"path":"/etc","pattern":"**/*"}}' \
  "$(deny 'command blocked by bash safety policy (required=4000 allowed=0467; mode=system/external/network/workspace bits=4:read,2:write,1:execute)')"
check '允许 Grep 无输出' \
  '{"hook_event_name":"PreToolUse","tool_name":"Grep","cwd":"/workspace","tool_input":{"path":".","pattern":"密钥"}}' \
  ''
check 'Grep 敏感路径拒绝' \
  '{"hook_event_name":"PreToolUse","tool_name":"Grep","cwd":"/workspace","tool_input":{"path":"/etc","pattern":"密钥"}}' \
  "$(deny 'command blocked by bash safety policy (required=4000 allowed=0467; mode=system/external/network/workspace bits=4:read,2:write,1:execute)')"
check 'Read 缺失路径失败关闭' \
  '{"hook_event_name":"PreToolUse","tool_name":"Read","cwd":"/workspace","tool_input":{}}' \
  "$(deny 'Bash Guard 未收到有效的 Read.file_path，已按失败关闭处理')"
check 'Write 缺失内容失败关闭' \
  '{"hook_event_name":"PreToolUse","tool_name":"Write","cwd":"/workspace","tool_input":{"file_path":"README.md"}}' \
  "$(deny 'Bash Guard 未收到有效的 Write.content，已按失败关闭处理')"
check 'Edit 缺失替换文本失败关闭' \
  '{"hook_event_name":"PreToolUse","tool_name":"Edit","cwd":"/workspace","tool_input":{"file_path":"README.md","old_string":"旧文本"}}' \
  "$(deny 'Bash Guard 未收到有效的 Edit.new_string，已按失败关闭处理')"
check 'Glob 缺失模式失败关闭' \
  '{"hook_event_name":"PreToolUse","tool_name":"Glob","cwd":"/workspace","tool_input":{}}' \
  "$(deny 'Bash Guard 未收到有效的 Glob.pattern，已按失败关闭处理')"
check 'Grep 缺失路径失败关闭' \
  '{"hook_event_name":"PreToolUse","tool_name":"Grep","cwd":"/workspace","tool_input":{"pattern":"密钥"}}' \
  "$(deny 'Bash Guard 未收到有效的 Grep.path，已按失败关闭处理')"
check '非预期事件失败关闭' \
  '{"hook_event_name":"PostToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"cat README.md"}}' \
  "$(deny 'Bash Guard 收到非预期 Hook 事件，已按失败关闭处理')"
check '缺失命令失败关闭' \
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{}}' \
  "$(deny 'Bash Guard 未收到有效的 Bash 命令，已按失败关闭处理')"
check '空白命令失败关闭' \
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"   "}}' \
  "$(deny 'Bash Guard 未收到有效的 Bash 命令，已按失败关闭处理')"
check '缺失工作目录失败关闭' \
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat README.md"}}' \
  "$(deny 'Bash Guard 未收到有效工作目录，已按失败关闭处理')"
check_env '无效权限模式失败关闭' \
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"cat README.md"}}' \
  "$(deny 'command blocked by bash safety policy (required=0004 allowed=0000; mode=system/external/network/workspace bits=4:read,2:write,1:execute)')" \
  'BASH_GUARD_MODE=bad1'

check_audit_path() {
  client=$1
  name=$2
  log=$3
  env_spec=$4
  rm -f "$log"
  input='{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"cat README.md"}}'
  if ! actual=$(printf '%s' "$input" | env HOME="$tmp_home" $env_spec "$binary" "$client" hook); then
    printf '%s\n' "失败：$name（Hook 执行失败）" >&2
    fail=$((fail + 1))
  elif [ -n "$actual" ] || [ ! -s "$log" ]; then
    printf '%s\n' "失败：$name（未写入预期审计日志）" >&2
    fail=$((fail + 1))
  elif ! python3 - "$log" "$client" <<'PY'
import json
import sys
with open(sys.argv[1]) as f:
    record = json.loads(f.readline())
assert record["client"] == sys.argv[2]
PY
  then
    printf '%s\n' "失败：$name（审计来源字段不正确）" >&2
    fail=$((fail + 1))
  else
    pass=$((pass + 1))
  fi
}

check_audit_path claude 'Claude 默认审计日志路径' "$tmp_home/.claude/bash-guard-audit.jsonl" ''
check_audit_path codex 'Codex 默认审计日志路径' "$tmp_home/.codex/bash-guard-audit.jsonl" ''

check_audit_native_tool() {
  log="$tmp_home/native-tool-audit.jsonl"
  rm -f "$log"
  input='{"hook_event_name":"PreToolUse","tool_name":"Write","cwd":"/workspace","tool_input":{"file_path":"README.md","content":"机密内容不应记录"}}'
  if ! actual=$(printf '%s' "$input" | env HOME="$tmp_home" BASH_GUARD_AUDIT_LOG="$log" "$binary" claude hook); then
    printf '%s\n' '失败：原生工具审计字段（Hook 执行失败）' >&2
    fail=$((fail + 1))
  elif [ -n "$actual" ] || ! python3 - "$log" <<'PY'
import json
import sys
with open(sys.argv[1]) as f:
    record = json.loads(f.readline())
assert record["tool_name"] == "Write"
assert record["operation"] == "写入路径：README.md"
assert record["tool_input_summary"] == {"file_path": "README.md", "content_bytes": len("机密内容不应记录".encode())}
assert "机密内容不应记录" not in str(record)
assert record["command"] is None

with open(sys.argv[1]) as f:
    records = [json.loads(line) for line in f]
assert all("机密内容不应记录" not in str(item) for item in records)
PY
  then
    printf '%s\n' '失败：原生工具审计字段不正确或泄露内容' >&2
    fail=$((fail + 1))
  else
    pass=$((pass + 1))
  fi
}

check_audit_native_tool
check_audit_path codex '自定义审计日志路径' "$tmp_home/custom-audit.jsonl" "BASH_GUARD_AUDIT_LOG=$tmp_home/custom-audit.jsonl"

if [ "$fail" -ne 0 ]; then
  exit 1
fi
printf '通过：%s 项 Hook 端到端检查\n' "$pass"
