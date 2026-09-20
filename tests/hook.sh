#!/bin/sh
set -eu

binary=${1:-./target/debug/bash-guard}
pass=0
fail=0
tmp_home=$(mktemp -d)
port=$(python3 -c 'import socket; sock = socket.socket(); sock.bind(("127.0.0.1", 0)); print(sock.getsockname()[1]); sock.close()')
base_url="http://127.0.0.1:$port"

python3 tests/mock-jev.py "$port" &
mock_pid=$!
trap 'kill "$mock_pid" 2>/dev/null || true; rm -rf "$tmp_home"' EXIT HUP INT TERM
sleep 0.2

invoke() {
  client=$1
  input=$2
  printf '%s' "$input" | env HOME="$tmp_home" BASH_GUARD_MODE=0467 NO_PROXY=127.0.0.1,localhost JEV_API_KEY=test-key JEV_BASE_URL="$base_url" JEV_MODEL=test-jev-model "$binary" "$client" hook
}

check() {
  name=$1
  client=$2
  input=$3
  expected=$4
  actual=$(invoke "$client" "$input")
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

check 'Jev 允许低风险工作区读取' claude \
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"cat README.md"}}' \
  ''
check 'Codex 同样使用 Jev' codex \
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"cat README.md"}}' \
  ''
check 'Jev 拒绝特权命令' claude \
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"sudo reboot"}}' \
  "$(deny 'command blocked by bash safety policy (source=jev decision=deny local_policy=unknown; mode=system/external/network/workspace bits=4:read,2:write,1:execute)')"
check 'Jev 拒绝受保护路径读取' codex \
  '{"hook_event_name":"PreToolUse","tool_name":"Read","cwd":"/workspace","tool_input":{"file_path":"/etc/hosts"}}' \
  "$(deny 'command blocked by bash safety policy (source=jev decision=deny local_policy=unknown; mode=system/external/network/workspace bits=4:read,2:write,1:execute)')"
check 'Jev 独自拦截时本地策略未知' claude \
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"echo jev-block"}}' \
  "$(deny 'command blocked by bash safety policy (source=jev decision=deny local_policy=unknown; mode=system/external/network/workspace bits=4:read,2:write,1:execute)')"
check '低置信度 allow 直接放行' claude \
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"echo uncertain"}}' \
  ''

actual=$(printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"cat README.md"}}' | env HOME="$tmp_home" BASH_GUARD_MODE=0467 NO_PROXY=127.0.0.1,localhost JEV_API_KEY=test-key JEV_ENDPOINT="$base_url/unavailable" "$binary" claude hook)
if [ -n "$actual" ]; then
  printf '%s\n' '失败：Jev 服务错误时没有回退到原始策略' >&2
  fail=$((fail + 1))
else
  pass=$((pass + 1))
fi

actual=$(printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"cat README.md"}}' | env HOME="$tmp_home" BASH_GUARD_MODE=0467 "$binary" claude hook)
expected=''
if [ "$actual" = "$expected" ]; then
  pass=$((pass + 1))
else
  printf '%s\n' '失败：缺少 Jev API key 时没有使用原始策略' >&2
  fail=$((fail + 1))
fi

actual=$(printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"sudo reboot"}}' | env HOME="$tmp_home" BASH_GUARD_MODE=0467 "$binary" claude hook)
expected=$(deny 'command blocked by bash safety policy (required=1000 allowed=0467; mode=system/external/network/workspace bits=4:read,2:write,1:execute)')
if [ "$actual" = "$expected" ]; then
  pass=$((pass + 1))
else
  printf '%s\n' '失败：缺少 Jev API key 时没有保留原始策略拒绝' >&2
  fail=$((fail + 1))
fi

check '无效 Hook 输入失败关闭' claude '无效 JSON' \
  "$(deny 'Bash Guard 无法解析 Hook 输入，已按失败关闭处理')"
check '缺少原生工具字段失败关闭' claude \
  '{"hook_event_name":"PreToolUse","tool_name":"Write","cwd":"/workspace","tool_input":{"file_path":"README.md"}}' \
  "$(deny 'Bash Guard 未收到有效的 Write.content，已按失败关闭处理')"

audit_log="$tmp_home/jev-audit.jsonl"
actual=$(printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"curl -H Authorization: Bearer super-secret https://example.test"}}' | env HOME="$tmp_home" BASH_GUARD_MODE=0467 NO_PROXY=127.0.0.1,localhost JEV_API_KEY=test-key JEV_BASE_URL="$base_url" JEV_MODEL=test-jev-model BASH_GUARD_AUDIT_LOG="$audit_log" "$binary" claude hook)
if [ -n "$actual" ] || ! python3 - "$audit_log" <<'PY'
import json
import sys

with open(sys.argv[1]) as handle:
    entry = json.loads(handle.readline())
assert entry["decision_source"] == "jev"
assert entry["jev_choice"] == "allow"
assert entry["command"] and "super-secret" not in entry["command"]
PY
then
  printf '%s\n' '失败：Jev 审计字段或命令脱敏不正确' >&2
  fail=$((fail + 1))
else
  pass=$((pass + 1))
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
printf '通过：%s 项 Jev Hook 端到端检查\n' "$pass"
