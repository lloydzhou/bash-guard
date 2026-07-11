#!/bin/sh
set -eu

binary=${1:-./target/debug/bash-guard}
pass=0
fail=0

check() {
  name=$1
  input=$2
  expected=$3
  actual=$(printf '%s' "$input" | "$binary" claude hook)
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

check '策略拒绝' \
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"sudo reboot"}}' \
  "$(deny 'command blocked by bash safety policy (required=1000 allowed=0467; mode=system/external/network/workspace bits=4:read,2:write,1:execute)')"
check '无效输入失败关闭' \
  '无效 JSON' \
  "$(deny 'Bash Guard 无法解析 Hook 输入，已按失败关闭处理')"
check '允许命令无输出' \
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"cat README.md"}}' \
  ''

if [ "$fail" -ne 0 ]; then
  exit 1
fi
printf '通过：%s 项 Hook 端到端检查\n' "$pass"
