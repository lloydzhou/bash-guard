"""Bash Guard 的命令权限分类核心。"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from typing import Iterable, List

DEFAULT_ALLOWED_MODE = "0467"

SCOPE_SYSTEM = 8
SCOPE_EXTERNAL = 4
SCOPE_NETWORK = 2
SCOPE_WORKSPACE = 1

PERM_READ = 4
PERM_WRITE = 2
PERM_EXECUTE = 1

_ROOT_DELETE_RE = re.compile(r"(^|[\s;|&])rm\s+-[^\s]*[rf][^\s]*\s+/([\s]|$|\*)", re.I)
_SYSTEM_PATH_RE = re.compile(r"(^|[\s\"'])(/etc|/usr|/bin|/sbin|/var|/library|/system|/dev)(/|[\s\"']|$)", re.I)
_SENSITIVE_PATH_RE = re.compile(
    r"(^|[\s\"'])(~|\$home)/(\.ssh|\.gnupg|\.aws|\.docker)(/|[\s\"']|$)"
    r"|(^|[\s\"'])([^\s\"']*\.(env|pem|key)|[^\s\"']*(token|credential|secret)[^\s\"']*)",
    re.I,
)
_EXTERNAL_PATH_RE = re.compile(r"(^|[\s\"'])(~|\$home)(/|[\s\"']|$)|(^|[\s\"'])/[A-Za-z0-9._-]", re.I)
_DEVICE_WRITE_RE = re.compile(
    r"(^|\s)(of=|>|1>|>>|1>>)\s*/dev/"
    r"(sd[a-z][0-9]*|disk[0-9]+|rdisk[0-9]+|nvme[0-9]+n[0-9]+(p[0-9]+)?|vd[a-z][0-9]*|xvd[a-z][0-9]*|hd[a-z][0-9]*)"
    r"(\s|$)",
    re.I,
)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    allowed_mode: str
    required_mode: str
    reason: str


def normalize_mode(mode: object, default: str = DEFAULT_ALLOWED_MODE) -> str:
    """规范化四位八进制模式；无效显式值按 0000 失败关闭。"""
    if mode is None or mode == "":
        mode = default
    text = str(mode)
    return text if re.fullmatch(r"[0-7]{4}", text) else "0000"


def mode_allows(allowed_mode: str, required_mode: str) -> bool:
    allowed = int(normalize_mode(allowed_mode), 8)
    required = int(normalize_mode(required_mode, "0000"), 8)
    return required & (0o7777 ^ allowed) == 0


class BashModeClassifier:
    """按 system/external/network/workspace 四个作用域累计 rwx 权限。"""

    def __init__(self, cwd: str) -> None:
        self.cwd = os.path.abspath(cwd or os.getcwd()).lower()
        self.required_mask = 0

    def add_mode(self, scopes: int, permissions: int) -> None:
        if scopes & SCOPE_SYSTEM:
            self.required_mask |= permissions << 9
        if scopes & SCOPE_EXTERNAL:
            self.required_mask |= permissions << 6
        if scopes & SCOPE_NETWORK:
            self.required_mask |= permissions << 3
        if scopes & SCOPE_WORKSPACE:
            self.required_mask |= permissions

    def add_path(self, raw_path: str, permissions: int) -> None:
        path = raw_path.strip("\"'")
        if path.startswith("of="):
            path = path[3:]
        path = path.rstrip(";,)")
        if not path or path == "/tmp" or path.startswith("/tmp/") or path == "/dev/null" or path.startswith("&"):
            return

        scope = SCOPE_WORKSPACE
        lowered = path.lower()
        if lowered in ("/", "/*"):
            scope = SCOPE_SYSTEM
        elif lowered.startswith("/dev/tcp"):
            scope = SCOPE_NETWORK
        elif _SENSITIVE_PATH_RE.search(lowered) or _SYSTEM_PATH_RE.search(lowered):
            scope = SCOPE_SYSTEM
        elif lowered == self.cwd or lowered.startswith(self.cwd + "/"):
            scope = SCOPE_WORKSPACE
        elif _EXTERNAL_PATH_RE.search(lowered) or ".." in lowered:
            scope = SCOPE_EXTERNAL
        self.add_mode(scope, permissions)

    @staticmethod
    def _tokens(segment: str) -> List[str]:
        try:
            lexer = shlex.shlex(segment, posix=True, punctuation_chars="<>")
            lexer.whitespace_split = True
            lexer.commenters = ""
            return list(lexer)
        except ValueError:
            return segment.split()

    def scan_segment(self, segment: str) -> None:
        seg = segment.strip().lower()
        if not seg:
            return

        if re.match(r"^(sudo|su|doas)(\s|$)", seg) or re.match(r"^(shutdown|reboot|halt|poweroff)", seg):
            self.add_mode(SCOPE_SYSTEM, PERM_EXECUTE)
        if re.match(r"^(mkfs|fdisk|diskutil)(\s|$)", seg) or re.match(r"^(mount|umount)\s", seg):
            self.add_mode(SCOPE_SYSTEM, PERM_WRITE)

        if (
            re.search(r"(^|\s)(curl|wget|http)(\s|$)", seg)
            or "https://" in seg
            or "http://" in seg
            or re.match(r"^git\s+(clone|fetch|pull|ls-remote)(\s|$)", seg)
        ):
            self.add_mode(SCOPE_NETWORK, PERM_READ)

        if (
            re.match(r"^git\s+push(\s|$)", seg)
            or re.search(r"(^|\s)scp\s", seg)
            or re.search(r"(^|\s)curl\s+(-d|--data|-f|-t)(\s|=)", seg)
        ):
            self.add_mode(SCOPE_NETWORK, PERM_WRITE)

        executes_stream = any(token in seg for token in ("| bash", "| sh", "eval ", "source <(", "bash -c $(", "sh -c $("))
        has_network_source = any(token in seg for token in ("curl ", "wget ", "http://", "https://"))
        if executes_stream and has_network_source:
            self.add_mode(SCOPE_NETWORK, PERM_EXECUTE)

        if _ROOT_DELETE_RE.search(seg) or _DEVICE_WRITE_RE.search(seg):
            self.add_mode(SCOPE_SYSTEM, PERM_WRITE)

        execute_patterns = (
            r"^\./",
            r"^(bash|sh|zsh)\s",
            r"^python[^\s]*($|\s)",
            r"^(node|ruby|perl)\s",
            r"^npm\s+(test|run)(\s|$)",
            r"^make($|\s)",
            r"^cargo\s+(test|build)(\s|$)",
            r"^go\s+test(\s|$)",
            r"^git\s+(commit|add|checkout|merge|rebase|stash)(\s|$)",
            r"(^|\s)function\s",
            r"\(\)",
            r"\{",
            r"(^|\s)(if|for|while|case)\s",
            r":\(\)\{:\|:&\};:",
        )
        if any(re.search(pattern, seg) for pattern in execute_patterns):
            self.add_mode(SCOPE_WORKSPACE, PERM_EXECUTE)

        write_patterns = (
            r">",
            r"(^|\s)tee\s",
            r"^(mkdir|touch|cp|mv|rm)\s",
            r"\srm\s",
            r"sed\s+-i",
            r"\s-delete($|\s)",
            r"^git\s+(fetch|pull|clone|commit|add|checkout|merge|rebase|stash)(\s|$)",
            r"^(npm|pnpm|yarn)\s+install(\s|$)",
            r"^cargo\s+build(\s|$)",
            r"^go\s+test(\s|$)",
            r"^npm\s+test(\s|$)",
        )
        write_like = any(re.search(pattern, seg) for pattern in write_patterns)
        path_permissions = PERM_READ | PERM_WRITE if write_like else PERM_READ
        saw_path = False
        pending_redirect = 0

        for token in self._tokens(seg):
            if pending_redirect:
                self.add_path(token, pending_redirect)
                saw_path = True
                pending_redirect = 0
                continue
            if token in (">", ">>", "1>", "1>>"):
                pending_redirect = PERM_WRITE
                continue
            if token == "<>":
                pending_redirect = PERM_READ | PERM_WRITE
                continue
            if token.startswith("2>"):
                continue
            if token.startswith((">", ">>")):
                self.add_path(token.lstrip(">"), PERM_WRITE)
                saw_path = True
                continue
            if token.startswith("<>"):
                self.add_path(token[2:], PERM_READ | PERM_WRITE)
                saw_path = True
                continue
            if token.startswith(("/", "./", "../", "~/")):
                self.add_path(token, path_permissions)
                saw_path = True
            elif _SENSITIVE_PATH_RE.search(token):
                self.add_path(token, path_permissions)
                saw_path = True

        if write_like and not saw_path and "/tmp/" not in seg:
            self.add_mode(SCOPE_WORKSPACE, PERM_WRITE)

    def classify(self, command: str) -> str:
        if not command:
            return "0000"
        script = command.lower().replace("\\\n", " ")
        if "/dev/tcp" in script:
            self.add_mode(SCOPE_NETWORK, PERM_READ | PERM_WRITE)
        for segment in _split_script(script):
            self.scan_segment(segment)
        if self.required_mask == 0:
            self.add_mode(SCOPE_WORKSPACE, PERM_READ)
        return format(self.required_mask, "04o")


def _split_script(script: str) -> Iterable[str]:
    """按换行、分号、&&、|| 拆分，同时保留普通管道供网络执行识别。"""
    return (part.strip() for part in re.split(r"\n|;|&&|\|\|", script) if part.strip())


def classify_required_mode(command: str, cwd: str) -> str:
    return BashModeClassifier(cwd).classify(command)


def evaluate(command: str, cwd: str, allowed_mode: object = None) -> PolicyDecision:
    allowed = normalize_mode(allowed_mode)
    required = classify_required_mode(command, cwd)
    is_allowed = mode_allows(allowed, required)
    if is_allowed:
        reason = "命令符合 Bash Guard 权限策略"
    else:
        reason = (
            "命令被 Bash Guard 阻止"
            f"（需要={required}，允许={allowed}；四位依次为 system/external/network/workspace，"
            "每位 4=读、2=写、1=执行）"
        )
    return PolicyDecision(is_allowed, allowed, required, reason)
