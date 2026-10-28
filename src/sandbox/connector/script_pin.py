"""Script content binding: resolver, preview and file pinning (ADR 0010 s9).

One function ``resolve`` is shared by the hook and the broker.  It uses
``shellwords.lex`` with the shell family the hook models: pwsh if
``tool_name == "PowerShell"``, else bash.

The resolver returns a ``ScriptResolution`` that tells the caller:
- *bound*: the command references a single static script that can be pinned;
- *unbound*: a reason code why the script cannot be pinned;
- *none*: the command has no script-shaped part (curl, git, kubectl).

The pin helpers lock the file in place during execution:
- Windows: CreateFile handles with FILE_FLAG_OPEN_REPARSE_POINT;
- POSIX: O_NOFOLLOW walk with dir_fd, fstat for regular file nlink 1.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sandbox.connector import shellwords

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_PREVIEW_BYTES = 64 * 1024  # 64 KiB

# C0 controls other than tab (0x09), LF (0x0A) and CR (0x0D),
# plus DEL (0x7F), C1 controls (0x80-0x9F) and bidi controls.
_BAD_CONTROLS = set()
for _cp in range(0x00, 0x20):
    if _cp not in (0x09, 0x0A, 0x0D):
        _BAD_CONTROLS.add(chr(_cp))
_BAD_CONTROLS.add('\x7f')  # DEL
for _cp in range(0x80, 0xA0):
    _BAD_CONTROLS.add(chr(_cp))
# Unicode bidi controls
for _cp in (0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F),
            *range(0x2066, 0x206A)):
    _BAD_CONTROLS.add(chr(_cp))

# ---------------------------------------------------------------------------
# Interpreter families and option tables (ADR 0010 s9 9.1)
# ---------------------------------------------------------------------------

_PYTHON_RE = re.compile(
    r"(?:python|python3(?:\.\d+)?)"
    r"(?:\.exe)?",
    re.IGNORECASE,
)

_NODE_RE = re.compile(r"node(?:\.exe)?", re.IGNORECASE)
_BASH_RE = re.compile(r"(?:bash|sh)(?:\.exe)?", re.IGNORECASE)
_PWSH_RE = re.compile(r"pwsh(?:\.exe)?", re.IGNORECASE)

# Deferred interpreters -- unbound in M2
_DEFERRED_RE = re.compile(
    r"(?:ruby|perl|dash|zsh|py|pythonw|powershell)"
    r"(?:\d[\d.]*)?(?:\.exe)?",
    re.IGNORECASE,
)

# Options that take a value argument (the next word is consumed)
_PYTHON_VALUE_OPTS = frozenset({"-W", "-X"})
# Boolean/flag options that do NOT consume the next word
_PYTHON_FLAG_OPTS = frozenset({
    "-B", "-b", "-d", "-E", "-I", "-i", "-O", "-OO",
    "-q", "-s", "-S", "-u", "-v", "-V", "--version", "-h", "--help",
    "--check-hash-based-pycs",
})
# Options that make the command unbound (code execution)
_PYTHON_UNBOUND_OPTS = frozenset({"-c", "-m", "-e", "-p", "-r", "--import"})

_NODE_FLAG_OPTS = frozenset({
    "--check", "--experimental-modules", "--harmony",
    "--no-warnings", "--trace-warnings", "--stack-trace-limit",
})
_NODE_UNBOUND_OPTS = frozenset({"-e", "--eval", "-p", "--print", "--require", "-r"})

_BASH_FLAG_OPTS = frozenset({
    "--noprofile", "--norc", "--noediting", "--posix",
    "-n", "-v", "-x", "-e", "-u", "-o",
})
_BASH_UNBOUND_OPTS = frozenset({"-c", "-l", "--rcfile", "-s"})

_PWSH_FLAG_OPTS = frozenset({
    "-NoProfile", "-NonInteractive", "-NoLogo", "-NoExit",
    "-Sta", "-Mta", "-WindowStyle",
})
_PWSH_UNBOUND_OPTS = frozenset({"-Command", "-c", "-EncodedCommand", "-e"})


def _family_for_tool(tool_name: str) -> str:
    """Shell family from tool_name (the classify.py rule)."""
    return "pwsh" if tool_name == "PowerShell" else "bash"


def _base_name(word: str) -> str:
    """Extract the base name from a path-like word, case-folded."""
    # Handle both forward and back slashes
    parts = re.split(r"[\\/]", word)
    return parts[-1].lower() if parts else word.lower()


def _is_abs_path(word: str) -> bool:
    """True if the word looks like an absolute path."""
    if len(word) >= 2 and word[1] == ':' and word[0].isalpha():
        return True  # Windows: C:\...
    if word.startswith('/'):
        return True  # POSIX
    return False


def _match_interpreter(base: str, word: str):
    """Return (family, matched) or None.

    family is one of: python, node, bash, pwsh, deferred.
    """
    if _PYTHON_RE.fullmatch(base):
        return ("python", True)
    if _NODE_RE.fullmatch(base):
        return ("node", True)
    if _BASH_RE.fullmatch(base):
        return ("bash", True)
    if _PWSH_RE.fullmatch(base):
        return ("pwsh", True)
    if _DEFERRED_RE.fullmatch(base):
        return ("deferred", True)
    return None


# ---------------------------------------------------------------------------
# Resolution result
# ---------------------------------------------------------------------------

@dataclass
class ScriptResolution:
    """Result of resolving a command to a script."""
    binding: str = "none"  # "bound", "unbound", "none"
    script: dict[str, Any] | None = None  # {rel, sha256, size, family, argv, script_index}
    script_unbound: str = ""  # reason code or ""
    script_preview: dict[str, Any] | None = None  # {text, sha256, shown, why}
    family: str = ""  # interpreter family
    argv: list[str] | None = None  # the lexed words for shell=False execution


def _has_ntfs_stream(operand: str) -> bool:
    """True if the operand names an NTFS alternate data stream."""
    # On Windows, after the drive letter (e.g., C:), a colon signals a stream
    if sys.platform != "win32":
        return False
    # Strip drive letter prefix
    rest = operand
    if len(operand) >= 2 and operand[1] == ':' and operand[0].isalpha():
        rest = operand[2:]
    return ':' in rest


def _check_path_safety(
    script_path: Path,
    root: Path,
    key_home: str | None = None,
) -> str | None:
    """Return a reason string if the script path is unsafe, else None."""
    try:
        resolved = script_path.resolve()
        root_resolved = root.resolve()
    except (OSError, ValueError):
        return "unresolvable_path"

    # Must be under root
    try:
        resolved.relative_to(root_resolved)
    except ValueError:
        return "outside_root"

    # Walk path components: no symlink, junction or reparse point from root down
    # Check that the file exists first
    if not script_path.exists():
        return "file_not_found"

    # Check each component from root down
    rel = resolved.relative_to(root_resolved)
    current = root_resolved
    for part in rel.parts[:-1]:
        current = current / part
        if not current.exists():
            return "path_component_missing"
        if current.is_symlink():
            return "symlink_in_path"
        if sys.platform == "win32":
            try:
                import ctypes.wintypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(str(current))
                if attrs != -1 and attrs & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
                    return "reparse_point_in_path"
            except Exception:
                pass

    # Check the file itself
    if script_path.is_symlink():
        return "symlink"
    if not script_path.is_file():
        return "not_regular_file"

    # Check nlink
    try:
        st = script_path.stat()
        if hasattr(st, 'st_nlink') and st.st_nlink > 1:
            return "hard_link"
    except OSError:
        return "stat_failed"

    # Must not be under .sandbox/
    try:
        sandbox_dir = root_resolved / ".sandbox"
        resolved.relative_to(sandbox_dir)
        return "under_sandbox"
    except ValueError:
        pass  # Good, not under .sandbox/

    # Must not be under key_home
    if key_home:
        try:
            kh = Path(key_home).resolve()
            resolved.relative_to(kh)
            return "under_key_home"
        except (ValueError, OSError):
            pass

    return None


def _read_script_content(script_path: Path) -> tuple[bytes | None, str]:
    """Read script content. Returns (bytes, error_reason_or_empty)."""
    try:
        data = script_path.read_bytes()
        return data, ""
    except OSError:
        return None, "read_failed"


def _make_preview(raw_bytes: bytes, layout_root: Path) -> dict[str, Any] | None:
    """Build the preview dict for a script body.

    Returns {text, sha256, shown, why} or None if the body cannot be shown.
    """
    # Check size
    if len(raw_bytes) > MAX_PREVIEW_BYTES:
        return {"text": "", "sha256": "", "shown": False, "why": "over_64k"}

    # Check for NUL
    if b'\x00' in raw_bytes:
        return {"text": "", "sha256": "", "shown": False, "why": "binary"}

    # Try UTF-8 decode
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return {"text": "", "sha256": "", "shown": False, "why": "non_utf8"}

    # Check for bad controls
    for ch in text:
        if ch in _BAD_CONTROLS:
            return {"text": "", "sha256": "", "shown": False, "why": "control_char"}

    # Scrub secrets from the preview
    try:
        from sandbox.connector.scrub import scrub_text
        scrubbed = scrub_text(text)
    except Exception:
        scrubbed = text

    preview_sha = hashlib.sha256(scrubbed.encode("utf-8")).hexdigest()
    return {"text": scrubbed, "sha256": preview_sha, "shown": True, "why": ""}


def _rel_path(script_path: Path, root: Path) -> str:
    """Root-relative path with forward slashes."""
    try:
        return str(script_path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except (ValueError, OSError):
        return str(script_path).replace("\\", "/")


# ---------------------------------------------------------------------------
# The resolver
# ---------------------------------------------------------------------------

def resolve(
    command: str,
    tool_name: str,
    exec_cwd: str,
    root: str,
    *,
    key_home: str | None = None,
) -> ScriptResolution:
    """Resolve a command to a script, if it has one.

    Returns a ScriptResolution describing the binding state.
    Shared by the hook and the broker.
    """
    family = _family_for_tool(tool_name)
    shell = family  # shellwords.lex shell parameter

    # Lex the command
    try:
        lexed = shellwords.lex(command, shell)
    except (shellwords.Bound, shellwords.LexError):
        return ScriptResolution(binding="unbound", script_unbound="lex_error")

    # Must be exactly one segment
    if len(lexed.segments) != 1:
        if len(lexed.segments) > 1:
            # Multi-segment: check if the first word is an interpreter
            first_seg = lexed.segments[0]
            if first_seg.words:
                first_base = _base_name(first_seg.words[0].raw)
                if _match_interpreter(first_base, first_seg.words[0].raw) is not None:
                    # It IS an interpreter command in a pipe/compound: unbound
                    seg_seps = set()
                    for seg in lexed.segments:
                        if seg.piped:
                            seg_seps.add("pipe")
                    if seg_seps:
                        return ScriptResolution(binding="unbound", script_unbound="pipe")
                    return ScriptResolution(binding="unbound", script_unbound="compound")
            # Non-interpreter command in a pipe/compound: binding "none"
            return ScriptResolution(binding="none")
        return ScriptResolution(binding="none")

    seg = lexed.segments[0]

    # No redirections allowed for binding (only if word 0 is an interpreter)
    if seg.redirs:
        if seg.words:
            first_base = _base_name(seg.words[0].raw)
            if _match_interpreter(first_base, seg.words[0].raw) is not None:
                return ScriptResolution(binding="unbound", script_unbound="redirect")
        return ScriptResolution(binding="none")

    # Check reasons from the lexer
    if lexed.reasons:
        # Only flag structural issues as "unbound" if the command involves an interpreter
        _has_interp = False
        if seg.words:
            _first_base = _base_name(seg.words[0].raw)
            _has_interp = _match_interpreter(_first_base, seg.words[0].raw) is not None
        if _has_interp:
            if "expansion" in lexed.reasons:
                return ScriptResolution(binding="unbound", script_unbound="dynamic")
            if "compound" in lexed.reasons:
                return ScriptResolution(binding="unbound", script_unbound="compound")
            if "heredoc" in lexed.reasons:
                return ScriptResolution(binding="unbound", script_unbound="redirect")
            if "tilde" in lexed.reasons:
                return ScriptResolution(binding="unbound", script_unbound="dynamic")
            if "brace_expansion" in lexed.reasons:
                return ScriptResolution(binding="unbound", script_unbound="dynamic")
            if "comment" in lexed.reasons:
                return ScriptResolution(binding="unbound", script_unbound="compound")
            if "pwsh_syntax" in lexed.reasons:
                return ScriptResolution(binding="unbound", script_unbound="dynamic")
        else:
            return ScriptResolution(binding="none")

    if not seg.words:
        return ScriptResolution(binding="none")

    words = seg.words

    # Check for assignment prefix
    if re.match(r"[A-Za-z_][A-Za-z0-9_]*\+?=", words[0].raw):
        return ScriptResolution(binding="unbound", script_unbound="assignment")

    # Check for dynamic or glob in any word
    for w in words:
        if w.dyn:
            return ScriptResolution(binding="unbound", script_unbound="dynamic")
        if w.glob:
            return ScriptResolution(binding="unbound", script_unbound="glob")

    # Word 0 is the command name
    cmd_word = words[0].raw
    cmd_base = _base_name(cmd_word)

    # Check if it's a known interpreter
    interp = _match_interpreter(cmd_base, cmd_word)
    if interp is None:
        # Check for direct exec forms
        if cmd_word.startswith("./") or cmd_word.startswith(".\\"):
            return ScriptResolution(binding="unbound", script_unbound="direct_exec")
        # Check for .exe, .cmd, .bat extensions
        lower = cmd_base.lower()
        if lower.endswith((".exe", ".cmd", ".bat")):
            return ScriptResolution(binding="unbound", script_unbound="direct_exec")
        # Check for source / .
        if cmd_base in ("source",):
            return ScriptResolution(binding="unbound", script_unbound="source")
        if cmd_word == ".":
            return ScriptResolution(binding="unbound", script_unbound="source")
        # Check for cmd
        if cmd_base in ("cmd", "cmd.exe"):
            return ScriptResolution(binding="unbound", script_unbound="cmd_c")
        # Check if this looks like an unknown interpreter running a script file
        # (a word followed by what looks like a script path with a script extension).
        # Only script extensions trigger this -- paths like data/customers/a.csv
        # are arguments to non-interpreter commands (cat, rm, scp).
        if len(words) > 1:
            possible_script = words[1].raw
            if possible_script.endswith((".py", ".js", ".rb", ".pl", ".sh",
                                         ".lua", ".zsh", ".php", ".r", ".jl",
                                         ".ps1", ".ts", ".coffee", ".groovy")):
                return ScriptResolution(
                    binding="unbound", script_unbound="unknown_interpreter",
                )
        # Not an interpreter -- binding is "none" (curl, git, etc.)
        return ScriptResolution(binding="none")

    interp_family, _ = interp

    # Deferred interpreters are unbound
    if interp_family == "deferred":
        return ScriptResolution(binding="unbound", script_unbound="deferred_interpreter")

    # Parse options and find the script operand
    argv = [w.raw for w in words]
    script_index = None

    if interp_family == "python":
        i = 1
        while i < len(words):
            arg = words[i].raw
            if arg == "-":
                return ScriptResolution(binding="unbound", script_unbound="stdin")
            if arg.startswith("-"):
                if arg in _PYTHON_UNBOUND_OPTS or (len(arg) > 1 and arg[1] != '-' and
                        any(c in arg[1:] for c in "cmerp")):
                    # Check specific unbound options
                    if "-c" in arg or arg == "-c":
                        return ScriptResolution(binding="unbound", script_unbound="-c")
                    if "-m" in arg or arg == "-m":
                        return ScriptResolution(binding="unbound", script_unbound="-m")
                    if "-e" in arg or arg == "-e":
                        return ScriptResolution(binding="unbound", script_unbound="-c")
                    if "-p" in arg or arg == "-p":
                        return ScriptResolution(binding="unbound", script_unbound="-c")
                    if "-r" in arg or arg == "-r" or arg == "--import":
                        return ScriptResolution(binding="unbound", script_unbound="preload")
                    return ScriptResolution(binding="unbound", script_unbound=arg)
                if arg in _PYTHON_VALUE_OPTS:
                    i += 2  # skip the value
                    continue
                if arg.startswith("-W") and len(arg) > 2:
                    i += 1  # -Wfoo, value attached
                    continue
                if arg.startswith("-X") and len(arg) > 2:
                    i += 1  # -Xfoo, value attached
                    continue
                # Check for cluster options like -OBs
                if len(arg) > 1 and arg[1] != '-':
                    # Flag cluster
                    all_flags = True
                    j = 1
                    while j < len(arg):
                        ch = arg[j]
                        if ch in "cmerp":
                            return ScriptResolution(
                                binding="unbound",
                                script_unbound=f"-{ch}",
                            )
                        if f"-{ch}" not in {"-B", "-b", "-d", "-E", "-I", "-i",
                                            "-O", "-q", "-s", "-S", "-u", "-v",
                                            "-V", "-h"}:
                            if ch in "WX":
                                # Value option in cluster; rest is value
                                break
                            all_flags = False
                            break
                        j += 1
                    if not all_flags:
                        return ScriptResolution(
                            binding="unbound",
                            script_unbound="unknown_option",
                        )
                    i += 1
                    continue
                # Long options
                if arg.startswith("--"):
                    if arg in ("--version", "--help", "--check-hash-based-pycs"):
                        i += 1
                        continue
                    return ScriptResolution(
                        binding="unbound", script_unbound="unknown_option",
                    )
                i += 1
                continue
            elif arg == "-":
                return ScriptResolution(binding="unbound", script_unbound="stdin")
            else:
                script_index = i
                break
            i += 1

    elif interp_family == "node":
        i = 1
        while i < len(words):
            arg = words[i].raw
            if arg.startswith("-"):
                if arg in _NODE_UNBOUND_OPTS:
                    if arg in ("-e", "--eval"):
                        return ScriptResolution(binding="unbound", script_unbound="-c")
                    if arg in ("-p", "--print"):
                        return ScriptResolution(binding="unbound", script_unbound="-c")
                    if arg in ("-r", "--require"):
                        return ScriptResolution(binding="unbound", script_unbound="preload")
                    return ScriptResolution(binding="unbound", script_unbound=arg)
                i += 1
                continue
            elif arg == "-":
                return ScriptResolution(binding="unbound", script_unbound="stdin")
            else:
                script_index = i
                break
            i += 1

    elif interp_family == "bash":
        i = 1
        while i < len(words):
            arg = words[i].raw
            if arg.startswith("-"):
                if arg in ("-c",):
                    return ScriptResolution(binding="unbound", script_unbound="-c")
                if arg in ("-l", "--login"):
                    return ScriptResolution(binding="unbound", script_unbound="-c")
                if arg in ("--rcfile",):
                    return ScriptResolution(binding="unbound", script_unbound="-c")
                if arg in ("-s",):
                    return ScriptResolution(binding="unbound", script_unbound="stdin")
                # Known flag options
                i += 1
                continue
            elif arg == "-":
                return ScriptResolution(binding="unbound", script_unbound="stdin")
            else:
                script_index = i
                break
            i += 1

    elif interp_family == "pwsh":
        # For pwsh, -File is required for binding
        has_file = False
        i = 1
        while i < len(words):
            arg = words[i].raw
            arg_lower = arg.lower().lstrip("-/")
            if arg.startswith("-") or arg.startswith("/"):
                if arg_lower.startswith("file") or arg_lower == "f":
                    has_file = True
                    i += 1
                    continue
                if arg_lower.startswith("command") or arg_lower == "c":
                    return ScriptResolution(binding="unbound", script_unbound="-c")
                if arg_lower.startswith("encodedcommand") or arg_lower in ("e", "ec", "ea"):
                    return ScriptResolution(binding="unbound", script_unbound="-c")
                # Known flags (case insensitive)
                i += 1
                continue
            else:
                if has_file:
                    script_index = i
                    break
                else:
                    # pwsh without -File: unbound
                    return ScriptResolution(
                        binding="unbound", script_unbound="pwsh_no_file",
                    )
            i += 1
        if not has_file:
            return ScriptResolution(binding="unbound", script_unbound="pwsh_no_file")

    if script_index is None:
        # No script operand found
        return ScriptResolution(binding="none")

    script_operand = words[script_index].raw

    # NTFS stream check
    if _has_ntfs_stream(script_operand):
        return ScriptResolution(binding="unbound", script_unbound="ntfs_stream")

    # Resolve the script path relative to exec_cwd
    root_path = Path(root).resolve()
    cwd_path = Path(exec_cwd).resolve() if exec_cwd else root_path
    script_path = cwd_path / script_operand

    # Key home
    kh = key_home or os.environ.get("SANDBOX_KEY_HOME", "")

    # Safety checks
    safety = _check_path_safety(script_path, root_path, kh)
    if safety:
        return ScriptResolution(binding="unbound", script_unbound=safety)

    # Read the script content
    raw_bytes, read_err = _read_script_content(script_path)
    if read_err:
        return ScriptResolution(binding="unbound", script_unbound=read_err)
    assert raw_bytes is not None

    content_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    rel = _rel_path(script_path, root_path)

    # Build the preview
    preview = _make_preview(raw_bytes, root_path)

    script_dict = {
        "rel": rel,
        "sha256": content_sha256,
        "size": len(raw_bytes),
        "family": interp_family,
        "argv": argv,
        "script_index": script_index,
    }

    return ScriptResolution(
        binding="bound",
        script=script_dict,
        script_unbound="",
        script_preview=preview,
        family=interp_family,
        argv=argv,
    )


# ---------------------------------------------------------------------------
# Windows pinning (ADR 0010 s9 9.4)
# ---------------------------------------------------------------------------

if sys.platform == "win32":
    import ctypes.wintypes

    _GENERIC_READ = 0x80000000
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _FILE_SHARE_DELETE = 0x00000004
    _OPEN_EXISTING = 3
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    _INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value

    class _FileInformationByHandleClass(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", ctypes.wintypes.DWORD),
            ("ftCreationTime", ctypes.wintypes.FILETIME),
            ("ftLastAccessTime", ctypes.wintypes.FILETIME),
            ("ftLastWriteTime", ctypes.wintypes.FILETIME),
            ("dwVolumeSerialNumber", ctypes.wintypes.DWORD),
            ("nFileSizeHigh", ctypes.wintypes.DWORD),
            ("nFileSizeLow", ctypes.wintypes.DWORD),
            ("nNumberOfLinks", ctypes.wintypes.DWORD),
            ("nFileIndexHigh", ctypes.wintypes.DWORD),
            ("nFileIndexLow", ctypes.wintypes.DWORD),
        ]

    def _win_open_handle(
        path: str, *, is_dir: bool = False, share_delete: bool = False,
    ) -> int:
        """Open a Windows file handle with FILE_FLAG_OPEN_REPARSE_POINT."""
        flags = _FILE_FLAG_OPEN_REPARSE_POINT
        if is_dir:
            flags |= _FILE_FLAG_BACKUP_SEMANTICS
        share = _FILE_SHARE_READ
        if not share_delete and is_dir:
            pass  # directories: no delete sharing
        elif share_delete:
            share |= _FILE_SHARE_DELETE
        # File: shared read-only (no write, no delete)
        # Directory: shared read (no delete)
        handle = ctypes.windll.kernel32.CreateFileW(
            str(path),
            _GENERIC_READ,
            share,
            None,
            _OPEN_EXISTING,
            flags,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE or handle == -1:
            err = ctypes.get_last_error() or ctypes.windll.kernel32.GetLastError()
            raise OSError(f"CreateFileW failed for {path}: error {err}")
        return handle

    def _win_handle_info(handle: int) -> tuple[int, int, int]:
        """(nlinks, attributes, file_size) from GetFileInformationByHandle."""
        info = _FileInformationByHandleClass()
        ok = ctypes.windll.kernel32.GetFileInformationByHandle(
            ctypes.wintypes.HANDLE(handle),
            ctypes.byref(info),
        )
        if not ok:
            raise OSError("GetFileInformationByHandle failed")
        size = (info.nFileSizeHigh << 32) | info.nFileSizeLow
        return info.nNumberOfLinks, info.dwFileAttributes, size

    def _win_close(handle: int) -> None:
        ctypes.windll.kernel32.CloseHandle(ctypes.wintypes.HANDLE(handle))

    def _win_read_from_handle(handle: int, size: int) -> bytes:
        """Read file content from a Windows handle via ReadFile.

        Uses ReadFile through ctypes so the handle stays owned by the
        caller (the ScriptPin).  The previous open_osfhandle approach
        transferred ownership to the CRT, causing a double-close in
        pin.release() (R5).
        """
        if size == 0:
            return b""
        buf = ctypes.create_string_buffer(size)
        bytes_read = ctypes.wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.ReadFile(
            ctypes.wintypes.HANDLE(handle),
            buf,
            ctypes.wintypes.DWORD(size),
            ctypes.byref(bytes_read),
            None,
        )
        if not ok:
            raise OSError("ReadFile failed")
        return buf.raw[:bytes_read.value]


class ScriptPin:
    """Holds open handles/fds that pin a script and its parent directories."""

    def __init__(self) -> None:
        self._handles: list[int] = []  # Windows HANDLEs
        self._fds: list[int] = []  # POSIX fds
        self._file_hash: str = ""
        self._file_size: int = 0

    @property
    def file_hash(self) -> str:
        return self._file_hash

    @property
    def file_size(self) -> int:
        return self._file_size

    def release(self) -> None:
        """Release all held handles/fds."""
        if sys.platform == "win32":
            for h in self._handles:
                try:
                    _win_close(h)
                except Exception:
                    pass
            self._handles.clear()
        else:
            for fd in self._fds:
                try:
                    os.close(fd)
                except Exception:
                    pass
            self._fds.clear()

    def __del__(self) -> None:
        self.release()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.release()


def pin_script(
    script_path: Path,
    root: Path,
    expected_hash: str,
    expected_size: int,
) -> ScriptPin:
    """Pin a script file for the duration of execution.

    Raises OSError with a descriptive message on any failure.
    Returns a ScriptPin holding the open handles/fds.
    """
    pin = ScriptPin()

    if sys.platform == "win32":
        _pin_windows(pin, script_path, root, expected_hash, expected_size)
    else:
        _pin_posix(pin, script_path, root, expected_hash, expected_size)

    return pin


def _pin_windows(
    pin: ScriptPin,
    script_path: Path,
    root: Path,
    expected_hash: str,
    expected_size: int,
) -> None:
    """Windows pinning: CreateFile handles with share-mode locks."""
    resolved_root = root.resolve()
    resolved_script = script_path.resolve()

    try:
        rel = resolved_script.relative_to(resolved_root)
    except ValueError:
        raise OSError("script not under root")

    parts = list(rel.parts)

    # Open root directory
    try:
        rh = _win_open_handle(str(resolved_root), is_dir=True, share_delete=False)
        pin._handles.append(rh)
    except OSError as e:
        pin.release()
        raise OSError(f"cannot pin root: {e}") from e

    # Open each intermediate directory
    current = resolved_root
    for part in parts[:-1]:
        current = current / part
        try:
            dh = _win_open_handle(str(current), is_dir=True, share_delete=False)
            pin._handles.append(dh)
        except OSError as e:
            pin.release()
            raise OSError(f"cannot pin directory {current}: {e}") from e

    # Open the script file (shared read-only: no write, no delete)
    try:
        fh = _win_open_handle(str(resolved_script), is_dir=False, share_delete=False)
        pin._handles.append(fh)
    except OSError as e:
        pin.release()
        raise OSError(f"cannot pin script: {e}") from e

    # Read attributes from the handle (C-c0-1)
    try:
        nlinks, attrs, file_size = _win_handle_info(fh)
    except OSError as e:
        pin.release()
        raise OSError(f"cannot read handle info: {e}") from e

    if attrs & _FILE_ATTRIBUTE_REPARSE_POINT:
        pin.release()
        raise OSError("script is a reparse point")
    if nlinks > 1:
        pin.release()
        raise OSError(f"script has {nlinks} hard links (expected 1)")

    # Hash from the handle
    try:
        content = _win_read_from_handle(fh, file_size)
    except Exception as e:
        pin.release()
        raise OSError(f"cannot read from handle: {e}") from e

    actual_hash = hashlib.sha256(content).hexdigest()
    actual_size = len(content)

    if actual_hash != expected_hash or actual_size != expected_size:
        pin.release()
        raise OSError(
            f"SCRIPT_CHANGED: expected sha256={expected_hash} size={expected_size}, "
            f"got sha256={actual_hash} size={actual_size}"
        )

    pin._file_hash = actual_hash
    pin._file_size = actual_size


def _pin_posix(
    pin: ScriptPin,
    script_path: Path,
    root: Path,
    expected_hash: str,
    expected_size: int,
) -> None:
    """POSIX pinning: O_NOFOLLOW walk with dir_fd."""
    resolved_root = root.resolve()
    resolved_script = script_path.resolve()

    try:
        rel = resolved_script.relative_to(resolved_root)
    except ValueError:
        raise OSError("script not under root")

    parts = list(rel.parts)

    # Open root (following links above root is ok)
    try:
        root_fd = os.open(str(resolved_root), os.O_RDONLY | os.O_DIRECTORY)
        pin._fds.append(root_fd)
    except OSError as e:
        pin.release()
        raise OSError(f"cannot open root: {e}") from e

    # Walk directories with O_NOFOLLOW | O_DIRECTORY
    current_fd = root_fd
    for part in parts[:-1]:
        try:
            d_fd = os.open(
                part,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY,
                dir_fd=current_fd,
            )
            pin._fds.append(d_fd)
            current_fd = d_fd
        except OSError as e:
            pin.release()
            raise OSError(f"cannot open directory {part}: {e}") from e

    # Open the file with O_NOFOLLOW | O_NONBLOCK
    file_name = parts[-1]
    try:
        file_fd = os.open(
            file_name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=current_fd,
        )
        pin._fds.append(file_fd)
    except OSError as e:
        pin.release()
        raise OSError(f"cannot open script: {e}") from e

    # fstat: regular file, nlink 1
    try:
        st = os.fstat(file_fd)
    except OSError as e:
        pin.release()
        raise OSError(f"cannot fstat: {e}") from e

    if not stat.S_ISREG(st.st_mode):
        pin.release()
        raise OSError("not a regular file")
    if st.st_nlink != 1:
        pin.release()
        raise OSError(f"nlink {st.st_nlink} != 1")

    # Hash from the fd
    with os.fdopen(os.dup(file_fd), "rb") as f:
        content = f.read()

    actual_hash = hashlib.sha256(content).hexdigest()
    actual_size = len(content)

    if actual_hash != expected_hash or actual_size != expected_size:
        pin.release()
        raise OSError(
            f"SCRIPT_CHANGED: expected sha256={expected_hash} size={expected_size}, "
            f"got sha256={actual_hash} size={actual_size}"
        )

    pin._file_hash = actual_hash
    pin._file_size = actual_size


def posix_rehash(script_path: Path) -> str:
    """Re-hash a script after the child exits (POSIX after-run check)."""
    try:
        data = script_path.read_bytes()
        return hashlib.sha256(data).hexdigest()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Shell resolution for the broker (ADR 0010 s9 9.4)
# ---------------------------------------------------------------------------

def resolve_shell(
    tool_name: str,
    session: dict[str, Any],
) -> tuple[str | None, str]:
    """Resolve the shell binary path for the broker.

    Returns (shell_path, error_reason).
    shell_path is None if the shell is not available.
    """
    family = _family_for_tool(tool_name)
    shells = session.get("shells")
    if shells is None:
        return None, "SHELL_UNAVAILABLE: no shells field in session.json"

    if family == "pwsh":
        path = shells.get("pwsh")
    else:
        path = shells.get("bash")

    if not path:
        return None, f"SHELL_UNAVAILABLE: no {family} shell recorded"

    # Validate at exec time: absolute, regular, not reparse, outside root
    if not os.path.isabs(path):
        return None, f"SHELL_UNAVAILABLE: {family} path is not absolute"

    if not os.path.isfile(path):
        return None, f"SHELL_UNAVAILABLE: {family} path does not exist"

    # Check for reparse point on Windows
    if sys.platform == "win32":
        try:
            attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
            if attrs != -1 and attrs & 0x400:  # reparse point
                return None, f"SHELL_UNAVAILABLE: {family} path is a reparse point"
        except Exception:
            pass

    # Check symlink on POSIX
    if sys.platform != "win32":
        if os.path.islink(path):
            # symlinks in /usr/bin are OK (e.g. /usr/bin/bash -> /bin/bash)
            pass

    return path, ""


def build_shell_argv(
    command: str,
    tool_name: str,
    shell_path: str,
) -> list[str]:
    """Build the argv for running a command through the appropriate shell.

    bash: [bash, --noprofile, --norc, -c, <command>]
    pwsh: [pwsh, -NoProfile, -NonInteractive, -EncodedCommand, <base64>]
    """
    import base64

    family = _family_for_tool(tool_name)

    if family == "pwsh":
        encoded = base64.b64encode(
            command.encode("utf-16-le")
        ).decode("ascii")
        return [shell_path, "-NoProfile", "-NonInteractive",
                "-EncodedCommand", encoded]
    else:
        # bash
        # On Windows with MSYS bash, backslashes in drive-letter paths must
        # become forward slashes so bash interprets them correctly.  However,
        # non-path backslashes (e.g. `\n`, `\d+` in regexes, printf escapes)
        # must reach bash byte-for-byte (R3, ADR 0010 s9 9.4).
        #
        # Strategy: split the command into whitespace-separated tokens.  For
        # each token, convert backslashes to forward slashes ONLY if the
        # (possibly unquoted) token starts with a drive letter followed by
        # `:\`.  Leave every other backslash untouched.
        bash_cmd = command
        if sys.platform == "win32":
            import re as _re
            # _convert_drive_token: converts backslashes inside a single
            # whitespace-delimited token that begins with a drive-letter path.
            # Handles bare `E:\foo\bar`, single-quoted `'E:\foo\bar'` and
            # double-quoted `"E:\foo\bar"` forms.
            _DRIVE_TOKEN = _re.compile(
                r"""(?:^|(?<=\s))"""          # start of string or after whitespace
                r"""(["']?)"""                 # optional opening quote
                r"""([A-Za-z]):\\"""           # drive letter + :\
                r"""(\S*)"""                   # rest of token (non-whitespace)
                , _re.VERBOSE,
            )

            def _convert_drive_token(m: _re.Match) -> str:
                quote = m.group(1)
                drive = m.group(2)
                rest = m.group(3).replace('\\', '/')
                return f"{quote}{drive}:/{rest}"

            bash_cmd = _DRIVE_TOKEN.sub(_convert_drive_token, bash_cmd)
        return [shell_path, "--noprofile", "--norc", "-c", bash_cmd]
