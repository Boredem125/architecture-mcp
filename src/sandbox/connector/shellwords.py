"""A conservative lexer for the static subset of shell command lines (T0f, D0b).

No AST and no model of bash. It reads only plain, quoted and backslash-escaped words,
the separators ``; & && | || |& newline ( )``, and redirections. Everything else is
recorded as a *reason* the command is **unresolvable**, and the caller never allows an
unresolvable command: it denies if a deny fragment is visible, else escalates. The
design is one-sided on purpose: a lexer bug can only add an escalation, never an allow.

Stdlib only, one linear pass over the raw string (no regex over it), and every limit
raises ``Bound`` so the caller denies: 32 KiB, nesting 8, 4,096 words, 256 quote pieces
in one word, and a 100 ms deadline checked per segment.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

MAX_BYTES = 32 * 1024
MAX_DEPTH = 8
MAX_WORDS = 4096
MAX_PIECES = 256
DEADLINE_SECONDS = 0.1


class Bound(Exception):
    """A limit was hit: the caller denies."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class LexError(Exception):
    """The command does not lex (for example an unbalanced quote)."""


@dataclass
class Word:
    raw: str  # quotes removed; backslash escapes kept (callers try both readings)
    glob: bool = False  # unquoted * ? [ { }
    dyn: bool = False  # $ ` or %VAR% outside single quotes: value unknown
    tilde: bool = False


@dataclass
class Segment:
    raw: str
    words: list[Word] = field(default_factory=list)
    redirs: list[tuple[str, Word]] = field(default_factory=list)
    piped: bool = False  # fed by a pipe from the previous segment


@dataclass
class Lexed:
    segments: list[Segment]
    reasons: set[str]


def check_deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise Bound("SHELL_DEADLINE", "analysis exceeded its 100 ms deadline")


# ---------------------------------------------------------------------------
# bash lexer
# ---------------------------------------------------------------------------

_PLAIN_BREAK = frozenset(" \t\r\n\\'\"$`()<>;&|#~*?[{}")
_PCT_VAR = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%")  # cmd-style %NAME% at a word start


class _Lexer:
    def __init__(self, s: str, deadline: float) -> None:
        self.s, self.n, self.i = s, len(s), 0
        self.deadline = deadline
        self.segs: list[Segment] = []
        self.reasons: set[str] = set()
        self.words: list[Word] = []
        self.redirs: list[tuple[str, Word]] = []
        self.cur: list[str] = []
        self.in_word = self.glob = self.dyn = self.tilde = self.quoted = False
        self.pieces = 0
        self.pending: str | None = None  # redirect operator waiting for its target
        self.heredocs: list[tuple[str, bool]] = []
        self.seg_start = 0
        self.piped_next = False
        self.piped = False
        self.depth = 0
        self.total_words = 0

    # -- words and segments ------------------------------------------------
    def end_word(self) -> None:
        if not self.in_word:
            return
        raw = "".join(self.cur)
        w = Word(raw, self.glob, self.dyn, self.tilde)
        if not self.quoted and _PCT_VAR.match(raw):
            w.dyn = True
        if w.dyn:
            self.reasons.add("expansion")
        if w.tilde:
            self.reasons.add("tilde")
        if w.glob and "{" in raw and "}" in raw and ("," in raw or ".." in raw):
            self.reasons.add("brace_expansion")
        self.total_words += 1
        if self.total_words > MAX_WORDS:
            raise Bound("SHELL_BOUND", f"more than {MAX_WORDS} words")
        if self.pending is not None:
            op, self.pending = self.pending, None
            if op in ("<<", "<<-"):
                self.heredocs.append((raw, op == "<<-"))
            self.redirs.append((op, w))
        else:
            self.words.append(w)
        self.cur = []
        self.in_word = self.glob = self.dyn = self.tilde = self.quoted = False
        self.pieces = 0

    def end_segment(self, sep: str, resume: int, end: int | None = None) -> None:
        end = self.i if end is None else end
        self.end_word()
        if self.pending is not None:
            self.reasons.add("syntax")
            self.pending = None
        if self.words or self.redirs:
            self.segs.append(Segment(self.s[self.seg_start:end].strip(), self.words,
                                     self.redirs, self.piped))
        check_deadline(self.deadline)
        self.words, self.redirs = [], []
        self.piped = self.piped_next = sep in ("|", "|&")
        self.seg_start = resume

    def add(self, text: str) -> None:
        self.cur.append(text)
        self.in_word = True

    def piece(self) -> None:
        self.pieces += 1
        self.quoted = self.in_word = True
        if self.pieces > MAX_PIECES:
            raise Bound("SHELL_BOUND", f"more than {MAX_PIECES} quoted pieces in one word")

    # -- redirections ------------------------------------------------------
    def redirect(self, c: str) -> None:
        s, i = self.s, self.i
        nxt, nn = s[i + 1:i + 2], s[i + 2:i + 3]
        if nxt == "(":  # <(...) and >(...): process substitution
            self.reasons.add("expansion")
            self.end_word()
            self.i += 1
            return
        if self.in_word and not self.quoted and "".join(self.cur).isdigit():
            self.cur, self.in_word = [], False  # the 2 of 2>&1 is a descriptor, not a word
        self.end_word()
        if c == ">":
            op = ">>" if nxt == ">" else ">" + nxt if nxt in ("&", "|") else ">"
        else:
            op = ("<<<" if nn == "<" else "<<-" if nn == "-" else "<<") if nxt == "<" else \
                "<" + nxt if nxt in ("&", ">") else "<"
        self.i += len(op)
        if op in ("<<", "<<-"):
            self.reasons.add("heredoc")
        self.pending = op

    def heredoc_bodies(self) -> None:
        """Skip the bodies of pending here-documents, starting after the newline."""
        pos = self.i + 1
        for delim, strip in self.heredocs:
            while pos < self.n:
                eol = self.s.find("\n", pos)
                eol = self.n if eol < 0 else eol
                line = self.s[pos:eol].rstrip("\r")
                pos = min(eol + 1, self.n)
                if (line.lstrip("\t") if strip else line) == delim:
                    break
        self.heredocs = []
        self.i = self.seg_start = pos

    # -- main loop -----------------------------------------------------------
    def run(self) -> Lexed:
        s, n = self.s, self.n
        ticks = 0
        while self.i < n:
            ticks += 1
            if not ticks & 1023:
                check_deadline(self.deadline)
            i = self.i
            c = s[i]
            if c not in _PLAIN_BREAK:
                j = i + 1
                while j < n and s[j] not in _PLAIN_BREAK:
                    j += 1
                self.add(s[i:j])
                self.i = j
                continue
            nxt = s[i + 1:i + 2]
            if c in " \t":
                self.end_word()
            elif c == "\\":
                if nxt == "\n":
                    self.i += 1  # line continuation: the word keeps going
                elif nxt == "\r" and s[i + 2:i + 3] == "\n":
                    self.i += 2
                else:
                    self.add(c + nxt)
                    self.i += 1
            elif c == "'":
                j = s.find("'", i + 1)
                if j < 0:
                    raise LexError("unbalanced single quote")
                self.piece()
                self.add(s[i + 1:j])
                self.i = j
            elif c == '"':
                self.double_quote()
            elif c == "$":
                if nxt in ("'", '"') or (nxt and not nxt.isspace()):
                    self.dyn = True
                self.add(c)
            elif c == "`":
                self.reasons.add("expansion")
                self.end_segment("`", i + 1)
            elif c in "()":
                self.reasons.add("compound")
                self.depth += 1 if c == "(" else -1
                self.depth = max(self.depth, 0)
                if self.depth > MAX_DEPTH:
                    raise Bound("SHELL_BOUND", f"nesting deeper than {MAX_DEPTH}")
                self.end_segment(c, i + 1)
            elif c in "<>":
                self.redirect(c)
                continue
            elif c == "&" and nxt == ">":  # &> and &>>
                self.end_word()
                self.pending = "&>>" if s[i + 2:i + 3] == ">" else "&>"
                self.i += len(self.pending) - 1
            elif c in ";&|\r\n":
                sep = c
                if c in "&|" and nxt == c:
                    sep = c + c
                elif c == "|" and nxt == "&":
                    sep = "|&"
                elif c == "\r" and nxt == "\n":
                    sep = "\r\n"
                self.i += len(sep) - 1
                self.end_segment(sep, self.i + 1, i)
                if sep[-1] == "\n" and self.heredocs:
                    self.heredoc_bodies()
                    continue
            elif c == "#":
                if self.in_word:
                    self.add(c)
                else:  # a comment: its text is never executed, but never allowed either
                    self.reasons.add("comment")
                    j = s.find("\n", i)
                    self.i = n if j < 0 else j
                    continue
            elif c == "~":
                if not self.in_word or "".join(self.cur)[-1:] in ("=", ":"):
                    self.tilde = True
                self.add(c)
            else:  # * ? [ { }
                self.glob = True
                self.add(c)
            self.i += 1
        self.end_segment("", n)
        return Lexed(self.segs, self.reasons)

    def double_quote(self) -> None:
        s, n = self.s, self.n
        j, buf = self.i + 1, []
        while True:
            if j >= n:
                raise LexError("unbalanced double quote")
            ch = s[j]
            if ch == '"':
                break
            if ch == "\\" and j + 1 < n:
                nx = s[j + 1]
                if nx in '"\\$`':
                    buf.append(nx)
                    j += 2
                    continue
                if nx == "\n":
                    j += 2
                    continue
                if nx == "\r" and s[j + 2:j + 3] == "\n":
                    j += 3
                    continue
            elif ch == "`" or (ch == "$" and j + 1 < n and not s[j + 1].isspace() and s[j + 1] != '"'):
                self.dyn = True
            buf.append(ch)
            j += 1
        self.piece()
        self.add("".join(buf))
        self.i = j


# ---------------------------------------------------------------------------
# PowerShell lexer: a smaller subset, everything else unresolvable
# ---------------------------------------------------------------------------

_PS_SPLIT = frozenset("&|(){}<>,")  # flagged, and they end the word and the segment
_PS_MARK = frozenset("$%!^@`#")  # flagged, kept in the word


def _lex_pwsh(s: str, deadline: float) -> Lexed:
    lx = _Lexer(s, deadline)
    n = len(s)
    while lx.i < n:
        i = lx.i
        c = s[i]
        if c in " \t":
            lx.end_word()
        elif c in "\r\n;" or c in _PS_SPLIT:
            if c in _PS_SPLIT:
                lx.reasons.add("pwsh_syntax")
            lx.end_segment("|" if c == "|" else c, i + 1)
        elif c in "'\"":
            j = i + 1
            while True:
                if j >= n:
                    raise LexError("unbalanced quote")
                if s[j] == "`" and c == '"':
                    lx.dyn = True
                    j += 2
                    continue
                if s[j] == "$" and c == '"':
                    lx.dyn = True
                if s[j] == c:
                    if s[j + 1:j + 2] == c:  # '' and "" are an escaped quote
                        j += 2
                        continue
                    break
                j += 1
            lx.piece()
            lx.add(s[i + 1:j].replace(c + c, c))
            lx.i = j
        elif c in _PS_MARK:
            lx.reasons.add("pwsh_syntax")
            lx.dyn = lx.dyn or c != "#"
            lx.add(c)
        else:
            if c in "*?[":
                lx.glob = True
            if c == "~" and not lx.in_word:
                lx.tilde = True
            lx.add(c)
        lx.i += 1
    lx.end_segment("", n)
    return Lexed(lx.segs, lx.reasons)


def lex(command: str, shell: str = "bash", deadline: float | None = None) -> Lexed:
    """Lex *command*. Raises ``Bound`` or ``LexError``; the caller denies on either."""
    if deadline is None:
        deadline = time.monotonic() + DEADLINE_SECONDS
    if shell == "pwsh":
        return _lex_pwsh(command, deadline)
    return _Lexer(command, deadline).run()


# ---------------------------------------------------------------------------
# what a segment's command word does
# ---------------------------------------------------------------------------

_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")
_EXTS = (".exe", ".cmd", ".bat", ".com", ".ps1")
_KEYWORDS = frozenset(
    "if then elif else fi for while until do done case esac select function coproc [[ ]] { } ! in "
    "foreach filter workflow".split())
_INDIRECT = frozenset(
    "eval source . exec command builtin enable env xargs sudo doas su nohup time timeout nice "
    "setsid stdbuf script trap declare typeset export read local readonly alias unalias mapfile "
    "readarray watch parallel at batch ionice chrt taskset nsenter unshare chroot strace ltrace "
    "gdb valgrind fakeroot runuser pkexec run0 flock unbuffer socat expect wsl start call "
    "iex invoke-expression start-process saps invoke-command icm invoke-item ii set-alias sal "
    "new-alias nal".split())
_CODE_TOOLS = frozenset(
    "awk gawk mawk nawk sed gsed ssh scp sftp vim vi nvim ex view emacs npx uvx bunx".split())
_SHELLS = frozenset("sh bash zsh dash ksh ksh93 ash csh tcsh fish busybox rbash mksh yash".split())
_FAMILIES = (  # (family, base-name pattern, option letters that carry code)
    ("python", re.compile(r"(python|pythonw|pypy|py)[0-9.]*"), "c"),
    ("node", re.compile(r"(node|nodejs|deno|bun|tsx|ts-node)[0-9.]*"), "ep"),
    ("perl", re.compile(r"(perl|ruby|jruby|lua|luajit|rscript|julia|osascript|groovy|irb)[0-9.]*"), "eE"),
    ("php", re.compile(r"php[0-9.]*"), "rRBE"),
)
_FEEDS = frozenset(("<", "<<", "<<-", "<<<", "<>", "<&"))
_RUNNERS = {"pipx": {"run"}, "npm": {"exec", "x", "dlx"}, "pnpm": {"dlx", "exec"},
            "yarn": {"dlx", "exec"}, "bun": {"x"}}


def bases(raw: str) -> set[str]:
    """Candidate command names of one word: last path component, extension stripped,
    read both as a Windows path (backslash separator) and as bash (backslash escape)."""
    out: set[str] = set()
    for v in (raw.replace("\\", "/"), raw.replace("\\", ""), raw.replace("\\", "").replace("^", "")):
        comps = [c for c in v.split("/") if c]
        if comps:
            b = comps[-1].casefold().rstrip(". ")
            out.add(b)
            out.update(b[:-len(e)] for e in _EXTS if b.endswith(e))
    return out


def _is_option_cluster(a: str) -> bool:
    return len(a) > 1 and a[0] == "-" and a[1] != "-"


def segment_reasons(seg: Segment) -> list[str]:
    """Reasons the segment's command cannot be resolved statically (D0b 3b-3d)."""
    if not seg.words:
        return []
    first, args = seg.words[0], [w.raw for w in seg.words[1:]]
    names = bases(first.raw)
    out: list[str] = []
    if _ASSIGN.match(first.raw):
        out.append("assignment_word")  # X=y cmd: PATH, BASH_ENV, LD_PRELOAD, NODE_OPTIONS ...
    if first.glob:
        out.append("glob_command_word")
    if names & _KEYWORDS:
        out.append("shell_keyword")
    if names & _INDIRECT:
        out.append("indirection_word")
    if "printf" in names and any(a.startswith("-v") for a in args):
        out.append("printf_v")
    if names & _CODE_TOOLS:
        out.append("code_carrying_tool")
    if names & {"cmd", "pwsh", "powershell", "powershell_ise", "pwsh-preview"}:
        out.append("interpreter_cmd_pwsh")
    fed = seg.piped or any(op in _FEEDS for op, _ in seg.redirs) or "-" in args
    fam_hit = False
    if names & _SHELLS:
        fam_hit = True
        if any(_is_option_cluster(a) and "c" in a for a in args):
            out.append("interpreter_code")
    for fam, pat, letters in _FAMILIES:
        if any(pat.fullmatch(nm) for nm in names):
            fam_hit = True
            if any(_is_option_cluster(a) and any(ch in a[1:] for ch in letters) for a in args) \
                    or (fam == "node" and any(a.startswith(("--eval", "--print")) for a in args)) \
                    or (fam == "node" and args[:1] == ["eval"]):
                out.append("interpreter_code")
    if fam_hit and fed:
        out.append("interpreter_fed")
    if "git" in names and any(
            a == "-c" or a.startswith(("--config-env", "--exec-path", "--output", "-O", "--ext-diff",
                                       "--textconv", "--no-index"))
            or (a.startswith("-c") and "=" in a) for a in args):
        out.append("code_carrying_tool")  # also: --output writes a file, e.g. .git/config
    if names & {"find", "fd"} and any(a in ("-exec", "-execdir", "-ok", "-okdir", "-x", "-X",
                                            "--exec", "--exec-batch") for a in args):
        out.append("find_exec")
    if names & {"tar", "bsdtar"} and any(
            a.startswith(("--to-", "--checkpoint-a", "--use-", "--rsh", "--info-script",
                          "--new-volume-script", "--rmt")) or (_is_option_cluster(a) and ("I" in a or "F" in a))
            for a in args):
        out.append("code_carrying_tool")
    if "rsync" in names and any(a.startswith(("--rsh", "--rsync-path")) or
                                (_is_option_cluster(a) and "e" in a) for a in args):
        out.append("code_carrying_tool")
    for nm in names:
        if nm in _RUNNERS and args[:1] and args[0].casefold() in _RUNNERS[nm]:
            out.append("code_carrying_tool")
    return out


def encoded_command(seg: Segment) -> bool:
    """A PowerShell -EncodedCommand (any abbreviation, any dash) anywhere in the segment."""
    ws = [w.raw for w in seg.words]
    for k, w in enumerate(ws):
        low = w.casefold()
        if ("pwsh" in low or "powershell" in low) and \
                bases(w) & {"pwsh", "powershell", "powershell_ise", "pwsh-preview"}:
            for a in ws[k + 1:]:
                rest = a.lstrip("-/‒–—―−").casefold()
                if len(rest) == len(a) or not rest:
                    continue
                rest = re.split(r"[:=]", rest, maxsplit=1)[0]
                if not rest:
                    continue
                if rest in ("ec", "ea") or "encodedcommand".startswith(rest) \
                        or "encodedarguments".startswith(rest):
                    return True
    return False


# ---------------------------------------------------------------------------
# deny fragments
# ---------------------------------------------------------------------------

FRAGMENTS = ("sandbox", ".sand", "sandbo~", "approve", "propose", "state/keys", "statekeys")
_FOLD = str.maketrans("", "", "'\"\\^`")


def fragment(command: str) -> str | None:
    """The first deny fragment visible once the text is case-folded and quotes, ``\\``,
    ``^`` and backticks are removed, else None."""
    folded = command.casefold().translate(_FOLD)
    for f in FRAGMENTS:
        if f in folded:
            return f
    return None
