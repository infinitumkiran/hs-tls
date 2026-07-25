#!/usr/bin/env python3
"""
Inject entry/exit call tracing into every top-level function of a Haskell package.

Strategy
--------
For each top-level function clause  `f p1 p2 = RHS`  we rewrite the RHS head to

    f p1 p2 = ETT.tio "Mod.f" $ RHS     -- result is `IO a`   -> in / out / exception
    f p1 p2 = ETT.tm  "Mod.f" $ RHS     -- result is `m a`    -> in / out
    f p1 p2 = ETT.t   "Mod.f" $ RHS     -- anything else      -> in only

`ETT.t :: String -> a -> a` is `Debug.Trace.trace`-shaped, so it type-checks against any
RHS whatsoever. `tio`/`tm` are only selected when the clause's argument count exactly
matches the number of top-level arrows in the function's type signature, so the RHS is
guaranteed to have the monadic type we claim it does.

Guarded clauses get one injection per guard alternative.
"""

import os
import re
import sys

KEYWORDS = {
    "import", "module", "type", "data", "newtype", "class", "instance",
    "deriving", "foreign", "infixl", "infixr", "infix", "pattern", "default",
    "where", "do", "let", "in", "if", "then", "else", "case", "of", "forall",
}

# Classes that guarantee a Monad superclass, so `tm` is safe on `m a`.
MONADISH = {
    "Monad", "MonadIO", "MonadFail", "MonadThrow", "MonadCatch", "MonadMask",
    "MonadState", "MonadReader", "MonadWriter", "MonadError", "MonadPlus",
    "MonadFix", "MonadRandom", "MonadUnliftIO", "MonadResource", "MonadRWS",
}

# Concrete monads (per-package) whose Monad instance has no extra constraints.
KNOWN_MONADS = {
    "TLSSt", "HandshakeM", "RecordM", "Get", "GetT", "Parser", "ParseASN1",
}

OPCHARS = set("!#$%&*+./<=>?@\\^|~:-")

IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_']*")


# ---------------------------------------------------------------------------
# lexing helpers
# ---------------------------------------------------------------------------

def strip_code(lines):
    """Return a parallel list of 'code-only' lines: comments/strings blanked out
    with spaces so column offsets stay identical.  Also returns, per line, a flag
    saying whether column 0 of that line sits inside a block comment."""
    out = []
    starts_in_comment = []
    nest = 0  # {- -} nesting depth
    for raw in lines:
        starts_in_comment.append(nest > 0)
        buf = list(raw)
        i = 0
        n = len(raw)
        while i < n:
            c = raw[i]
            if nest > 0:
                if raw.startswith("{-", i):
                    nest += 1
                    buf[i] = buf[i + 1] = " "
                    i += 2
                    continue
                if raw.startswith("-}", i):
                    nest -= 1
                    buf[i] = buf[i + 1] = " "
                    i += 2
                    continue
                buf[i] = " "
                i += 1
                continue
            if raw.startswith("{-", i):
                # a pragma {-# ... #-} is not a comment, but it contains no code
                nest += 1
                buf[i] = buf[i + 1] = " "
                i += 2
                continue
            if raw.startswith("--", i):
                # only a comment if not part of an operator like `-->` or `<--`
                j = i + 2
                while j < n and raw[j] == "-":
                    j += 1
                nxt = raw[j] if j < n else ""
                prv = raw[i - 1] if i > 0 else ""
                if nxt not in OPCHARS and prv not in OPCHARS:
                    for k in range(i, n):
                        buf[k] = " "
                    break
                i = j
                continue
            if c == '"':
                buf[i] = " "
                i += 1
                while i < n:
                    if raw[i] == "\\":
                        buf[i] = " "
                        if i + 1 < n:
                            buf[i + 1] = " "
                        i += 2
                        continue
                    if raw[i] == '"':
                        buf[i] = " "
                        i += 1
                        break
                    buf[i] = " "
                    i += 1
                continue
            if c == "'":
                # character literal, but ' is also valid in identifiers
                if i > 0 and (raw[i - 1].isalnum() or raw[i - 1] in "_'"):
                    i += 1
                    continue
                m = re.match(r"'(\\.[^']*|[^'\\])'", raw[i:])
                if m:
                    for k in range(i, i + m.end()):
                        buf[k] = " "
                    i += m.end()
                    continue
                i += 1
                continue
            i += 1
        out.append("".join(buf))
    return out, starts_in_comment


def depth_scan(code):
    """Yield (index, char, depth) for a code-only string, depth counting ()[]{} ."""
    depth = 0
    for i, c in enumerate(code):
        if c in "([{":
            yield i, c, depth
            depth += 1
        elif c in ")]}":
            depth -= 1
            yield i, c, depth
        else:
            yield i, c, depth


def find_tokens(code, depth_wanted=0):
    """Return list of (start, end, text, depth) for identifier and operator tokens."""
    toks = []
    depth = 0
    i = 0
    n = len(code)
    while i < n:
        c = code[i]
        if c in "([{":
            toks.append((i, i + 1, c, depth))
            depth += 1
            i += 1
            continue
        if c in ")]}":
            depth -= 1
            toks.append((i, i + 1, c, depth))
            i += 1
            continue
        if c.isspace():
            i += 1
            continue
        if c == ",":
            toks.append((i, i + 1, c, depth))
            i += 1
            continue
        if c == "`":
            j = code.find("`", i + 1)
            if j < 0:
                j = i
            toks.append((i, j + 1, code[i:j + 1], depth))
            i = j + 1
            continue
        m = IDENT.match(code, i)
        if m:
            toks.append((m.start(), m.end(), m.group(), depth))
            i = m.end()
            continue
        if c in OPCHARS:
            j = i
            while j < n and code[j] in OPCHARS:
                j += 1
            toks.append((i, j, code[i:j], depth))
            i = j
            continue
        i += 1
    return toks


# ---------------------------------------------------------------------------
# signature analysis
# ---------------------------------------------------------------------------

def split_top(text, sep):
    """Split `text` on occurrences of operator token `sep` at bracket depth 0."""
    parts = []
    last = 0
    for s, e, t, d in find_tokens(text):
        if d == 0 and t == sep:
            parts.append(text[last:s])
            last = e
    parts.append(text[last:])
    return parts


def analyse_signature(sig_text):
    """Given the text after `::`, return (n_arrows, result_head, monadish_vars, raw)."""
    text = sig_text
    # drop `forall a b .`
    toks = find_tokens(text)
    if toks and toks[0][2] == "forall":
        for s, e, t, d in toks:
            if d == 0 and t == "." :
                text = text[e:]
                break
    ctx_parts = split_top(text, "=>")
    result_part = ctx_parts[-1]
    context = " ".join(ctx_parts[:-1])

    monadish = set()
    for m in re.finditer(r"\b([A-Z][A-Za-z0-9_']*)\s+([a-z][A-Za-z0-9_']*)", context):
        if m.group(1) in MONADISH:
            monadish.add(m.group(2))

    arrows = split_top(result_part, "->")
    n_arrows = len(arrows) - 1
    result = arrows[-1].strip()
    head_toks = find_tokens(result)
    head = head_toks[0][2] if head_toks else ""
    n_args_applied = 0
    if head_toks:
        depth0 = [t for t in head_toks if t[3] == 0]
        n_args_applied = max(0, len(depth0) - 1)
    return n_arrows, head, n_args_applied, monadish, result


def collect_signatures(lines, code):
    """Map top-level name -> (n_arrows, head, n_applied, monadish, result_text)."""
    sigs = {}
    i = 0
    n = len(lines)
    while i < n:
        c = code[i]
        if not c.strip() or c[0].isspace():
            i += 1
            continue
        # gather the logical declaration block
        j = i + 1
        while j < n and (not code[j].strip() or code[j][0].isspace()):
            j += 1
        block = "\n".join(code[i:j])
        toks = find_tokens(block)
        if toks and toks[0][2] in KEYWORDS:
            i = j
            continue
        # look for a depth-0 `::`
        pos = None
        for s, e, t, d in toks:
            if d == 0 and t == "::":
                pos = (s, e)
                break
            if d == 0 and t in ("=", "|"):
                break
        if pos:
            lhs = block[:pos[0]]
            rhs = block[pos[1]:]
            names = []
            for m in IDENT.finditer(lhs):
                names.append(m.group())
            # operator signatures: (<+>) :: ...
            for m in re.finditer(r"\(\s*([" + re.escape("".join(OPCHARS)) + r"]+)\s*\)", lhs):
                names.append(m.group(1))
            info = analyse_signature(rhs)
            for nm in names:
                sigs[nm] = info
        i = j
    return sigs


# ---------------------------------------------------------------------------
# clause rewriting
# ---------------------------------------------------------------------------

def count_lhs_args(lhs_code):
    """Count pattern groups after the function name, at bracket depth 0."""
    toks = [t for t in find_tokens(lhs_code) if t[3] == 0 or t[2] in "([{"]
    # walk depth-0 groups
    groups = 0
    i = 0
    toks_all = find_tokens(lhs_code)
    while i < len(toks_all):
        s, e, t, d = toks_all[i]
        if d != 0:
            i += 1
            continue
        if t in "([{":
            # skip to matching close at depth 0
            j = i + 1
            while j < len(toks_all):
                if toks_all[j][3] == 0 and toks_all[j][2] in ")]}":
                    break
                j += 1
            groups += 1
            i = j + 1
            continue
        if t in ")]}" or t == ",":
            i += 1
            continue
        if t == "_" or IDENT.fullmatch(t) or t.startswith("`"):
            groups += 1
            i += 1
            continue
        if set(t) <= OPCHARS:
            # strictness / irrefutable prefix attaches to the following group
            if t in ("!", "~"):
                i += 1
                continue
            groups += 1
            i += 1
            continue
        i += 1
    return groups


def clause_name_and_arity(lhs_code):
    """Return (name, arity) for a clause LHS, or (None, None) if not a function binding."""
    toks = find_tokens(lhs_code)
    if not toks:
        return None, None
    s, e, t, d = toks[0]
    if t in KEYWORDS:
        return None, None
    if t in "([{":
        # (<+>) a b = ... / pattern binding — handle the operator-in-parens form
        m = re.match(r"\(\s*([" + re.escape("".join(OPCHARS)) + r"]+)\s*\)", lhs_code.strip())
        if m:
            rest = lhs_code.strip()[m.end():]
            return m.group(1), count_lhs_args(rest)
        return None, None
    if not IDENT.fullmatch(t) or not (t[0].islower() or t[0] == "_"):
        return None, None
    # infix definition?  `a <+> b = ...`  or  `a `foo` b = ...`
    if len(toks) > 1:
        s2, e2, t2, d2 = toks[1]
        if d2 == 0 and t2.startswith("`"):
            return t2.strip("`"), 2
        if d2 == 0 and set(t2) <= OPCHARS and t2 not in ("=", "|", "::", "!", "~", "@"):
            return t2, 2
    rest = lhs_code[e:]
    return t, count_lhs_args(rest)


def pick_combinator(name, arity, sigs):
    info = sigs.get(name)
    if info is None:
        return "t"
    n_arrows, head, n_applied, monadish, result = info
    if "#" in result:
        return None  # unlifted / unboxed — do not touch
    if arity != n_arrows:
        return "t"
    if n_applied < 1:
        return "t"
    if head == "IO":
        return "tio"
    if head in monadish:
        return "tm"
    if head in KNOWN_MONADS:
        return "tm"
    return "t"


def eq_positions(block_code):
    """Find injection points: list of absolute offsets just past a top-level `=`.

    Returns [] if the declaration has no RHS (e.g. a signature or a `data` decl)."""
    toks = find_tokens(block_code)
    # stop at a depth-0 `where`
    limit = len(block_code)
    for s, e, t, d in toks:
        if d == 0 and t == "where":
            limit = s
            break
    toks = [x for x in toks if x[0] < limit]

    guarded = False
    for s, e, t, d in toks:
        if d == 0 and t == "|":
            guarded = True
            break
        if d == 0 and t == "=":
            break

    points = []
    if not guarded:
        for s, e, t, d in toks:
            if d == 0 and t == "=":
                points.append(e)
                break
        return points

    # guarded: one injection per `| ... = ` alternative
    seeking_eq = False
    for s, e, t, d in toks:
        if d != 0:
            continue
        if t == "|":
            seeking_eq = True
            continue
        if t == "=" and seeking_eq:
            points.append(e)
            seeking_eq = False
    return points


LAYOUT_KW = ("do", "mdo", "of", "let", "where", "case")


def needs_reindent(code_line, off):
    """True when inserting text at `off` would shift a layout block whose first
    item is on this same line -- in that case every continuation line of the
    clause has to be shifted by the same amount to keep the layout intact."""
    post = code_line[off:]
    last = None
    for s, e, tk, d in find_tokens(post):
        if tk in LAYOUT_KW:
            last = (s, e)
    if last is None:
        return False
    return post[last[1]:].strip() != ""


def instrument_file(path, module_name, alias, out_lines=None):
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as fh:
        lines = fh.read().split("\n")
    code, _ = strip_code(lines)
    sigs = collect_signatures(lines, code)

    # ---- collect edits as (line_idx, col, text) -------------------------------
    edits = []
    # line index -> (last injection line of its clause scope, scope_end)
    scopes = []
    stats = {"t": 0, "tm": 0, "tio": 0, "skipped": 0, "reindented": 0}

    # line offsets for the joined-block representation
    i = 0
    n = len(lines)
    while i < n:
        c = code[i]
        if not c.strip() or c[0].isspace():
            i += 1
            continue
        j = i + 1
        while j < n and (not code[j].strip() or code[j][0].isspace()):
            j += 1
        block_lines = code[i:j]
        block = "\n".join(block_lines)

        toks = find_tokens(block)
        if not toks or toks[0][2] in KEYWORDS or block.lstrip().startswith("#"):
            i = j
            continue

        pts = eq_positions(block)
        if pts:
            first_eq = pts[0]
            name, arity = clause_name_and_arity(block[:first_eq - 1])
            if name is not None:
                comb = pick_combinator(name, arity, sigs)
                if comb is None:
                    stats["skipped"] += 1
                else:
                    label = "%s.%s" % (module_name, name)
                    placed = []
                    for p in pts:
                        # translate absolute offset in `block` -> (line, col)
                        off = p
                        li = i
                        for bl in block_lines:
                            if off <= len(bl):
                                break
                            off -= len(bl) + 1
                            li += 1
                        # do not inject in front of a negative literal
                        tail = code[li][off:].lstrip()
                        if tail.startswith("-") and not tail.startswith("->"):
                            stats["skipped"] += 1
                            continue
                        edits.append((li, off, ' %s.%s "%s" %s.$' % (alias, comb, label, alias)))
                        placed.append(li)
                        stats[comb] += 1
                    # record re-indent scopes: lines after injection line `li`
                    # up to the next injection line (or end of the clause block)
                    for k, li in enumerate(placed):
                        scope_end = placed[k + 1] if k + 1 < len(placed) else j
                        if needs_reindent(code[li], [o for (l, o, _) in edits
                                                     if l == li][-1]):
                            scopes.append((li, scope_end))
        i = j

    if not edits:
        return None, stats

    # ---- re-indent continuation lines whose layout block got shifted ---------
    by_line = {}
    for li, col, text in edits:
        by_line.setdefault(li, []).append((col, text))

    for li, scope_end in scopes:
        shift = sum(len(text) for _, text in by_line.get(li, []))
        if shift == 0:
            continue
        for k in range(li + 1, min(scope_end, len(lines))):
            if not lines[k].strip() or lines[k].startswith("#"):
                continue
            lines[k] = " " * shift + lines[k]
            stats["reindented"] += 1

    # ---- apply edits, right-to-left per line ---------------------------------
    for li, items in by_line.items():
        for col, text in sorted(items, reverse=True):
            lines[li] = lines[li][:col] + text + lines[li][col:]

    # ---- add the import ------------------------------------------------------
    last_import = None
    for idx, c in enumerate(code):
        if c.startswith("import"):
            last_import = idx
    if last_import is None:
        for idx, c in enumerate(code):
            m = re.search(r"\bwhere\b", c)
            if m and "module" in " ".join(code[: idx + 1]):
                last_import = idx
                break
    if last_import is None:
        last_import = 0
    ins = last_import + 1
    # walk past continuation lines of that import, then past any CPP #else/#endif
    while ins < len(lines) and lines[ins][:1].isspace() and lines[ins].strip():
        ins += 1
    while ins < len(lines) and re.match(r"^#\s*(else|elif|endif)", lines[ins]):
        ins += 1
    lines.insert(ins, "import qualified %s as %s" % (TRACE_MODULE[0], alias))

    return "\n".join(lines), stats


TRACE_MODULE = [None]  # set by main


# ---------------------------------------------------------------------------

def module_of(root, path):
    rel = os.path.relpath(path, root)
    return rel[:-3].replace(os.sep, ".")


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--pkg-dir", required=True)
    ap.add_argument("--src-root", default=".", help="source dir relative to pkg-dir (hs-source-dirs)")
    ap.add_argument("--trace-module", required=True)
    ap.add_argument("--alias", default="ETT__")
    ap.add_argument("--only", default=None, help="file with newline-separated module names to instrument")
    ap.add_argument("--exclude", default="", help="comma-separated module prefixes to skip")
    args = ap.parse_args()

    TRACE_MODULE[0] = args.trace_module
    root = os.path.join(args.pkg_dir, args.src_root)

    only = None
    if args.only:
        with open(args.only) as fh:
            only = {l.strip() for l in fh if l.strip()}

    excludes = [e for e in args.exclude.split(",") if e]

    total = {"t": 0, "tm": 0, "tio": 0, "skipped": 0, "reindented": 0}
    touched = 0
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in sorted(filenames):
            if not fn.endswith(".hs"):
                continue
            path = os.path.join(dirpath, fn)
            mod = module_of(root, path)
            if only is not None and mod not in only:
                continue
            if any(mod.startswith(e) for e in excludes):
                continue
            if mod == args.trace_module:
                continue
            new, stats = instrument_file(path, mod, args.alias)
            for k in total:
                total[k] += stats.get(k, 0)
            if new is not None:
                with open(path, "w", encoding="utf-8", errors="surrogateescape") as fh:
                    fh.write(new)
                touched += 1
    print("  files: %d   tio(in/out/exc): %d   tm(in/out): %d   t(in): %d   skipped: %d   lines reindented: %d"
          % (touched, total["tio"], total["tm"], total["t"], total["skipped"],
             total["reindented"]))


if __name__ == "__main__":
    main()
