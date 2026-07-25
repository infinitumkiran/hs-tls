#!/usr/bin/env python3
"""Assemble forks/euler-tls-traced from pristine hackage sources + call tracing."""

import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "src")
TMPL = os.path.join(HERE, "EulerTrace.hs.tmpl")

# (source dir, fork subdir, package tag, trace module, exclude prefixes, only-list or None)
PKGS = [
    ("tls-1.9.0", "tls", "tls", "Debug.EulerTrace.Tls",
     "Tests,Benchmarks,Setup", None),
    ("crypton-1.0.4", "crypton", "crypton", "Debug.EulerTrace.Crypton",
     "Setup,Tests,tests,benchmarks", "CRYPTON_SUBSET"),
    ("crypton-x509-1.7.7", "crypton-x509", "crypton-x509",
     "Debug.EulerTrace.CryptonX509", "Tests,Setup", None),
    ("crypton-x509-store-1.6.11", "crypton-x509-store", "crypton-x509-store",
     "Debug.EulerTrace.CryptonX509Store", "Tests,Setup", None),
    ("crypton-x509-validation-1.6.14", "crypton-x509-validation",
     "crypton-x509-validation", "Debug.EulerTrace.CryptonX509Validation",
     "Tests,Setup", None),
    # Not in the original list, but forking crypton-x509 forces this dependent to
    # be rebuilt anyway, and it is on the TLS path (it loads the system CA store).
    ("crypton-x509-system-1.6.7", "crypton-x509-system", "crypton-x509-system",
     "Debug.EulerTrace.CryptonX509System", "Tests,Setup", None),
    ("crypton-connection-0.4.5", "crypton-connection", "crypton-connection",
     "Debug.EulerTrace.CryptonConnection", "Setup", None),
    ("http-client-0.7.19", "http-client", "http-client",
     "Debug.EulerTrace.HttpClient",
     "Setup,test-nonet,test,Network.PublicSuffixList", None),
    ("http-client-tls-0.3.6.4", "http-client-tls", "http-client-tls",
     "Debug.EulerTrace.HttpClientTls", "Setup,test", None),
]


def cabal_file(d):
    return [os.path.join(d, f) for f in os.listdir(d) if f.endswith(".cabal")][0]


def add_other_module(path, module):
    """Add `module` to the library stanza's other-modules field."""
    with open(path) as fh:
        lines = fh.read().split("\n")

    # find the library stanza
    lib = None
    for i, l in enumerate(lines):
        if re.match(r"^[Ll]ibrary\s*$", l.rstrip()):
            lib = i
            break
    if lib is None:
        raise SystemExit("no library stanza in %s" % path)
    end = len(lines)
    for i in range(lib + 1, len(lines)):
        if lines[i].strip() and not lines[i][0].isspace():
            end = i
            break

    field = None
    for i in range(lib + 1, end):
        if re.match(r"^\s*[Oo]ther-modules\s*:", lines[i]):
            field = i
            break

    if field is None:
        for i in range(lib + 1, end):
            if re.match(r"^\s*[Ee]xposed-modules\s*:", lines[i]):
                field = i
                break
        if field is None:
            raise SystemExit("no exposed-modules in %s" % path)
        indent = re.match(r"^(\s*)", lines[field]).group(1)
        # skip the exposed-modules item block
        j = field + 1
        base = len(indent)
        while j < end and (not lines[j].strip() or
                           len(lines[j]) - len(lines[j].lstrip()) > base):
            j += 1
        lines.insert(j, "%s[Other-modules-placeholder]" % indent)
        lines[j] = "%sOther-modules:     %s" % (indent, module)
        with open(path, "w") as fh:
            fh.write("\n".join(lines))
        return

    m = re.match(r"^(\s*)([Oo]ther-modules\s*:)(\s*)(\S.*)?$", lines[field])
    indent, name, gap, first = m.group(1), m.group(2), m.group(3), m.group(4)
    if first:
        col = len(indent) + len(name) + len(gap)
        lines.insert(field + 1, " " * col + module)
    else:
        # items start on the following line; copy its indentation
        nxt = field + 1
        while nxt < end and not lines[nxt].strip():
            nxt += 1
        ind2 = re.match(r"^(\s*)", lines[nxt]).group(1) if nxt < end else indent + "    "
        lines.insert(field + 1, ind2 + module)

    with open(path, "w") as fh:
        fh.write("\n".join(lines))


def drop_werror(path):
    with open(path) as fh:
        txt = fh.read()
    new = txt.replace("-Werror", "")
    if new != txt:
        with open(path, "w") as fh:
            fh.write(new)


def crypton_subset(pkgdir):
    """Modules of crypton that the TLS path actually imports."""
    wanted = subprocess.run(
        ["grep", "-rhoE", r"\bCrypto\.[A-Za-z0-9_.]+"] + TLS_PATH_DIRS,
        capture_output=True, text=True).stdout.split()
    mods = set()
    for w in sorted(set(wanted)):
        p = os.path.join(pkgdir, w.replace(".", os.sep) + ".hs")
        if os.path.exists(p):
            mods.add(w)
    return sorted(mods)


TLS_PATH_DIRS = []


def main():
    dest_root = sys.argv[1]
    global TLS_PATH_DIRS
    TLS_PATH_DIRS = [
        os.path.join(SRC, "tls-1.9.0", "Network"),
        os.path.join(SRC, "crypton-x509-1.7.7"),
        os.path.join(SRC, "crypton-x509-store-1.6.11"),
        os.path.join(SRC, "crypton-x509-validation-1.6.14"),
        os.path.join(SRC, "crypton-connection-0.4.5"),
        os.path.join(SRC, "http-client-tls-0.3.6.4"),
    ]

    with open(TMPL) as fh:
        tmpl = fh.read()

    os.makedirs(dest_root, exist_ok=True)

    for srcdir, sub, tag, mod, excl, only in PKGS:
        dest = os.path.join(dest_root, sub)
        if os.path.exists(dest):
            shutil.rmtree(dest)
        shutil.copytree(os.path.join(SRC, srcdir), dest)
        print("== %s  (from %s)" % (sub, srcdir))

        # 1. drop in the tracer
        modpath = os.path.join(dest, *mod.split(".")) + ".hs"
        os.makedirs(os.path.dirname(modpath), exist_ok=True)
        with open(modpath, "w") as fh:
            fh.write(tmpl.replace("@MODULE@", mod).replace("@PKGTAG@", tag))

        # 2. register it in the .cabal
        cf = cabal_file(dest)
        add_other_module(cf, mod)
        drop_werror(cf)

        # 3. rewrite every top-level function
        onlyfile = None
        if only == "CRYPTON_SUBSET":
            mods = crypton_subset(dest)
            onlyfile = os.path.join(HERE, "crypton-subset.txt")
            with open(onlyfile, "w") as fh:
                fh.write("\n".join(mods) + "\n")
            print("   crypton subset: %d modules" % len(mods))

        cmd = [sys.executable, os.path.join(HERE, "instrument.py"),
               "--pkg-dir", dest, "--trace-module", mod, "--exclude", excl]
        if onlyfile:
            cmd += ["--only", onlyfile]
        subprocess.run(cmd, check=True)


if __name__ == "__main__":
    main()
