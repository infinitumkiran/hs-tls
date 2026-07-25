#!/usr/bin/env python3
"""Read an EULER_TLS_TRACE log and say which function broke.

    ett-blame.py trace.log

For every thread, replays the entry/exit lines and reports the frames that were
entered and never left -- innermost first. That innermost frame is the function
the request died in. Also lists the exception frames ('!') in propagation order,
and can diff two traces to find where a working and a failing run diverge:

    ett-blame.py --diff good.log bad.log
"""

import argparse
import re
import sys

LINE = re.compile(
    r"^ETT (?P<seq>\d+) (?P<pkg>\S+) (?P<tid>ThreadId \d+) +(?P<dir>[><!:]) (?P<rest>.*)$"
)


def parse(path):
    events = []
    with open(path, errors="replace") as fh:
        for raw in fh:
            m = LINE.match(raw.rstrip("\n"))
            if not m:
                continue
            rest = m.group("rest")
            label, _, exc = rest.partition("   !! ")
            events.append({
                "seq": int(m.group("seq")),
                "pkg": m.group("pkg"),
                "tid": m.group("tid"),
                "dir": m.group("dir"),
                "label": label.strip(),
                "exc": exc.strip(),
            })
    return events


def replay(events, stop_at=None):
    """Per thread, the open stack after replaying events[:stop_at]."""
    stacks = {}
    for e in events[:stop_at]:
        if e["dir"] == ">":
            stacks.setdefault(e["tid"], []).append(e)
        elif e["dir"] in "<!":
            st = stacks.setdefault(e["tid"], [])
            # pop back to the matching label if we can find it
            for i in range(len(st) - 1, -1, -1):
                if st[i]["label"] == e["label"]:
                    del st[i:]
                    break
            else:
                if st:
                    st.pop()
    return stacks


def at_first_exception(events):
    """The open stack, and the entry-only frames, at the moment of the first '!'.

    Every frame is eventually unwound by the exception, so the state at the end
    of the trace is empty and useless; the state at the first '!' is the answer.
    """
    idx = next((i for i, e in enumerate(events) if e["dir"] == "!"), None)
    if idx is None:
        return None, None, None
    first = events[idx]
    stack = replay(events, idx).get(first["tid"], [])
    # entry-only ('t') frames cannot be paired, so show the recent ones on this
    # thread as extra candidates -- the innermost is often the actual thrower
    tail = [e for e in events[max(0, idx - 12):idx]
            if e["dir"] == ":" and e["tid"] == first["tid"]]
    return first, stack, tail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logs", nargs="+")
    ap.add_argument("--diff", action="store_true",
                    help="compare two traces and print the first divergence")
    args = ap.parse_args()

    if args.diff:
        if len(args.logs) != 2:
            sys.exit("--diff needs exactly two logs")
        a, b = (parse(p) for p in args.logs)
        for i, (x, y) in enumerate(zip(a, b)):
            if (x["pkg"], x["dir"], x["label"]) != (y["pkg"], y["dir"], y["label"]):
                print("traces diverge at event %d\n  %s: %s %s %s\n  %s: %s %s %s" % (
                    i, args.logs[0], x["pkg"], x["dir"], x["label"],
                    args.logs[1], y["pkg"], y["dir"], y["label"]))
                return
        print("no divergence in the common prefix (%d events); "
              "lengths %d vs %d" % (min(len(a), len(b)), len(a), len(b)))
        return

    events = parse(args.logs[0])
    if not events:
        sys.exit("no ETT lines found -- was EULER_TLS_TRACE set?")
    print("%d trace events" % len(events))

    first, stack, tail = at_first_exception(events)

    if first is None:
        print("\nno exception frames -- nothing broke in an instrumented "
              "IO function.")
        open_now = {t: s for t, s in replay(events).items() if s}
        if open_now:
            print("\nstill-open frames at end of trace (innermost first):")
            for tid, st in open_now.items():
                print("  %s:" % tid)
                for e in reversed(st):
                    print("    %-24s %s   (seq %d)"
                          % (e["pkg"], e["label"], e["seq"]))
        return

    print("\n>>> BROKE IN: %s   (%s, seq %d)"
          % (stack[-1]["label"] if stack else first["label"],
             stack[-1]["pkg"] if stack else first["pkg"],
             stack[-1]["seq"] if stack else first["seq"]))
    if first["exc"]:
        print("    %s" % first["exc"].replace("\\n", " ")[:200])

    if tail:
        print("\n    entry-only frames just before it (any of these may be the\n"
              "    actual thrower -- pure functions have no exit line):")
        for e in tail[-6:]:
            print("      %-24s %s" % (e["pkg"], e["label"]))

    if stack:
        print("\nopen frames at the exception (innermost first):")
        for e in reversed(stack):
            print("  %-24s %s   (seq %d)" % (e["pkg"], e["label"], e["seq"]))

    excs = [e for e in events if e["dir"] == "!"]
    print("\nexception propagated out through:")
    for e in excs:
        print("  %-24s %s" % (e["pkg"], e["label"]))


if __name__ == "__main__":
    main()
