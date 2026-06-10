"""monocle.cli — command-line front end.

  monocle info     <lib>                  sections, arch, import + dangerous-import summary
  monocle imports  <lib> [-g PATTERN]     list resolved PLT imports (optionally filtered)
  monocle strings  <lib> [-g PATTERN]     list rodata strings (optionally filtered)
  monocle str      <lib> <substr>         locate string(s) + their code xrefs
  monocle xref     <lib> <substr|0xADDR>  xrefs to a string substring or an address
  monocle fn       <lib> <0xSTART> <0xEND>  disassemble a range (annotated)
  monocle ctx      <lib> <0xADDR>         disassemble the enclosing function of ADDR
  monocle callers  <lib> <0xADDR>         call sites targeting ADDR (with enclosing fn)
  monocle hunt     <lib>                  dangerous-call (memcpy/strcpy/...) triage
"""
import argparse
import sys
from .core import Binary


def _int(x):
    return int(x, 16) if x.lower().startswith("0x") else int(x, 0)


def cmd_info(b, _a):
    print(f"path : {b.path}")
    print(f"arch : {b.arch}")
    print(f"sections: {[(hex(a), n) for a, _, _, n in b.sections]}")
    print(f"imports resolved: {len(b.plt)}   strings: {len(b.strings)}")
    dang = b.dangerous_imports()
    print(f"dangerous imports ({len(dang)}):")
    for d in dang:
        print(f"  {d}")


def cmd_imports(b, a):
    for name in b.imports():
        if not a.grep or a.grep.lower() in name.lower():
            print(name)


def cmd_strings(b, a):
    for addr in sorted(b.strings):
        s = b.strings[addr]
        if not a.grep or a.grep.lower() in s.lower():
            print(f"{addr:#010x}  {s!r}")


def cmd_str(b, a):
    for addr, s in b.find_str(a.needle):
        xr = b.xrefs_to_addr(addr)
        print(f"{addr:#x}  {s!r}  xrefs={[hex(x) for x in xr]}")


def cmd_xref(b, a):
    if a.target.lower().startswith("0x"):
        addr = _int(a.target)
        for x in b.xrefs_to_addr(addr):
            fs, fe = b.enclosing(x)
            print(f"ref@{x:#x}  fn={fs:#x}-{fe:#x}")
    else:
        for addr, s in b.find_str(a.target):
            for x in b.xrefs_to_addr(addr):
                fs, fe = b.enclosing(x)
                print(f"str {addr:#x} {s!r}  ref@{x:#x}  fn={fs:#x}-{fe:#x}")


def cmd_fn(b, a):
    for line in b.disasm(_int(a.start), _int(a.end)):
        print(line)


def cmd_ctx(b, a):
    addr = _int(a.addr)
    fs, fe = b.enclosing(addr)
    print(f"; enclosing fn {fs:#x} - {fe:#x}  (target {addr:#x})")
    for line in b.disasm(fs, fe):
        print(line)


def cmd_callers(b, a):
    addr = _int(a.addr)
    for caddr, mn in b.callers(addr):
        fs, fe = b.enclosing(caddr)
        print(f"{caddr:#x} ({mn}) in fn {fs:#x}-{fe:#x}")


def cmd_hunt(b, a):
    hits = b.hunt()
    print(f"; {len(hits)} dangerous call site(s) in {b.path}")
    for addr, name in hits:
        fs, _fe = b.enclosing(addr)
        short = name if len(name) < 60 else name[:57] + "..."
        print(f"{addr:#x}  -> {short:<60}  fn={fs:#x}")


COMMANDS = {
    "info": cmd_info, "imports": cmd_imports, "strings": cmd_strings,
    "str": cmd_str, "xref": cmd_xref, "fn": cmd_fn, "ctx": cmd_ctx,
    "callers": cmd_callers, "hunt": cmd_hunt,
}


def build_parser():
    p = argparse.ArgumentParser(prog="monocle", description="a monocle for stripped binaries")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, *args, grep=False):
        sp = sub.add_parser(name)
        sp.add_argument("lib")
        for arg in args:
            sp.add_argument(arg)
        if grep:
            sp.add_argument("-g", "--grep", default=None)
        return sp

    add("info")
    add("imports", grep=True)
    add("strings", grep=True)
    add("str", "needle")
    add("xref", "target")
    add("fn", "start", "end")
    add("ctx", "addr")
    add("callers", "addr")
    add("hunt")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        b = Binary(args.lib)
    except FileNotFoundError:
        print(f"monocle: no such file: {args.lib}", file=sys.stderr)
        return 2
    COMMANDS[args.cmd](b, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
