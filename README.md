# 🧐 monocle

`monocle` is a static-analysis tool built on
[capstone](https://www.capstone-engine.org/) and
[pyelftools](https://github.com/eliben/pyelftools) for analyzing **stripped**
c/c++ shared objects, such as the native libraries in an android apk's
`lib/arm64-v8a/`. it is intended for finding memory-corruption and
protocol-parsing bugs from the command line or a short python script. Significantly less token hungry way of analysing large packaged libraries (or libs injected at runtime)

the primary target is **aarch64 / arm64**. x86-64 and 32-bit arm binaries load and disassemble, but literal-pool cross-referencing and function-boundary recovery are tuned for arm64.

## what it does

stripped binaries have no symbols, so navigation works through **strings**.
compilers leave behind log/assert/error messages with source paths and field
names that identify what a function does. `monocle` supports this workflow:

1. `strings -g` / `str` — find the error string for the parser of interest.
2. `xref` — jump from that string to the code that references it.
3. `ctx` — disassemble the enclosing function, with `bl` targets resolved to
   imported names (`memcpy`, `operator new`, …) and string loads inlined.
4. `hunt` — or work in the other direction: list every dangerous call site
   and triage.

## install

```sh
pip install -e .          # from a clone
# or just: pip install capstone pyelftools  and run  python -m monocle.cli
```

## cli

```text
monocle info     <lib>                    sections, arch, import + dangerous-import summary
monocle imports  <lib> [-g pattern]       resolved plt imports (filtered)
monocle strings  <lib> [-g pattern]       rodata strings (filtered)
monocle str      <lib> <substr>           locate string(s) + their code xrefs
monocle xref     <lib> <substr|0xaddr>    xrefs to a string substring or an address
monocle fn       <lib> <0xstart> <0xend>  disassemble a range (annotated)
monocle ctx      <lib> <0xaddr>           disassemble the enclosing function of addr
monocle callers  <lib> <0xaddr>           call sites targeting addr (+ enclosing fn)
monocle hunt     <lib>                     dangerous-call (memcpy/strcpy/…) triage
```

### example session

```sh
# what does this lib import that's worth worrying about?
monocle info libpb_datax_jni.so

# find the parser behind an error message, then read it
monocle xref libpb_datax_jni.so "Invalid payload size in header"
monocle ctx  libpb_datax_jni.so 0x2de54

# go the other way: every memcpy/memmove/strcpy call site
monocle hunt libpb_datax_jni.so
```

## as a library

```python
from monocle import Binary

b = Binary("libpb_datax_jni.so")
for addr, s in b.find_str("Kwaltz header size"):
    for ref in b.xrefs_to_addr(addr):
        start, end = b.enclosing(ref)
        print("\n".join(b.disasm(start, end)))
```

`Binary` exposes: `read`, `imports`, `dangerous_imports`, `find_str`,
`xrefs_to_addr`, `callers`, `enclosing`, `disasm`, `hunt`, plus `strings`,
`plt`, and `sections` maps.

## gotchas

- function-boundary recovery is a heuristic (last terminator → next `ret`).
  if a function looks truncated, widen it with `fn start end`.
- xref recovery models `adrp`+`add`/`ldr` literal pools — it won't catch values
  built across basic blocks or through registers it can't track.
- obviously doesn't replace a disassembler, just useful for me

## license

mit.
