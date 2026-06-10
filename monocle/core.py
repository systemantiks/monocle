"""monocle.core — static-analysis primitives for stripped ELF shared objects.

A thin, scriptable layer over capstone + pyelftools aimed at protocol-parser bug
hunting in stripped C/C++ binaries: string<->code cross-referencing, PLT/import
name resolution, function-boundary recovery, and dangerous-call triage.

Primary target is AArch64 (ARM64) — the adrp/add/ldr literal-pool xref recovery and
prologue-based function boundary heuristics are arm64-specific. x86-64 and 32-bit ARM
load and disassemble, but xref/enclosing/callers degrade gracefully.
"""
from __future__ import annotations
import bisect
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from capstone import (
    Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_ARCH_ARM,
    CS_MODE_LITTLE_ENDIAN, CS_MODE_64, CS_MODE_ARM, CS_OP_IMM,
)

# functions whose call sites are worth a second look when bug hunting
DANGEROUS = (
    "memcpy", "memmove", "mempcpy", "strcpy", "stpcpy", "strcat", "strncpy",
    "strncat", "sprintf", "vsprintf", "alloca", "gets", "realloc", "malloc",
    "operator new", "__memcpy_chk", "__memmove_chk", "resize", "reserve",
    "wrapBytes", "getDirectAddress", "getDirectCapacity",
)

_STRING_SECTIONS = (".rodata", ".rodata.str1.1", ".data.rel.ro", ".data")


class Binary:
    def __init__(self, path: str):
        self.path = path
        self.f = open(path, "rb")
        self.elf = ELFFile(self.f)
        self.arch, self.md = self._make_disassembler()
        self.md.detail = True
        self._load_sections()
        self._load_imports()
        self._index_strings()

    # ---- setup -----------------------------------------------------------
    def _make_disassembler(self):
        m = self.elf["e_machine"]
        if m == "EM_AARCH64":
            return "aarch64", Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        if m == "EM_X86_64":
            return "x86_64", Cs(CS_ARCH_X86, CS_MODE_64)
        if m == "EM_ARM":
            return "arm", Cs(CS_ARCH_ARM, CS_MODE_ARM)
        # default to arm64 — most Android native libs
        return "aarch64", Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    def _load_sections(self):
        self.sections = []          # (start, end, data, name)
        self.text = None            # (start, end, data)
        for s in self.elf.iter_sections():
            addr, size = s["sh_addr"], s["sh_size"]
            if addr == 0 or s["sh_type"] == "SHT_NOBITS":
                continue
            data = s.data()
            self.sections.append((addr, addr + size, data, s.name))
            if s.name == ".text":
                self.text = (addr, addr + size, data)
        self.sections.sort()
        self._sec_starts = [a for a, _, _, _ in self.sections]

    def read(self, addr: int, n: int):
        i = bisect.bisect_right(self._sec_starts, addr) - 1
        if i < 0:
            return None
        a, b, data, _ = self.sections[i]
        if addr < a or addr + n > b:
            return None
        return data[addr - a: addr - a + n]

    def _load_imports(self):
        """Map PLT stub address -> imported symbol name."""
        self.plt = {}               # stub addr -> name
        self.got_sym = {}           # GOT slot addr -> name
        symtab = self.elf.get_section_by_name(".dynsym")
        for relname in (".rela.plt", ".rela.dyn"):
            rel = self.elf.get_section_by_name(relname)
            if not isinstance(rel, RelocationSection):
                continue
            for r in rel.iter_relocations():
                idx = r["r_info_sym"]
                if symtab and idx < symtab.num_symbols():
                    name = symtab.get_symbol(idx).name
                    if name:
                        self.got_sym[r["r_offset"]] = name
        plt = self.elf.get_section_by_name(".plt")
        if plt and self.arch == "aarch64":
            base, data = plt["sh_addr"], plt.data()
            for off in range(0, len(data), 16):
                self._resolve_plt_stub(base + off, data[off: off + 16])

    def _resolve_plt_stub(self, stub_addr, chunk):
        adrp = None
        for ins in self.md.disasm(chunk, stub_addr):
            if ins.mnemonic == "adrp":
                adrp = ins.operands[1].imm
            elif ins.mnemonic == "ldr" and adrp is not None:
                for op in ins.operands:
                    if op.type == CS_OP_IMM:
                        got = adrp + op.imm
                        if got in self.got_sym:
                            self.plt[stub_addr] = self.got_sym[got]
                        return
            elif ins.mnemonic == "add" and adrp is not None:
                got = adrp + ins.operands[2].imm
                if got in self.got_sym:
                    self.plt[stub_addr] = self.got_sym[got]

    def _index_strings(self):
        self.strings = {}           # addr -> str
        for a, _b, data, name in self.sections:
            if name not in _STRING_SECTIONS:
                continue
            i = 0
            while i < len(data):
                if 32 <= data[i] < 127:
                    j = i
                    while j < len(data) and 32 <= data[j] < 127:
                        j += 1
                    if j - i >= 4 and j < len(data) and data[j] == 0:
                        self.strings[a + i] = data[i:j].decode("ascii", "replace")
                    i = j
                else:
                    i += 1

    # ---- queries ---------------------------------------------------------
    def imports(self):
        return sorted(set(self.plt.values()))

    def dangerous_imports(self):
        return [x for x in self.imports() if any(k in x for k in DANGEROUS)]

    def find_str(self, needle: str):
        return [(a, s) for a, s in self.strings.items() if needle in s]

    def xrefs_to_addr(self, target: int):
        """Find .text sites whose adrp(+add/ldr) literal load resolves to `target`."""
        if not self.text or self.arch != "aarch64":
            return []
        ta, _tb, data = self.text
        res, regpage = [], {}
        for ins in self.md.disasm(data, ta):
            if ins.mnemonic == "adrp":
                regpage[ins.operands[0].reg] = ins.operands[1].imm
            elif ins.mnemonic == "add" and len(ins.operands) == 3 and ins.operands[2].type == CS_OP_IMM:
                rn = ins.operands[1].reg
                if regpage.get(rn) is not None:
                    if regpage[rn] + ins.operands[2].imm == target:
                        res.append(ins.address)
                    rd = ins.operands[0].reg
                    if rd != rn:
                        regpage.pop(rd, None)
            elif ins.mnemonic == "ldr" and len(ins.operands) == 2 and ins.operands[1].type != CS_OP_IMM:
                m = ins.operands[1].mem
                if m.base in regpage and regpage.get(m.base) is not None and m.index == 0:
                    if regpage[m.base] + m.disp == target:
                        res.append(ins.address)
        return res

    def callers(self, target: int):
        """Find bl/b/call sites targeting `target`."""
        if not self.text:
            return []
        ta, _tb, data = self.text
        res = []
        branch = ("bl", "b", "call") if self.arch != "x86_64" else ("call", "jmp")
        for ins in self.md.disasm(data, ta):
            if ins.mnemonic in branch and ins.operands and ins.operands[0].type == CS_OP_IMM:
                if ins.operands[0].imm == target:
                    res.append((ins.address, ins.mnemonic))
        return res

    def enclosing(self, addr: int):
        """Heuristic function bounds: from the last terminator before `addr` to the
        first ret/brk at-or-after it."""
        ta, tb, data = self.text
        lo = max(ta, addr - 0x6000)
        window = data[lo - ta: min(len(data), addr - ta + 0x4000)]
        instrs = list(self.md.disasm(window, lo))
        last_term = lo
        for ins in instrs:
            if ins.address >= addr:
                break
            far_b = (ins.mnemonic == "b" and ins.operands and ins.operands[0].type == CS_OP_IMM
                     and not (lo <= ins.operands[0].imm <= tb))
            if ins.mnemonic in ("ret", "brk") or far_b:
                last_term = ins.address + 4
        end = addr + 4
        for ins in instrs:
            if ins.address < addr:
                continue
            end = ins.address + 4
            if ins.mnemonic in ("ret", "brk"):
                break
        return last_term, end

    # ---- rendering -------------------------------------------------------
    def annotate_call(self, ins):
        if ins.operands and ins.operands[0].type == CS_OP_IMM:
            t = ins.operands[0].imm
            if t in self.plt:
                return f"    ; -> {self.plt[t]}"
            if t in self.strings:
                return f"    ; '{self.strings[t]}'"
        return ""

    def disasm(self, start: int, end: int, resolve=True):
        out = []
        data = self.read(start, end - start)
        if data is None:
            return out
        regpage = {}
        call_mn = ("bl", "b", "call", "jmp")
        for ins in self.md.disasm(data, start):
            line = f"{ins.address:#010x}  {ins.mnemonic:<8} {ins.op_str}"
            if resolve and self.arch == "aarch64":
                if ins.mnemonic == "adrp":
                    regpage[ins.operands[0].reg] = ins.operands[1].imm
                elif ins.mnemonic == "add" and len(ins.operands) == 3 and ins.operands[2].type == CS_OP_IMM:
                    rn = ins.operands[1].reg
                    if regpage.get(rn) is not None:
                        val = regpage[rn] + ins.operands[2].imm
                        if val in self.strings:
                            line += f"    ; '{self.strings[val]}'"
                        regpage[ins.operands[0].reg] = None
            if resolve and ins.mnemonic in call_mn:
                line += self.annotate_call(ins)
            out.append(line)
        return out

    def hunt(self):
        """Find call sites to DANGEROUS imports; return [(addr, name, fn_start)]."""
        if not self.text:
            return []
        targets = {stub: name for stub, name in self.plt.items()
                   if any(k in name for k in DANGEROUS)}
        ta, _tb, data = self.text
        hits = []
        branch = ("bl", "b", "call")
        for ins in self.md.disasm(data, ta):
            if ins.mnemonic in branch and ins.operands and ins.operands[0].type == CS_OP_IMM:
                t = ins.operands[0].imm
                if t in targets:
                    hits.append((ins.address, targets[t]))
        return hits
