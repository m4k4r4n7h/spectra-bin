import os
import math
import struct
import hashlib
from collections import Counter
from .bridge import NativeEngineBridge

try:
    from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_32, CS_MODE_64, CS_MODE_ARM
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


class BinaryReverseEngine:
    def __init__(self, filepath):
        self.filepath = filepath
        with open(filepath, "rb") as f:
            self.raw = f.read()
        self.size = len(self.raw)
        self.sha256 = hashlib.sha256(self.raw).hexdigest()
        self.bridge = NativeEngineBridge()
        self.format_type = "Raw Binary Stream"
        self.arch_name = "Unknown"
        self.bits = 64
        self.endian = "<"
        self.entry_vaddr = 0
        self.entry_offset = 0
        self.is_pie = False
        self.has_rwx = False
        self.interpreter = None
        self.segments = []
        self.sections = []
        self.disassembly = []

    def calculate_entropy(self, data_slice):
        if not data_slice:
            return 0.0
        length = len(data_slice)
        counts = Counter(data_slice)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    def extract_strings(self, min_len=4):
        results = []
        current = bytearray()
        for b in self.raw:
            if 32 <= b <= 126:
                current.append(b)
            else:
                if len(current) >= min_len:
                    results.append(current.decode("ascii", errors="ignore"))
                current.clear()
        if len(current) >= min_len:
            results.append(current.decode("ascii", errors="ignore"))
        return results

    def classify_opcode(self, mnemonic, operands):
        if mnemonic in ("syscall", "svc", "int"):
            return "Kernel System Call"
        if mnemonic in ("call", "bl", "blr"):
            return f"Subroutine Call ({operands})"
        if mnemonic in ("ret", "retq"):
            return "Stack Frame Return"
        if mnemonic in ("cpuid", "rdtsc"):
            return "Hardware Probe"
        if mnemonic.startswith("j") or mnemonic.startswith("b."):
            return "Control Flow Branch"
        if mnemonic in ("push", "pop"):
            return "Stack Manipulation"
        return "Register / Memory Op"

    def parse_container(self):
        native_info = self.bridge.probe_file(self.filepath)
        if native_info:
            self.entry_vaddr = native_info["entry_point"]
            self.entry_offset = native_info["entry_file_offset"]
            self.is_pie = native_info["is_pie"]
            self.has_rwx = native_info["has_rwx_segment"]
            if native_info["interpreter"]:
                self.interpreter = native_info["interpreter"]

        if self.size >= 4 and self.raw[:4] == b"\x7fELF":
            self.parse_elf()
        elif self.size >= 2 and self.raw[:2] == b"MZ":
            self.parse_pe()
        else:
            self.format_type = "Raw Binary Stream"
            self.arch_name = "x86_64"

    def parse_elf(self):
        self.format_type = "ELF (Executable and Linkable Format)"
        self.bits = 64 if self.raw[4] == 2 else 32
        self.endian = "<" if self.raw[5] == 1 else ">"

        if self.bits == 64 and self.size >= 64:
            ehdr = struct.unpack(self.endian + "HHIQQQIHHHHHH", self.raw[16:64])
            e_type, e_machine, _, e_entry, e_phoff, e_shoff, _, _, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = ehdr
            self.entry_vaddr = e_entry
            self.is_pie = (e_type == 3)

            arch_map = {62: "x86_64", 183: "AArch64", 3: "x86", 40: "ARM", 243: "RISC-V"}
            self.arch_name = arch_map.get(e_machine, f"Arch-{e_machine}")
            pt_types = {1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP", 6: "PT_PHDR", 1685382481: "PT_GNU_STACK"}

            for i in range(e_phnum):
                off = e_phoff + i * e_phentsize
                if off + 56 > self.size:
                    break
                p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack(
                    self.endian + "IIQQQQQQ", self.raw[off:off + 56]
                )
                perms = (
                    ("R" if p_flags & 4 else "-") +
                    ("W" if p_flags & 2 else "-") +
                    ("X" if p_flags & 1 else "-")
                )
                if (p_flags & 2) and (p_flags & 1):
                    self.has_rwx = True
                self.segments.append({
                    "type": pt_types.get(p_type, f"0x{p_type:x}"),
                    "offset": p_offset,
                    "vaddr": p_vaddr,
                    "filesz": p_filesz,
                    "memsz": p_memsz,
                    "perms": perms,
                })
                if p_type == 3 and p_offset + p_filesz <= self.size:
                    self.interpreter = self.raw[p_offset:p_offset + p_filesz].rstrip(b"\x00").decode("ascii", errors="ignore")
                if p_type == 1 and p_vaddr <= self.entry_vaddr < (p_vaddr + p_memsz):
                    self.entry_offset = (self.entry_vaddr - p_vaddr) + p_offset

            strtab_offset = 0
            strtab_size = 0
            if e_shstrndx < e_shnum:
                shstr_off = e_shoff + e_shstrndx * e_shentsize
                if shstr_off + 64 <= self.size:
                    shstr_fields = struct.unpack(self.endian + "IIQQQQIIQQ", self.raw[shstr_off:shstr_off + 64])
                    strtab_offset = shstr_fields[4]
                    strtab_size = shstr_fields[5]

            for i in range(e_shnum):
                off = e_shoff + i * e_shentsize
                if off + 64 > self.size:
                    break
                sh_name_idx, _, _, sh_addr, sh_offset, sh_size, _, _, _, _ = struct.unpack(
                    self.endian + "IIQQQQIIQQ", self.raw[off:off + 64]
                )
                sec_name = f"sec_{i}"
                if strtab_offset and (strtab_offset + sh_name_idx) < (strtab_offset + strtab_size):
                    end_idx = self.raw.find(b"\x00", strtab_offset + sh_name_idx)
                    if end_idx != -1:
                        sec_name = self.raw[strtab_offset + sh_name_idx:end_idx].decode("ascii", errors="ignore")
                sec_bytes = self.raw[sh_offset:sh_offset + sh_size] if sh_offset + sh_size <= self.size else b""
                self.sections.append({
                    "name": sec_name,
                    "vaddr": sh_addr,
                    "offset": sh_offset,
                    "size": sh_size,
                    "entropy": self.calculate_entropy(sec_bytes),
                })

    def parse_pe(self):
        self.format_type = "PE (Portable Executable)"
        if self.size < 0x40:
            return
        pe_offset = struct.unpack("<I", self.raw[0x3C:0x40])[0]
        if pe_offset + 24 > self.size or self.raw[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return
        machine, num_sections, _, _, _, opt_hdr_size, _ = struct.unpack("<HHIIIHH", self.raw[pe_offset + 4:pe_offset + 24])
        arch_map = {0x8664: "x86_64", 0x014C: "x86", 0xAA64: "AArch64"}
        self.arch_name = arch_map.get(machine, f"0x{machine:x}")

        opt_offset = pe_offset + 24
        if opt_offset + 28 <= self.size:
            magic = struct.unpack("<H", self.raw[opt_offset:opt_offset + 2])[0]
            self.bits = 64 if magic == 0x20B else 32
            entry_rva = struct.unpack("<I", self.raw[opt_offset + 16:opt_offset + 20])[0]
            image_base = struct.unpack(
                "<Q" if self.bits == 64 else "<I",
                self.raw[opt_offset + 24:opt_offset + (32 if self.bits == 64 else 28)],
            )[0]
            self.entry_vaddr = image_base + entry_rva

            sec_table_off = opt_offset + opt_hdr_size
            for i in range(num_sections):
                s_off = sec_table_off + i * 40
                if s_off + 40 > self.size:
                    break
                name_raw, virt_size, virt_addr, raw_size, raw_ptr, _, _, _, _, _ = struct.unpack(
                    "<8sIIIIIIHHI", self.raw[s_off:s_off + 40]
                )
                sec_name = name_raw.rstrip(b"\x00").decode("ascii", errors="ignore")
                sec_bytes = self.raw[raw_ptr:raw_ptr + raw_size] if raw_ptr + raw_size <= self.size else b""
                self.sections.append({
                    "name": sec_name,
                    "vaddr": image_base + virt_addr,
                    "offset": raw_ptr,
                    "size": raw_size,
                    "entropy": self.calculate_entropy(sec_bytes),
                })
                if virt_addr <= entry_rva < (virt_addr + max(virt_size, raw_size)):
                    self.entry_offset = (entry_rva - virt_addr) + raw_ptr

    def disassemble_entry_point(self, limit=25):
        native_disasm = self.bridge.disassemble_entry(self.filepath, limit)
        if native_disasm:
            self.disassembly = native_disasm
            return

        if self.entry_offset >= self.size:
            return
        code_slice = self.raw[self.entry_offset:self.entry_offset + 256]
        if HAS_CAPSTONE:
            arch = CS_ARCH_ARM64 if self.arch_name == "AArch64" else CS_ARCH_X86
            mode = CS_MODE_ARM if self.arch_name == "AArch64" else (CS_MODE_64 if self.bits == 64 else CS_MODE_32)
            md = Cs(arch, mode)
            for idx, insn in enumerate(md.disasm(code_slice, self.entry_vaddr)):
                if idx >= limit:
                    break
                hex_bytes = " ".join(f"{b:02x}" for b in insn.bytes)
                self.disassembly.append({
                    "address": insn.address,
                    "hex_bytes": hex_bytes,
                    "mnemonic": insn.mnemonic,
                    "operands": insn.op_str,
                    "semantic_group": self.classify_opcode(insn.mnemonic, insn.op_str),
                })
        else:
            for i in range(0, min(len(code_slice), 64), 8):
                chunk = code_slice[i:i + 8]
                hex_bytes = " ".join(f"{b:02x}" for b in chunk)
                self.disassembly.append({
                    "address": self.entry_vaddr + i,
                    "hex_bytes": hex_bytes,
                    "mnemonic": ".byte",
                    "operands": f"block_{i // 8}",
                    "semantic_group": "Raw Byte Sequence",
                })

    def infer_system_execution_and_behavior(self):
        strings = self.extract_strings(4)
        behavior_catalog = {
            "Process & Execution Control": ["execve", "fork", "vfork", "posix_spawn", "CreateProcess", "system", "popen"],
            "Network Communication": ["socket", "connect", "bind", "listen", "accept", "send", "recv", "WSAStartup", "getaddrinfo"],
            "Memory Allocation & Protection": ["mmap", "mprotect", "VirtualAlloc", "VirtualProtect", "dlopen", "LoadLibrary"],
            "Filesystem Operations": ["open", "openat", "fopen", "read", "write", "unlink", "rename", "CreateFile", "DeleteFile"],
            "Cryptography & Entropy": ["EVP_EncryptInit", "AES_encrypt", "CryptAcquireContext", "BCryptGenRandom", "getrandom"],
            "Process Inspection & Debugging": ["ptrace", "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "prctl"],
        }
        matched = {}
        for category, indicators in behavior_catalog.items():
            hits = [sym for sym in indicators if any(sym == s or s.startswith(sym + "@") for s in strings)]
            if hits:
                matched[category] = hits
        return matched

    def render_report(self):
        self.parse_container()
        self.disassemble_entry_point()
        behaviors = self.infer_system_execution_and_behavior()
        overall_entropy = self.calculate_entropy(self.raw)
        engine_mode = "C/C++ Native Shared Library + Python" if self.bridge.is_available() else "Pure Python Fallback"

        print("=" * 84)
        print(f"SPECTRA-BIN REVERSE ENGINEERING REPORT: {os.path.basename(self.filepath)}")
        print("=" * 84)
        print(f"Engine Backend     : {engine_mode}")
        print(f"SHA-256 Digest     : {self.sha256}")
        print(f"File Size          : {self.size} bytes")
        print(f"Container Format   : {self.format_type}")
        print(f"Target Architecture: {self.arch_name} ({self.bits}-bit)")
        print(f"Overall Entropy    : {overall_entropy:.4f} bits/byte")
        print(f"PIE / ASLR Ready   : {'Yes' if self.is_pie else 'No'}")
        print(f"RWX Memory Pages   : {'Detected' if self.has_rwx else 'None'}")
        print(f"Entry Virtual Addr : 0x{self.entry_vaddr:016x}")
        print(f"Entry File Offset  : 0x{self.entry_offset:08x}")

        print("\n[1] OPERATING SYSTEM EXECUTION LIFECYCLE")
        if "ELF" in self.format_type:
            print("  1. Kernel Traps execve() : Kernel validates 0x7F 'E' 'L' 'F' magic bytes.")
            print("  2. Virtual Memory Layout : Kernel maps PT_LOAD segments into process page tables:")
            for seg in self.segments:
                if seg["type"] == "PT_LOAD":
                    print(f"     -> File 0x{seg['offset']:06x} -> VAddr 0x{seg['vaddr']:012x} "
                          f"(MemSz: 0x{seg['memsz']:06x}, Perms: {seg['perms']})")
            if self.interpreter:
                print(f"  3. Dynamic Linker Stage  : Kernel maps interpreter '{self.interpreter}'.")
                print("  4. Symbol Resolution     : Linker loads shared objects and patches PLT/GOT entries.")
            else:
                print("  3. Static Initialization : No PT_INTERP present; binary initializes directly.")
            print(f"  5. CPU Register Handoff  : Kernel sets instruction pointer to 0x{self.entry_vaddr:x}.")
        elif "PE" in self.format_type:
            print("  1. Kernel Process Init   : NtCreateUserProcess verifies MZ and PE headers.")
            print("  2. Section Page Mapping  : Windows Memory Manager maps sections into virtual memory.")
            print("  3. Import Table Linking  : LdrInitializeThunk resolves DLL imports in the IAT.")
            print(f"  4. Entry Point Transfer  : Thread starts at AddressOfEntryPoint 0x{self.entry_vaddr:x}.")
        else:
            print("  1. Unstructured Image    : File lacks standard OS loader headers.")

        if self.sections:
            print("\n[2] BINARY SECTION & ENTROPY LAYOUT")
            print(f"  {'Section Name':<20} {'VAddr':<18} {'Offset':<12} {'Size':<10} {'Entropy':<8}")
            print("  " + "-" * 72)
            for sec in self.sections[:16]:
                print(f"  {sec['name']:<20} 0x{sec['vaddr']:014x}   0x{sec['offset']:08x}   {sec['size']:<10} {sec['entropy']:.3f}")

        print("\n[3] SYSTEM CAPABILITIES & BEHAVIORAL INDICATORS")
        if behaviors:
            for category, symbols in behaviors.items():
                print(f"  * {category}: {', '.join(symbols)}")
        else:
            print("  * No dynamic API symbol strings matched.")

        print("\n[4] ENTRY POINT DISASSEMBLY & INSTRUCTION SEMANTICS")
        for insn in self.disassembly:
            print(f"  0x{insn['address']:012x}:  {insn['hex_bytes']:<24}  "
                  f"{insn['mnemonic']:<8} {insn['operands']:<26} [{insn['semantic_group']}]")
        print("=" * 84)
