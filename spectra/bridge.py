import os
import ctypes


class NativeBinaryProfile(ctypes.Structure):
    _fields_ = [
        ("file_size", ctypes.c_uint64),
        ("entropy", ctypes.c_double),
        ("format", ctypes.c_char * 32),
        ("arch", ctypes.c_char * 32),
        ("entry_point", ctypes.c_uint64),
        ("entry_file_offset", ctypes.c_uint64),
        ("phdr_count", ctypes.c_uint16),
        ("shdr_count", ctypes.c_uint16),
        ("is_pie", ctypes.c_int),
        ("has_rwx_segment", ctypes.c_int),
        ("interpreter", ctypes.c_char * 256),
    ]


class NativeInstructionRecord(ctypes.Structure):
    _fields_ = [
        ("address", ctypes.c_uint64),
        ("hex_bytes", ctypes.c_char * 32),
        ("mnemonic", ctypes.c_char * 16),
        ("operands", ctypes.c_char * 64),
        ("semantic_group", ctypes.c_char * 48),
    ]


class NativeEngineBridge:
    def __init__(self, lib_path=None):
        if lib_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            lib_path = os.path.join(base_dir, "build", "libspectra.so")
        self.lib_path = lib_path
        self.lib = None
        if os.path.exists(self.lib_path):
            try:
                self.lib = ctypes.CDLL(self.lib_path)
                self.lib.analyze_binary_file.argtypes = [ctypes.c_char_p, ctypes.POINTER(NativeBinaryProfile)]
                self.lib.analyze_binary_file.restype = ctypes.c_int
                self.lib.disassemble_binary_entry.argtypes = [
                    ctypes.c_char_p,
                    ctypes.POINTER(NativeInstructionRecord),
                    ctypes.c_int,
                ]
                self.lib.disassemble_binary_entry.restype = ctypes.c_int
            except OSError:
                self.lib = None

    def is_available(self):
        return self.lib is not None

    def probe_file(self, filepath):
        if not self.is_available():
            return None
        profile = NativeBinaryProfile()
        res = self.lib.analyze_binary_file(filepath.encode("utf-8"), ctypes.byref(profile))
        if res != 0:
            return None
        return {
            "file_size": profile.file_size,
            "entropy": profile.entropy,
            "format": profile.format.decode("utf-8", errors="ignore"),
            "arch": profile.arch.decode("utf-8", errors="ignore"),
            "entry_point": profile.entry_point,
            "entry_file_offset": profile.entry_file_offset,
            "phdr_count": profile.phdr_count,
            "shdr_count": profile.shdr_count,
            "is_pie": bool(profile.is_pie),
            "has_rwx_segment": bool(profile.has_rwx_segment),
            "interpreter": profile.interpreter.decode("utf-8", errors="ignore"),
        }

    def disassemble_entry(self, filepath, limit=25):
        if not self.is_available():
            return None
        array_type = NativeInstructionRecord * limit
        records = array_type()
        count = self.lib.disassemble_binary_entry(filepath.encode("utf-8"), records, limit)
        if count <= 0:
            return None
        output = []
        for i in range(count):
            output.append({
                "address": records[i].address,
                "hex_bytes": records[i].hex_bytes.decode("utf-8", errors="ignore").strip(),
                "mnemonic": records[i].mnemonic.decode("utf-8", errors="ignore"),
                "operands": records[i].operands.decode("utf-8", errors="ignore"),
                "semantic_group": records[i].semantic_group.decode("utf-8", errors="ignore"),
            })
        return output
