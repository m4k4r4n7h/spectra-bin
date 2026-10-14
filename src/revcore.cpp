#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <map>
#include <algorithm>
#include <cstdint>
#include <elf.h>
#include <capstone/capstone.h>

struct DecodedInstruction {
    uint64_t address;
    std::string hex_bytes;
    std::string mnemonic;
    std::string operands;
    std::string behavior_note;
};

class ReverseEngineCore {
private:
    std::vector<uint8_t> buffer;
    uint64_t entry_vaddr = 0;
    uint64_t entry_offset = 0;
    cs_arch target_arch = CS_ARCH_X86;
    cs_mode target_mode = CS_MODE_64;

    std::string classify_instruction(const std::string &mnemonic, const std::string &op_str) {
        if (mnemonic == "syscall" || mnemonic == "int" || mnemonic == "svc") {
            return "Direct Kernel System Call Transition";
        }
        if (mnemonic == "call" || mnemonic == "bl" || mnemonic == "blr") {
            return "Subroutine Invocation (" + op_str + ")";
        }
        if (mnemonic == "ret" || mnemonic == "retq") {
            return "Stack Frame Unwind / Return";
        }
        if (mnemonic == "cpuid" || mnemonic == "rdtsc") {
            return "Hardware / Timing Inspection";
        }
        if (mnemonic.rfind("j", 0) == 0 || mnemonic.rfind("b.", 0) == 0) {
            return "Control Flow Branch";
        }
        return "";
    }

public:
    bool load_file(const std::string &path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) return false;
        std::streamsize size = file.tellg();
        if (size <= 0) return false;
        file.seekg(0, std::ios::beg);
        buffer.resize(static_cast<size_t>(size));
        if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) return false;

        if (buffer.size() >= sizeof(Elf64_Ehdr) &&
            buffer[0] == 0x7F && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F') {
            const auto *ehdr = reinterpret_cast<const Elf64_Ehdr *>(buffer.data());
            entry_vaddr = ehdr->e_entry;
            if (ehdr->e_machine == EM_AARCH64) {
                target_arch = CS_ARCH_ARM64;
                target_mode = CS_MODE_ARM;
            } else {
                target_arch = CS_ARCH_X86;
                target_mode = CS_MODE_64;
            }

            if (ehdr->e_phoff + ehdr->e_phnum * sizeof(Elf64_Phdr) <= buffer.size()) {
                const auto *phdrs = reinterpret_cast<const Elf64_Phdr *>(buffer.data() + ehdr->e_phoff);
                for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
                    if (phdrs[i].p_type == PT_LOAD &&
                        entry_vaddr >= phdrs[i].p_vaddr &&
                        entry_vaddr < phdrs[i].p_vaddr + phdrs[i].p_memsz) {
                        entry_offset = (entry_vaddr - phdrs[i].p_vaddr) + phdrs[i].p_offset;
                        break;
                    }
                }
            }
        }
        return true;
    }

    std::vector<DecodedInstruction> disassemble_entry(size_t max_instructions) {
        std::vector<DecodedInstruction> results;
        if (entry_offset >= buffer.size()) return results;

        csh handle;
        if (cs_open(target_arch, target_mode, &handle) != CS_ERR_OK) {
            return results;
        }
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        const uint8_t *code_ptr = buffer.data() + entry_offset;
        size_t code_len = std::min<size_t>(buffer.size() - entry_offset, 512);
        cs_insn *insn = nullptr;

        size_t count = cs_disasm(handle, code_ptr, code_len, entry_vaddr, max_instructions, &insn);
        if (count > 0) {
            for (size_t i = 0; i < count; i++) {
                std::ostringstream hex_stream;
                for (uint16_t b = 0; b < insn[i].size; b++) {
                    hex_stream << std::hex << std::setw(2) << std::setfill('0')
                               << static_cast<int>(insn[i].bytes[b]) << " ";
                }
                std::string mnem = insn[i].mnemonic;
                std::string ops = insn[i].op_str;
                results.push_back({
                    insn[i].address,
                    hex_stream.str(),
                    mnem,
                    ops,
                    classify_instruction(mnem, ops)
                });
            }
            cs_free(insn, count);
        }
        cs_close(&handle);
        return results;
    }

    std::map<std::string, std::vector<std::string>> extract_behavioral_capabilities() {
        std::map<std::string, std::vector<std::string>> capabilities;
        std::map<std::string, std::string> rules = {
            {"socket", "Network Socket Creation"},
            {"connect", "Outbound Network Connection"},
            {"bind", "Network Port Listening"},
            {"execve", "New Process Execution"},
            {"system", "Shell Command Execution"},
            {"fork", "Child Process Cloning"},
            {"mprotect", "Virtual Memory Permission Modification"},
            {"mmap", "Direct Virtual Memory Mapping"},
            {"dlopen", "Runtime Shared Library Injection / Loading"},
            {"ptrace", "Process Debugging / Inspection"},
            {"fopen", "Filesystem Stream Access"},
            {"unlink", "File Deletion"},
            {"pthread_create", "Multi-threaded Execution"}
        };

        std::string current;
        for (uint8_t byte : buffer) {
            if (byte >= 32 && byte <= 126) {
                current.push_back(static_cast<char>(byte));
            } else {
                if (current.size() >= 3) {
                    for (const auto &rule : rules) {
                        if (current == rule.first || current.rfind(rule.first + "@", 0) == 0) {
                            capabilities[rule.second].push_back(current);
                        }
                    }
                }
                current.clear();
            }
        }
        return capabilities;
    }
};

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary_path>\n";
        return 1;
    }

    ReverseEngineCore engine;
    if (!engine.load_file(argv[1])) {
        std::cerr << "Unable to load binary file.\n";
        return 1;
    }

    std::cout << "=== ENTRY POINT DISASSEMBLY ===\n";
    auto instructions = engine.disassemble_entry(25);
    for (const auto &inst : instructions) {
        std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0') << inst.address << "  "
                  << std::left << std::setw(24) << std::setfill(' ') << inst.hex_bytes
                  << std::setw(10) << inst.mnemonic
                  << std::setw(28) << inst.operands;
        if (!inst.behavior_note.empty()) {
            std::cout << " [" << inst.behavior_note << "]";
        }
        std::cout << "\n";
    }

    std::cout << "\n=== DETECTED SYSTEM BEHAVIORS ===\n";
    auto caps = engine.extract_behavioral_capabilities();
    for (const auto &entry : caps) {
        std::cout << "* " << entry.first << " (Symbol: " << entry.second.front() << ")\n";
    }
    return 0;
}
