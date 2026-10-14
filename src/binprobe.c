#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>

typedef struct {
    uint64_t file_size;
    double entropy;
    char format[32];
    char arch[32];
    uint64_t entry_point;
    uint64_t entry_file_offset;
    uint16_t phdr_count;
    uint16_t shdr_count;
    int is_pie;
    int has_rwx_segment;
    char interpreter[256];
} BinaryProfile;

double compute_entropy(const uint8_t *data, size_t size) {
    if (size == 0) return 0.0;
    uint64_t counts[256] = {0};
    for (size_t i = 0; i < size; i++) {
        counts[data[i]]++;
    }
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / (double)size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

void detect_magic(const uint8_t *data, size_t size, BinaryProfile *profile) {
    if (size >= 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
        snprintf(profile->format, sizeof(profile->format), "ELF");
    } else if (size >= 2 && data[0] == 'M' && data[1] == 'Z') {
        snprintf(profile->format, sizeof(profile->format), "PE/COFF");
    } else if (size >= 4 && ((data[0] == 0xCF && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE) ||
                             (data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFA && data[3] == 0xCF))) {
        snprintf(profile->format, sizeof(profile->format), "Mach-O 64");
    } else if (size >= 2 && data[0] == '#' && data[1] == '!') {
        snprintf(profile->format, sizeof(profile->format), "Interpreter Script");
    } else {
        snprintf(profile->format, sizeof(profile->format), "Raw Binary / Data");
    }
}

void parse_elf64(const uint8_t *data, size_t size, BinaryProfile *profile) {
    if (size < sizeof(Elf64_Ehdr)) return;
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        snprintf(profile->arch, sizeof(profile->arch), "32-bit ELF");
        return;
    }

    switch (ehdr->e_machine) {
        case EM_X86_64: snprintf(profile->arch, sizeof(profile->arch), "x86_64"); break;
        case EM_AARCH64: snprintf(profile->arch, sizeof(profile->arch), "AArch64"); break;
        case EM_RISCV: snprintf(profile->arch, sizeof(profile->arch), "RISC-V"); break;
        default: snprintf(profile->arch, sizeof(profile->arch), "Machine ID %u", ehdr->e_machine); break;
    }

    profile->entry_point = ehdr->e_entry;
    profile->phdr_count = ehdr->e_phnum;
    profile->shdr_count = ehdr->e_shnum;
    profile->is_pie = (ehdr->e_type == ET_DYN) ? 1 : 0;

    if (ehdr->e_phoff + (ehdr->e_phnum * sizeof(Elf64_Phdr)) > size) return;
    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(data + ehdr->e_phoff);

    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr *ph = &phdrs[i];

        if (ph->p_type == PT_INTERP && ph->p_offset + ph->p_filesz <= size && ph->p_filesz < sizeof(profile->interpreter)) {
            memcpy(profile->interpreter, data + ph->p_offset, ph->p_filesz);
            profile->interpreter[sizeof(profile->interpreter) - 1] = '\0';
        }

        if (ph->p_type == PT_LOAD) {
            if ((ph->p_flags & PF_W) && (ph->p_flags & PF_X)) {
                profile->has_rwx_segment = 1;
            }
            if (profile->entry_point >= ph->p_vaddr && profile->entry_point < (ph->p_vaddr + ph->p_memsz)) {
                profile->entry_file_offset = (profile->entry_point - ph->p_vaddr) + ph->p_offset;
            }
        }
    }
}

int analyze_binary_file(const char *filepath, BinaryProfile *profile) {
    memset(profile, 0, sizeof(BinaryProfile));
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size == 0) {
        close(fd);
        return -1;
    }

    uint8_t *mapped = (uint8_t *)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        close(fd);
        return -1;
    }

    profile->file_size = (uint64_t)st.st_size;
    profile->entropy = compute_entropy(mapped, st.st_size);
    detect_magic(mapped, st.st_size, profile);

    if (strcmp(profile->format, "ELF") == 0) {
        parse_elf64(mapped, st.st_size, profile);
    }

    munmap(mapped, st.st_size);
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }

    BinaryProfile profile;
    if (analyze_binary_file(argv[1], &profile) != 0) {
        fprintf(stderr, "Failed to analyze target file.\n");
        return 1;
    }

    printf("Format:            %s\n", profile.format);
    printf("Architecture:      %s\n", profile.arch[0] ? profile.arch : "Generic");
    printf("File Size:         %llu bytes\n", (unsigned long long)profile.file_size);
    printf("Shannon Entropy:   %.4f bits/byte\n", profile.entropy);
    printf("Entry Virtual Addr:0x%llx\n", (unsigned long long)profile.entry_point);
    printf("Entry File Offset: 0x%llx\n", (unsigned long long)profile.entry_file_offset);
    printf("Dynamic Loader:    %s\n", profile.interpreter[0] ? profile.interpreter : "Statically Linked / None");
    printf("PIE Enabled:       %s\n", profile.is_pie ? "Yes" : "No");
    printf("RWX Memory Pages:  %s\n", profile.has_rwx_segment ? "Detected" : "None");
    return 0;
}
