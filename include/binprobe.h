#ifndef BINPROBE_H
#define BINPROBE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

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

typedef struct {
    uint64_t address;
    char hex_bytes[32];
    char mnemonic[16];
    char operands[64];
    char semantic_group[48];
} InstructionRecord;

double compute_entropy(const uint8_t *data, size_t size);
int analyze_binary_file(const char *filepath, BinaryProfile *profile);
int disassemble_binary_entry(const char *filepath, InstructionRecord *records, int max_records);

#ifdef __cplusplus
}
#endif

#endif
