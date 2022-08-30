#include <string.h>
#include <stdio.h>
struct elf_header_x86_64
{
    uint32_t magic;

    uint8_t class;
    uint8_t endian;
    uint8_t version;
    uint8_t osabi;
    uint8_t abiversion;
    
    uint8_t padding[7];
    uint16_t type;
    uint16_t machine;

    uint32_t e_version;

    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;

    uint32_t e_flags;

    uint16_t e_ehsize;
    uint16_t e_phentsize;

    uint16_t e_phunum;
    uint16_t e_shentsize;

    uint16_t e_shnum;
    uint16_t e_shstrndx;

};
struct elf_section_header_x86_64
{
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;

    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;

    uint32_t sh_link;
    uint32_t sh_info;


    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

void parse_section_headers(FILE* f, struct elf_header_x86_64* elfheader);
void parse_elf(char* filename);