
#include <stdint.h>
#include "elf_parse_x86_64.h"
#include <stdio.h>
#include <string.h>

void parse_section_headers(FILE* f, uint64_t e_shoff, uint16_t e_shnum)
{

    fseek(f,e_shoff,SEEK_SET);
    
    struct elf_section_header_x86_64 e;

    int seek = e_shoff;
    for (int s = 0; s < e_shnum; s++)
    {
        
        copy_to_struct(f,&e,sizeof(struct elf_section_header_x86_64));
        int ret_count = 0;
        if ((e.sh_flags&0x4)>>2)
        {
            printf("-- Section %03d - File offset: %d ,Name offset: %d, Size: %d, Executable: %d\n",s,e.sh_offset,e.sh_name,e.sh_size,(e.sh_flags&0x4)>>2) ;

            fseek(f,e.sh_offset,SEEK_SET);
            uint8_t buf[e.sh_size];
            copy_to_struct(f,buf,e.sh_size);
            
            int max_search = 10;
            for (int i = 0; i < e.sh_size; i++)
            {
                if (buf[i] == 0xc3)
                {
                    int backoff = buf+i-max_search >= buf? max_search: i;
                    for (backoff; backoff >= 0; backoff--)
                    {
                        output_disassembly(buf+i-backoff, backoff+1, e.sh_addr +i-backoff);
                    }
                    ret_count++;
                }
            }
            //printf("Found %d RET instructions!\n",ret_count);

        }

        seek += sizeof(struct elf_section_header_x86_64);
        fseek(f,seek,SEEK_SET);

    }
    
}
void parse_elf(char* filename)
{
    FILE* f = fopen(filename,"rb");

    struct elf_header_x86_64 e;

    copy_to_struct(f,&e,sizeof(struct elf_header_x86_64));
    if (e.magic != 0x464c457f)
    {
        puts("ELF Magic Number is incorrect! Terminating!");
        exit(-1);
    }
    if (e.machine == 0x3e)
        printf("ARCH: X86_64\n");
    else
        printf("UNSUPPORTED ARCHITECTURE!\n");
    printf("ELF Header size: 0x%x\n", sizeof(struct elf_header_x86_64));
    printf("ELF Version: %d\n",e.e_version);
    printf("ELF Entry: %p\n",e.e_entry);
    printf("ELF program start: %p\n",e.e_phoff);
    printf("ELF Section start: %p\n",e.e_shoff);
    printf("ELF Section count: %d\n",e.e_shnum);
    printf("ELF Section Name store index: %d\n",e.e_shstrndx);

    parse_section_headers(f, e.e_shoff, e.e_shnum);
}