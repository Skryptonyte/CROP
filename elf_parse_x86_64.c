
#include <stdint.h>
#include "elf_parse_x86_64.h"
#include <stdio.h>
#include <string.h>


void parse_section(FILE* f, struct elf_section_header_x86_64* e, uint8_t* buf)
{
    fseek(f,e->sh_offset,SEEK_SET);
    copy_to_struct(f,buf,e->sh_size);
}


void parse_section_headers(FILE* f, struct elf_header_x86_64* elfheader)
{

    uint16_t e_shnum = elfheader->e_shnum;
    uint64_t e_shoff = elfheader->e_shoff;

    fseek(f,e_shoff,SEEK_SET);
    struct elf_section_header_x86_64 e;

    int gadget_count = 0;
    int seek = e_shoff;
    for (int s = 0; s < e_shnum; s++)
    {
        
        copy_to_struct(f,&e,sizeof(struct elf_section_header_x86_64));
        int ret_count = 0;
        if ((e.sh_flags&0x4)>>2)
        {
            printf("-- Section %03d - File offset: %ld ,Name offset: %d, Size: %ld, Executable: %d\n",s,e.sh_offset,e.sh_name,e.sh_size,(e.sh_flags&0x4)>>2) ;

            
            uint8_t buf[e.sh_size];
            parse_section(f, &e, buf);
            int max_search = 10;
            for (int i = 0; i < e.sh_size; i++)
            {
                // Gadgets ending with ret (near)
                if (buf[i] == 0xc3)     
                {
                    int backoff = buf+i-max_search >= buf? max_search: i;
                    for (backoff; backoff >= 0; backoff--)
                    {
                        if (output_disassembly(buf+i-backoff, backoff+1, e.sh_addr +i-backoff)) gadget_count++;
                    }
                }
                // Gadgets ending with call <register> or jmp <register>
                else if (buf[i] == 0xff && i+1 < e.sh_size && ( ( buf[i+1] <= 0xd7 && buf[i+1] >= 0xd0 ) || ( buf[i+1] <= 0xe7 && buf[i+1] >= 0xe0 )) )    
                {
                    int backoff = buf+i-max_search >= buf? max_search: i;
                    for (backoff; backoff >= 0; backoff--)
                    {
                        if (output_disassembly(buf+i-backoff, backoff+1, e.sh_addr +i-backoff)) gadget_count++;
                    }
                    ret_count++;
                }
            }
        }

        seek += sizeof(struct elf_section_header_x86_64);
        fseek(f,seek,SEEK_SET);

    }
    
    printf("No. of gadgets: %d\n",gadget_count);
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

    parse_section_headers(f, &e);
}