#include "utils.h"
#include <stdint.h>
#include <capstone/capstone.h>

void copy_to_struct(FILE* f, void* e, size_t size)
{
    for (int i = 0; i < size; i++)
    {
        int ch = getc(f);
        if (ch == EOF)
        {
            puts("Error: EOF reached unexpectedly!");
            exit(-1);
        }
        *(((uint8_t*) e)+i) = (uint8_t) ch&0xff; 
    }
}


void output_disassembly(void* buf, int size, uint64_t addr)
{  
    csh handle;
    cs_insn* insn;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return;

    int count = cs_disasm(handle, buf, size, addr, 0, &insn);
    if (count == 0)
    {
        // printf("Can't disassemble :(\n");
        return;
    }
    printf("%018p: ",insn[0].address);
    for (int i = 0; i < count; i++)
    {

        printf("%s %s; ",insn[i].mnemonic,insn[i].op_str);
    }
    printf("\n");

    cs_close(&handle);
}
