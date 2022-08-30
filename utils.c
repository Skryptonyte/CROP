#include "utils.h"
#include <stdint.h>
#include <string.h>
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


int valid_gadget(cs_insn *insn, int count)
{
    int is_ret = strstr(insn[count-1].mnemonic,"ret") != NULL;
    int is_call = strstr(insn[count-1].mnemonic,"call") != NULL;
    int is_jmp = strstr(insn[count-1].mnemonic,"jmp") != NULL;
    if (is_ret || is_call || is_jmp)
        return 1;
    return 0;
}
int output_disassembly(void* buf, int size, uint64_t addr)
{  
    csh handle;
    cs_insn* insn;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return 0;

    int count = cs_disasm(handle, buf, size, addr, 0, &insn);
    if (count == 0)
    {
        // printf("Can't disassemble :(\n");
        return 0;
    }

    if (valid_gadget(insn, count) == 0)
    {
        //printf("INSTRUCTION SKIPPED\n!");
        return 0;
    }
    printf("0x%016x: ",insn[0].address);
    for (int i = 0; i < count; i++)
    {

        printf("%s %s; ",insn[i].mnemonic,insn[i].op_str);
        
    }
    printf("\n");

    cs_free(insn, count);
    cs_close(&handle);
    return 1;
}
