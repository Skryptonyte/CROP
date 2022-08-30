
#include <stdio.h>
#include <stdint.h>

void copy_to_struct(FILE* f, void *e, size_t size);
int output_disassembly(void* buf, int size, uint64_t addr);
