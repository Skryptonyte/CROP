#include <stdio.h>
#include <capstone/capstone.h>
#include <string.h>

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        puts("Syntax: crop <executable>");
        return -1;
    }
    parse_elf(argv[1]);
    return 0;
}
