#include <elf.h>
#include <stdlib.h>
#include <stdio.h>

#include "Link.h"
#include "LoaderInternal.h"

Elf64_Addr __attribute__((visibility ("hidden"))) //this makes trampoline to call it w/o plt
runtimeResolve(LinkMap *lib, Elf64_Word reloc_entry)
{
    printf("Resolving address for entry %u\n", reloc_entry);
    /* Your code here */
    char* string_table = (char*)lib->dynInfo[DT_STRTAB]->d_un.d_ptr;
    Elf64_Sym* symbol_table = (Elf64_Sym*)lib->dynInfo[DT_SYMTAB]->d_un.d_ptr;
    Elf64_Rela* rela = (Elf64_Rela*)lib->dynInfo[DT_JMPREL]->d_un.d_ptr;
    while(reloc_entry > 0){
    	rela++;
    	reloc_entry--;
    }
   	Elf64_Sym* symbol = symbol_table + (rela->r_info >> 32);
   	char* name = string_table + symbol->st_name;
   	void* address = search(lib, name);
   	//printf("%s: %p = %p\n", name, (uint64_t*)(lib->addr + rela->r_offset + rela->r_addend), address);
   	*(uint64_t*)(lib->addr + rela->r_offset + rela->r_addend) = address;
    return (Elf64_Addr)address;
}
