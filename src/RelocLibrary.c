#include <dlfcn.h> //turn to dlsym for help at fake load object
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <elf.h>
#include <link.h>
#include <string.h>

#include "Link.h"
#include "LoaderInternal.h"

// glibc version to hash a symbol
static uint_fast32_t
dl_new_hash(const char *s)
{
    uint_fast32_t h = 5381;
    for (unsigned char c = *s; c != '\0'; c = *++s)
        h = h * 33 + c;
    return h & 0xffffffff;
}

// find symbol `name` inside the symbol table of `dep`
void *symbolLookup(LinkMap *dep, const char *name)
{
    if(dep->fake)
    {
        void *handle = dlopen(dep->name, RTLD_LAZY);
        if(!handle)
        {
            fprintf(stderr, "relocLibrary error: cannot dlopen a fake object named %s", dep->name);
            abort();
        }
        dep->fakeHandle = handle;
        return dlsym(handle, name);
    }

    Elf64_Sym *symtab = (Elf64_Sym *)dep->dynInfo[DT_SYMTAB]->d_un.d_ptr;
    const char *strtab = (const char *)dep->dynInfo[DT_STRTAB]->d_un.d_ptr;

    uint_fast32_t new_hash = dl_new_hash(name);
    Elf64_Sym *sym;
    const Elf64_Addr *bitmask = dep->l_gnu_bitmask;
    uint32_t symidx;
    Elf64_Addr bitmask_word = bitmask[(new_hash / __ELF_NATIVE_CLASS) & dep->l_gnu_bitmask_idxbits];
    unsigned int hashbit1 = new_hash & (__ELF_NATIVE_CLASS - 1);
    unsigned int hashbit2 = ((new_hash >> dep->l_gnu_shift) & (__ELF_NATIVE_CLASS - 1));
    if ((bitmask_word >> hashbit1) & (bitmask_word >> hashbit2) & 1)
    {
        Elf32_Word bucket = dep->l_gnu_buckets[new_hash % dep->l_nbuckets];
        if (bucket != 0)
        {
            const Elf32_Word *hasharr = &dep->l_gnu_chain_zero[bucket];
            do
            {
                if (((*hasharr ^ new_hash) >> 1) == 0)
                {
                    symidx = hasharr - dep->l_gnu_chain_zero;
                    /* now, symtab[symidx] is the current symbol.
                       Hash table has done its job */
                    const char *symname = strtab + symtab[symidx].st_name;
                    if (!strcmp(symname, name))
                    {    
                        Elf64_Sym *s = &symtab[symidx];
                        // return the real address of found symbol
                        return (void *)(s->st_value + dep->addr);
                    }
                }
            } while ((*hasharr++ & 1u) == 0);
        }
    }
    return NULL; //not this dependency
}

void* search(LinkMap* lib, const char* name){
	if(lib->fake && strcmp(name, "printf"))
		return NULL;
   	void *address = symbolLookup(lib, name);
   	if(address != NULL)
   		return address;
   	for(int i = 0; i < lib->searchNum; i++){
   		address = search(lib->searchList[i], name);
   		if(address != NULL)
   			return address;
	}
	return NULL;
}

void reloclibrary(LinkMap *lib, int mode){
	*((uint64_t*)lib->dynInfo[DT_PLTGOT]->d_un.d_ptr + 1) = lib;
	*((uint64_t*)lib->dynInfo[DT_PLTGOT]->d_un.d_ptr + 2) = &trampoline;
    char* string_table = (char*)lib->dynInfo[DT_STRTAB]->d_un.d_ptr;
    Elf64_Sym* symbol_table = (Elf64_Sym*)lib->dynInfo[DT_SYMTAB]->d_un.d_ptr;
    if(!lib->dynInfo[DT_RELA])return;
    Elf64_Rela* rela = (Elf64_Rela*)lib->dynInfo[DT_RELA]->d_un.d_ptr;
    uint64_t count = lib->dynInfo[DT_RELACOUNT_NEW]->d_un.d_val;
    uint64_t size = lib->dynInfo[DT_RELASZ]->d_un.d_val;
    size /= sizeof(Elf64_Rela);
    size -= count;
    while(count--){
    	*(uint64_t*)(lib->addr + rela->r_offset) = lib->addr + rela->r_addend;
    	rela++;
    }
    while(size--){
    	Elf64_Sym* symbol = symbol_table + (rela->r_info >> 32);
    	char* name = string_table + symbol->st_name;
    	void* address = search(lib, name);
    	//printf("%s: %p = %p\n", name, (uint64_t*)(lib->addr + rela->r_offset), address + rela->r_addend);
    	if(address != NULL)
		   	*(uint64_t*)(lib->addr + rela->r_offset) = address + rela->r_addend;
    	rela++;
    }
    if(!lib->dynInfo[DT_JMPREL])return;
    rela = (Elf64_Rela*)lib->dynInfo[DT_JMPREL]->d_un.d_ptr;
    size = lib->dynInfo[DT_PLTRELSZ]->d_un.d_val;
    size /= sizeof(Elf64_Rela);
    while(size--){
    	if(mode){
    		Elf64_Sym* symbol = symbol_table + (rela->r_info >> 32);
	    	char* name = string_table + symbol->st_name;
	    	void* address = search(lib, name);
    		//printf("%s: %p = %p\n", name, (uint64_t*)(lib->addr + rela->r_offset), address + rela->r_addend);
 		   	//printf("%p = %p\n", (uint64_t*)(lib->addr + rela->r_offset), *(uint64_t*)(lib->addr + rela->r_offset) + lib->addr);
		   	*(uint64_t*)(lib->addr + rela->r_offset) = *(uint64_t*)(lib->addr + rela->r_offset) + lib->addr;
		   	continue;
    	}
    	Elf64_Sym* symbol = symbol_table + (rela->r_info >> 32);
    	char* name = string_table + symbol->st_name;
    	void* address = search(lib, name);
    	//printf("%s: %p = %p\n", name, (uint64_t*)(lib->addr + rela->r_offset), address + rela->r_addend);
    	if(address != NULL)
		   	*(uint64_t*)(lib->addr + rela->r_offset) = address + rela->r_addend;
    	rela++;
    }
}

void reloc_search(LinkMap *lib, int mode){
	if(lib->fake)
		return;
	reloclibrary(lib, mode);
	for(int i = 0; i < lib->searchNum; i++)
		reloc_search(lib->searchList[i], mode);
}

void RelocLibrary(LinkMap *lib, int mode)
{
    /* Your code here */
    //if(mode)puts("Resolving address for entry 0");//unbengable
    reloc_search(lib, mode);
}
