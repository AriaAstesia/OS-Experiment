#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <unistd.h> //for getpagesize
#include <sys/mman.h>

#include <fcntl.h>

#include "Link.h"
#include "LoaderInternal.h"

#define ALIGN_DOWN(base, size) ((base) & -((__typeof__(base))(size)))
#define ALIGN_UP(base, size) ALIGN_DOWN((base) + (size)-1, (size))

static const char *sys_path[] = {
    "/usr/lib/x86_64-linux-gnu/",
    "/lib/x86_64-linux-gnu/",
    ""
};

static const char *fake_so[] = {
    "libc.so.6",
    "ld-linux.so.2",
    ""
};

static void setup_hash(LinkMap *l)
{
    uint32_t *hash;

    /* borrowed from dl-lookup.c:_dl_setup_hash */
    Elf32_Word *hash32 = (Elf32_Word *)l->dynInfo[DT_GNU_HASH_NEW]->d_un.d_ptr;
    l->l_nbuckets = *hash32++;
    Elf32_Word symbias = *hash32++;
    Elf32_Word bitmask_nwords = *hash32++;

    l->l_gnu_bitmask_idxbits = bitmask_nwords - 1;
    l->l_gnu_shift = *hash32++;

    l->l_gnu_bitmask = (Elf64_Addr *)hash32;
    hash32 += 64 / 32 * bitmask_nwords;

    l->l_gnu_buckets = hash32;
    hash32 += l->l_nbuckets;
    l->l_gnu_chain_zero = hash32 - symbias;
}

static void fill_info(LinkMap *lib)
{
    Elf64_Dyn *dyn = lib->dyn;
    Elf64_Dyn **dyn_info = lib->dynInfo;

    while (dyn->d_tag != DT_NULL)
    {
        if ((Elf64_Xword)dyn->d_tag < DT_NUM)
            dyn_info[dyn->d_tag] = dyn;
        else if ((Elf64_Xword)dyn->d_tag == DT_RELACOUNT)
            dyn_info[DT_RELACOUNT_NEW] = dyn;
        else if ((Elf64_Xword)dyn->d_tag == DT_GNU_HASH)
            dyn_info[DT_GNU_HASH_NEW] = dyn;
        ++dyn;
    }
    #define rebase(tag)                             \
        do                                          \
        {                                           \
            if (dyn_info[tag])                          \
                dyn_info[tag]->d_un.d_ptr += lib->addr; \
        } while (0)
    rebase(DT_SYMTAB);
    rebase(DT_STRTAB);
    rebase(DT_RELA);
    rebase(DT_JMPREL);
    rebase(DT_GNU_HASH_NEW); //DT_GNU_HASH
    rebase(DT_PLTGOT);
    rebase(DT_INIT);
    rebase(DT_INIT_ARRAY);
}

void* maplibrary(const char* libpath){
    const uint64_t pgsz = getpagesize();
    int fd = open(libpath, O_RDONLY);
    LinkMap *lib = malloc(sizeof(LinkMap));
    Elf64_Ehdr *header = malloc(sizeof(Elf64_Ehdr));
    pread(fd, header, sizeof(Elf64_Ehdr), 0);
    lib->name = malloc(sizeof(libpath));
    strcpy(lib->name, libpath);

	Elf64_Phdr **segment = malloc(header->e_phnum * sizeof(Elf64_Phdr*));
	uint64_t size = 0;
	for(int i = 0; i < header->e_phnum; i++){
		segment[i] = malloc(sizeof(Elf64_Phdr));
		pread(fd, segment[i], sizeof(Elf64_Phdr), header->e_phoff + i * header->e_phentsize);
		if(segment[i]->p_type == PT_DYNAMIC)
			break;
		size = segment[i]->p_vaddr + segment[i]->p_memsz;
	}

	int prot = 0;
	prot |= (segment[0]->p_flags & PF_R)? PROT_READ : 0;
	prot |= (segment[0]->p_flags & PF_W)? PROT_WRITE : 0;
	prot |= (segment[0]->p_flags & PF_X)? PROT_EXEC : 0;

	void *start_addr = mmap(NULL, ALIGN_UP(size, pgsz), prot,
			MAP_FILE | MAP_PRIVATE, fd, ALIGN_DOWN(segment[0]->p_offset, pgsz));
	lib->addr = (uint64_t)start_addr;

	for(int i = 1; i < header->e_phnum; i++){

		size = segment[i]->p_vaddr + segment[i]->p_memsz;
		size = (ALIGN_UP(size - ALIGN_DOWN(segment[i]->p_vaddr, pgsz), pgsz));
		int offset = (ALIGN_DOWN(segment[i]->p_offset, pgsz));

		prot = 0;
		prot |= (segment[i]->p_flags & PF_R)? PROT_READ : 0;
		prot |= (segment[i]->p_flags & PF_W)? PROT_WRITE : 0;
		prot |= (segment[i]->p_flags & PF_X)? PROT_EXEC : 0;

		if(segment[i]->p_type == PT_DYNAMIC){
			lib->dyn = mmap(NULL, size, prot, MAP_FILE | MAP_PRIVATE, fd, offset) + (segment[i]->p_offset & pgsz - 1);
			break;
		}else{
			mmap((void*)(ALIGN_DOWN((uint64_t)start_addr + segment[i]->p_vaddr, pgsz)),
					size, prot,	MAP_FILE | MAP_PRIVATE | MAP_FIXED, fd, offset);
		}
	}
	fill_info(lib);
	setup_hash(lib);
    return lib;
}

void* MapLibrary(const char *libpath)
{
    /*
     * hint:
     * 
     * lib = malloc(sizeof(LinkMap));
     * 
     * foreach segment:
     * mmap(start_addr, segment_length, segment_prot, MAP_FILE | ..., library_fd, 
     *      segment_offset);
     * 
     * lib -> addr = ...;
     * lib -> dyn = ...;
     * 
     * fill_info(lib);
     * setup_hash(lib);
     * 
     * return lib;
    */
   
    /* Your code here */
    LinkMap *lib = maplibrary(libpath);
    char* string_table = (char*)lib->dynInfo[DT_STRTAB]->d_un.d_ptr;
    char runpath[20] = "./test_lib/";
    char deppath[100] = {0};
    int cnt = 0;
    lib->searchList = malloc(100 * sizeof(LinkMap*));
    Elf64_Dyn *dyn = lib->dyn;
    while(dyn->d_tag != DT_NULL && dyn->d_tag != DT_NEEDED)dyn++;
    while(dyn->d_tag != DT_NULL && dyn->d_tag == DT_NEEDED){
    	char* name = string_table + dyn->d_un.d_val;
    	if(!strlen(name)){
    		dyn++;
    		continue;
		}
    	lib->searchList[cnt] = malloc(sizeof(LinkMap));
    	if(!strcmp(name, fake_so[0]) || !strcmp(name, fake_so[1])){
    		lib->searchList[cnt]->fake = 1;
    		lib->searchList[cnt]->name = name;
    		cnt++;
    		dyn++;
    		continue;
    	}
    	strcat(deppath, runpath);
    	strcat(deppath, name);
    	lib->searchList[cnt++] = MapLibrary(deppath);
    	dyn++;
    	memset(deppath, 0, sizeof deppath);
    }
    lib->searchNum = cnt;
    return lib;
}
