#include <stdlib.h>
#include <stdio.h>
#include <elf.h>
#include <stdint.h>

#include "Link.h"
#include "LoaderInternal.h"

void InitLibrary(LinkMap *l)
{
    /* Your code here */
    void (*foo)(void);
    foo = (void*)l->dynInfo[DT_INIT]->d_un.d_ptr;
    foo();

	uint64_t* func_addr = (uint64_t*)l->dynInfo[DT_INIT_ARRAY]->d_un.d_ptr;
    uint64_t size = l->dynInfo[DT_INIT_ARRAYSZ]->d_un.d_val;
    size /= sizeof(void*);
    while(size--){
    	foo = (void*)(*func_addr);
    	if(foo != NULL)
    	foo();
    	func_addr++;
    }
}
