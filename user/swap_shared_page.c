#include <inc/lib.h>
#include <lib/syscall.c>

#define SLEEP_FOR 100

void
ifork()
{
	char *msg = "Shared by Parent";
	int cpid, r = 0, i=0;
	uint64_t addr = 0xa00000;

	if ((cpid=fork()) == 0) {
		sys_yield();
		sys_yield();
		while(true){
			//if(0 == addr%0xbdf000)
			//	cprintf("\t\t\tChild ENV[%08x] Running...Received shared page from parent: \"%s\"\n", thisenv->env_id, (char*)0xaf0000);
			sys_sleep(SLEEP_FOR);
			addr+=PGSIZE;
			if ((r = sys_page_alloc(0, (void*)addr, PTE_P|PTE_U|PTE_W)) < 0){
				cprintf("\t\t\tALLOC of %016x by Child[%08x] FAILED with %e!.\n", addr, thisenv->env_id, r);
				exit();
			}

			cprintf("\t\t\tALLOC of %016x by Child[%08x] done.\n", addr, thisenv->env_id);
		}
	}else{
	}

        if ((r = sys_page_alloc(0, (void*)addr, PTE_P|PTE_U|PTE_W|PTE_SHARE)) < 0){
                cprintf("\t\t\tALLOC of %016x by Parent[%08x] FAILED with %e!.\n", addr, thisenv->env_id, r);
                exit();
        }
        memcpy((void*)addr, msg, strlen(msg)+1);
	cprintf("\t\t\tMAPPING %016x to Child[%08x]\n", addr, cpid);
	if((r=sys_page_map(thisenv->env_id, (void*)addr, cpid, (void*)addr, PTE_P|PTE_U|PTE_SHARE)) <0){
		("\t\t\tMAPPING of %016x by Parent[%08x] to Child[%016x] FAILED with %e!.\n", addr, thisenv->env_id, cpid, r);
		exit();
	}

	while(true){
		sys_yield();
		sys_yield();
		sys_sleep(60000);
		cprintf("\t\t\tParent[%08x] shared page: \"%s\"\n", thisenv->env_id, (char*)0xa00000);
	}
}

void
umain(int argc, char **argv)
{
	ifork();
}

