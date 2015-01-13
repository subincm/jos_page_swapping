#include <inc/lib.h>
#include <lib/syscall.c>

#define SLEEP_FOR 10
#define N_CHILDREN 1

    void
ifork()
{
    int nchildren = N_CHILDREN;
    int cpids[N_CHILDREN];
    int r = 0, i=0;
    uint64_t addr = 0xa00000;
    char *msg = "Hi There, still here\n";

#if 0    
    if(nchildren > 0){
        if ((cpids[N_CHILDREN - nchildren--]=fork()) == 0) {
            while(true){
                cprintf("\t\t\tChild ENV[%08x] Running...\n", thisenv->env_id);
                sys_sleep(SLEEP_FOR);
                cprintf("\t\t\tChild ENV[%08x] done sleeping.\n", thisenv->env_id);		
                if ((r = sys_page_alloc(0, (void*)addr, PTE_P|PTE_U|PTE_W)) < 0){
                    cprintf("\t\t\tALLOC of %016x by Child[%08x] FAILED with %e!.\n", addr, thisenv->env_id, r);
                    exit();
                }

                cprintf("\t\t\tALLOC of %016x by Child[%08x] done.\n", addr, thisenv->env_id);
                addr+=PGSIZE;
            }
        }
    }
#endif

//#define MAX_ALLOC 2500
#define MAX_ALLOC 2500

    uint64_t tmp = addr;
    int count = 0; 
    while(true){
        count++;
        cprintf("\t\t\tENV[%08x] Running...\n", thisenv->env_id);
        sys_sleep(SLEEP_FOR);
        cprintf("\t\t\tENV[%08x] done sleeping.\n", thisenv->env_id);		
        if ((r = sys_page_alloc(0, (void*)addr, PTE_P|PTE_U|PTE_W)) < 0){
            cprintf("\t\t\tALLOC of %016x by ENV[%08x] FAILED with %e!.\n", addr, thisenv->env_id, r);
            exit();
        }
        if ((addr == tmp) || ((addr >  tmp) && (addr < (tmp +MAX_ALLOC*PGSIZE))))
            strncpy((char *)addr, msg, strlen(msg)+1);

        if(count == MAX_ALLOC)
        {
            if((strcmp((char *)tmp, msg) == 0) || strcmp((char *)tmp+PGSIZE, msg) == 0) 
            {
                cprintf("Data consistent across Swap\n");
                exit();
            }
            else
            {
                cprintf("Data inconsistent across Swap\n");
                exit();
            }
        }

        cprintf("\t\t\tALLOC of %016x by ENV[%08x] done.\n", addr, thisenv->env_id);
        addr+=PGSIZE;
    }
}

void
umain(int argc, char **argv)
{
	ifork();
}

