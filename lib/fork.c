// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#ifndef PTE_COW
#define PTE_COW		0x800
#endif /* PTE_COW */

extern void _pgfault_upcall (void);
//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	//cprintf("fault @%16x\n", (char*)addr);
	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.

	// LAB 4: Your code here.
    //cprintf("pgfault(): Handling for VA=%016x", addr);
    
    if (!(err & FEC_WR))
    {
	cprintf("RIP = %016x\n", utf->utf_rip);
	cprintf("RSP = %016x\n", utf->utf_rsp);
	cprintf("RSP = %016x\n", utf->utf_regs.reg_rbp);
    cprintf("saved sp = %016x\n", *(((uint64_t *)utf->utf_regs.reg_rbp)));
    cprintf("saved return ip = %016x\n", *(((uint64_t *)utf->utf_regs.reg_rbp)+1));
       panic("pgfault(): faulting access wasn't a write, VA=%016x", addr);
     } 
    if (!(uvpt[PGNUM(addr)] & PTE_COW))
        panic("pgfault(): on a non COW page, va = %016x, UXSTACKTOP = %016x", addr, UXSTACKTOP-PGSIZE);

    if ((r = sys_page_alloc (0, (void *)PFTEMP, PTE_U|PTE_W|PTE_P) < 0))
        panic("pgfault(): sys_page_alloc failed: %e", r);

    addr = ROUNDDOWN(addr,PGSIZE);
    
    memmove (PFTEMP, addr, PGSIZE);

    if ((r = sys_page_map (0, PFTEMP, 0, addr, PTE_U|PTE_W|PTE_P)) < 0)
        panic("pgfault(): sys_page_map failed: %e", r);
    
    if ((r = sys_page_unmap(0, PFTEMP)) < 0)
        panic("pgfault(): sys_page_unmap failed: %e", r);
}
//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
    int ret;
    void *va = (void *)((uintptr_t)pn*PGSIZE);

    if ((uvpt[pn] & (PTE_W | PTE_COW)) && (!(uvpt[pn] & PTE_SHARE)))
    {
        if ((ret = sys_page_map(0, va, envid, va, PTE_U|PTE_COW|PTE_P)) < 0)
        {
            return ret;
        }
        
        if ((ret = sys_page_map(0, va, 0, va, PTE_U|PTE_COW|PTE_P)) < 0)
        {
            return ret;
        }
    }
    else
    {
	int perm = PTE_U|PTE_P;
	if (uvpt[pn] & PTE_SHARE)
		perm = uvpt[pn] & PTE_SYSCALL;
        if ((ret = sys_page_map(0, va, envid, va, perm)) < 0)
        {
            return ret;
        }
    }
    return ret;
}
//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	envid_t envid;
	int ret;
	uintptr_t addr;
	extern unsigned char end[];

	set_pgfault_handler(pgfault);

	envid = sys_exofork();
	if (envid < 0)
		panic("sys_exofork: %e", envid);

	if (envid == 0) {
		// We're the child.
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}

	// We're the parent.
	// LAB 4: Your code here.
    for (addr = UTEXT; addr < UXSTACKTOP - PGSIZE; addr += PGSIZE) {
	    if ((uvpml4e[VPML4E(addr)] & PTE_P) &&
			    (uvpde[VPDPE(addr)] & PTE_P) && 
			    (uvpd[VPD(addr)] & PTE_P) && 
			    (uvpt[PGNUM(addr)] & PTE_P) && 
			    (uvpt[PGNUM(addr)] & PTE_U))
		{
		   //if (uvpt[PGNUM(addr)] & PTE_SHARE)
			//	cprintf("shared page: %016x\n", addr);
		    if ( (ret = duppage (envid, PGNUM(addr))) < 0)
		    {
			    sys_env_destroy(envid);
			    return ret;
		    }
		}
    }

    if ( (ret = sys_page_alloc (envid, (void *)(UXSTACKTOP - PGSIZE), 
                    PTE_U|PTE_W|PTE_P)) < 0)
    {
        sys_env_destroy(envid);
        return ret;
    }
    
    sys_env_set_pgfault_upcall (envid, _pgfault_upcall);

    if ( (ret = sys_env_set_status(envid, ENV_RUNNABLE)) < 0)
    {
        sys_env_destroy(envid);
        return ret;
    }
    
    return envid;
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
