/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/syscall.h>
#include <kern/console.h>
#include <kern/sched.h>
#include <kern/time.h>
#include <kern/e1000.h>

// Print a string to the system console.
// The string is exactly 'len' characters long.
// Destroys the environment on memory errors.
static void
sys_cputs(const char *s, size_t len)
{
	// Check that the user has permission to read memory [s, s+len).
	// Destroy the environment if not.
	user_mem_assert(curenv, (const void *)s, len, PTE_U);

	// LAB 3: Your code here.
	user_mem_assert(curenv, (const void *)s, len, PTE_U);
	// Print the string supplied by the user.
	cprintf("%.*s", len, s);
}

// Read a character from the system console without blocking.
// Returns the character, or 0 if there is no input waiting.
static int
sys_cgetc(void)
{
	return cons_getc();
}

// Returns the current environment's envid.
static envid_t
sys_getenvid(void)
{
	return curenv->env_id;
}

// Destroy a given environment (possibly the currently running environment).
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_destroy(envid_t envid)
{
	int r;
	struct Env *e;

	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;
	env_destroy(e);
	return 0;
}

// Deschedule current environment and pick a different one to run.
static void
sys_yield(void)
{
	sched_yield();
}

// Allocate a new environment.
// Returns envid of new environment, or < 0 on error.  Errors are:
//	-E_NO_FREE_ENV if no free environment is available.
//	-E_NO_MEM on memory exhaustion.
static envid_t
sys_exofork(void)
{
	// Create the new environment with env_alloc(), from kern/env.c.
	// It should be left as env_alloc created it, except that
	// status is set to ENV_NOT_RUNNABLE, and the register set is copied
	// from the current environment -- but tweaked so sys_exofork
	// will appear to return 0.

	// LAB 4: Your code here.
    int r = 0;
    struct Env *new_env;

    if ((r = env_alloc(&new_env, curenv->env_id)) < 0)
        return r;

    assert(new_env);
    // Copy over the tf from the parent
    new_env->env_tf = curenv->env_tf;
    // Set the return value to 0
    new_env->env_tf.tf_regs.reg_rax = 0;
    // Misc. settings
    new_env->env_parent_id = curenv->env_id;
    new_env->env_status = ENV_NOT_RUNNABLE;

    return (new_env->env_id);
}

// Set envid's env_status to status, which must be ENV_RUNNABLE
// or ENV_NOT_RUNNABLE.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if status is not a valid status for an environment.
static int
sys_env_set_status(envid_t envid, int status)
{
	// Hint: Use the 'envid2env' function from kern/env.c to translate an
	// envid to a struct Env.
	// You should set envid2env's third argument to 1, which will
	// check whether the current environment has permission to set
	// envid's status.

	// LAB 4: Your code here.
    int r = 0;
    struct Env *env;

    if ((ENV_RUNNABLE != status) && (ENV_NOT_RUNNABLE != status))
        return -E_INVAL;

    if ((r = envid2env(envid, &env, 1)) < 0)
        return r;

    assert(env);
    env->env_status = status;
    return 0;
}

// Set envid's trap frame to 'tf'.
// tf is modified to make sure that user environments always run at code
// protection level 3 (CPL 3) with interrupts enabled.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_trapframe(envid_t envid, struct Trapframe *tf)
{
	// LAB 5: Your code here.
	// Remember to check whether the user has supplied us with a good
	// address!
	struct Env* e = NULL;
	int r;
	if((r = envid2env(envid, &e, 1)) < 0)
		return r;

	assert(e);
	memcpy(&(e->env_tf), tf, sizeof(struct Trapframe));
	e->env_tf.tf_ds = GD_UD | 3;
	e->env_tf.tf_es = GD_UD | 3;
	e->env_tf.tf_ss = GD_UD | 3;
	e->env_tf.tf_cs = GD_UT | 3;

	e->env_tf.tf_eflags |= FL_IF; //Enable interrupts
	return 0;
	//panic("sys_env_set_trapframe not implemented");
}

// Set the page fault upcall for 'envid' by modifying the corresponding struct
// Env's 'env_pgfault_upcall' field.  When 'envid' causes a page fault, the
// kernel will push a fault record onto the exception stack, then branch to
// 'func'.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_pgfault_upcall(envid_t envid, void *func)
{
	// LAB 4: Your code here.
    int ret = 0;
	struct Env *e;
	if ((ret = envid2env(envid, &e, 1)) < 0)
		return ret;
    e->env_pgfault_upcall = func;
        return ret;
}

// Allocate a page of memory and map it at 'va' with permission
// 'perm' in the address space of 'envid'.
// The page's contents are set to 0.
// If a page is already mapped at 'va', that page is unmapped as a
// side effect.
//
// perm -- PTE_U | PTE_P must be set, PTE_AVAIL | PTE_W may or may not be set,
//         but no other bits may be set.  See PTE_SYSCALL in inc/mmu.h.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
//	-E_INVAL if perm is inappropriate (see above).
//	-E_NO_MEM if there's no memory to allocate the new page,
//		or to allocate any necessary page tables.
int
sys_page_alloc(envid_t envid, void *va, int perm)
{
	// Hint: This function is a wrapper around page_alloc() and
	//   page_insert() from kern/pmap.c.
	//   Most of the new code you write should be to check the
	//   parameters for correctness.
	//   If page_insert() fails, remember to free the page you
	//   allocated!

	// LAB 4: Your code here.
	int err = -E_INVAL;
	struct Env *e;
	struct PageInfo *pp;

	//if ((perm & ~(PTE_SYSCALL)) || ((perm & (PTE_U | PTE_P)) != (PTE_U | PTE_P)))
	//	return err;

	if (((uintptr_t)va >= UTOP) || PGOFF(va))
		return err;

	if ((err = envid2env(envid, &e, 1)) < 0)
		return err;

	assert(e->env_pml4e);

	if ( NULL == (pp = page_alloc(ALLOC_ZERO|PG_SWAPPABLE)))
	{
		return err;
	}

	cprintf("Inserting %016x into ENV[%08x]'s Page Table\n", page2pa(pp), e->env_id);
	if ((err = page_insert_env(e->env_id, e->env_pml4e, pp, va, perm)) < 0)
	{
		page_decref(pp);
		return err;
	}

	//cprintf("Page allocated @VA[%x] has perm %x\n", (uint64_t*)va,perm);
	return 0;
}

// Map the page of memory at 'srcva' in srcenvid's address space
// at 'dstva' in dstenvid's address space with permission 'perm'.
// Perm has the same restrictions as in sys_page_alloc, except
// that it also must not grant write access to a read-only
// page.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if srcenvid and/or dstenvid doesn't currently exist,
//		or the caller doesn't have permission to change one of them.
//	-E_INVAL if srcva >= UTOP or srcva is not page-aligned,
//		or dstva >= UTOP or dstva is not page-aligned.
//	-E_INVAL is srcva is not mapped in srcenvid's address space.
//	-E_INVAL if perm is inappropriate (see sys_page_alloc).
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in srcenvid's
//		address space.
//	-E_NO_MEM if there's no memory to allocate any necessary page tables.
static int
sys_page_map(envid_t srcenvid, void *srcva,
	     envid_t dstenvid, void *dstva, int perm)
{
	// Hint: This function is a wrapper around page_lookup() and
	//   page_insert() from kern/pmap.c.
	//   Again, most of the new code you write should be to check the
	//   parameters for correctness.
	//   Use the third argument to page_lookup() to
	//   check the current permissions on the page.

	// LAB 4: Your code here.
	int err = -E_INVAL;
	struct Env *src_envid_ptr = NULL, *dst_envid_ptr = NULL;
    struct PageInfo *page = NULL;
    pte_t *pte = NULL;

    #define	PTE_SHARE	0x400
    if (perm & ~(PTE_U | PTE_P | PTE_AVAIL | PTE_W | PTE_SHARE))
	    return err;

    if (((uintptr_t)srcva >= UTOP) || PGOFF(srcva) || ((uintptr_t)dstva >= UTOP) || PGOFF(dstva))
        return err;

	if (((err = envid2env(srcenvid, &src_envid_ptr, 1)) < 0) ||
	    ((err = envid2env(dstenvid, &dst_envid_ptr, 1)) < 0))
		return err;

    if (NULL == (page = page_lookup(src_envid_ptr->env_pml4e, (void *)srcva, &pte)))
        return -E_INVAL;

    if ((perm & PTE_W) && !(*pte & PTE_W))
        return -E_INVAL;
    
    if ((err = page_insert_env(dst_envid_ptr->env_id, dst_envid_ptr->env_pml4e, page, (void *)dstva, perm)) < 0)
        return err;

    return 0;
}

// Unmap the page of memory at 'va' in the address space of 'envid'.
// If no page is mapped, the function silently succeeds.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
static int
sys_page_unmap(envid_t envid, void *va)
{
	// Hint: This function is a wrapper around page_remove().
	// LAB 4: Your code here.
	int r;
	struct Env *e;

    if ((uintptr_t)va >= UTOP || PGOFF(va))
        return -E_INVAL;

	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;

    if (e->env_pml4e)
        page_remove_env(envid, e->env_pml4e, va);

    return 0;
}

// Try to send 'value' to the target env 'envid'.
// If srcva < UTOP, then also send page currently mapped at 'srcva',
// so that receiver gets a duplicate mapping of the same page.
//
// The send fails with a return value of -E_IPC_NOT_RECV if the
// target is not blocked, waiting for an IPC.
//
// The send also can fail for the other reasons listed below.
//
// Otherwise, the send succeeds, and the target's ipc fields are
// updated as follows:
//    env_ipc_recving is set to 0 to block future sends;
//    env_ipc_from is set to the sending envid;
//    env_ipc_value is set to the 'value' parameter;
//    env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.
// The target environment is marked runnable again, returning 0
// from the paused sys_ipc_recv system call.  (Hint: does the
// sys_ipc_recv function ever actually return?)
//
// If the sender wants to send a page but the receiver isn't asking for one,
// then no page mapping is transferred, but no error occurs.
// The ipc only happens when no errors occur.
//
// Returns 0 on success, < 0 on error.
// Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist.
//		(No need to check permissions.)
//	-E_IPC_NOT_RECV if envid is not currently blocked in sys_ipc_recv,
//		or another environment managed to send first.
//	-E_INVAL if srcva < UTOP but srcva is not page-aligned.
//	-E_INVAL if srcva < UTOP and perm is inappropriate
//		(see sys_page_alloc).
//	-E_INVAL if srcva < UTOP but srcva is not mapped in the caller's
//		address space.
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in the
//		current environment's address space.
//	-E_NO_MEM if there's not enough memory to map srcva in envid's
//		address space.
static int
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{
	// LAB 4: Your code here.
    int ret;
    struct Env *env;
    struct PageInfo *page = NULL;
    pte_t *pte = NULL;

    //cprintf("[sys_ipc_try_send] : envid = [%08x]\n", envid);

	if ((ret = envid2env(envid, &env, 0)) < 0)
		return ret;

    //cprintf("[sys_ipc_try_send] : Env Status = %d\n", env->env_status);
    //cprintf("[sys_ipc_try_send] : env_ipc_recving = %d\n", env->env_ipc_recving);
   
    if( env->env_status!= ENV_NOT_RUNNABLE || !env->env_ipc_recving)
        return -E_IPC_NOT_RECV;

    cprintf("[sys_ipc_try_send] : Writing to env\n");
    if (((uintptr_t)srcva < UTOP) && ((uintptr_t)env->env_ipc_dstva < UTOP))
    {
        if (((perm & ~(PTE_SYSCALL)) || ((perm & (PTE_U | PTE_P)) != (PTE_U | PTE_P))) ||
                PGOFF(srcva))
            return -E_INVAL;

        if (NULL == (page = page_lookup(curenv->env_pml4e, (void *)srcva, &pte)))
            return -E_INVAL;

        if ((perm & PTE_W) && !(*pte & PTE_W))
            return -E_INVAL;

        if ((ret = page_insert_env(env->env_id, env->env_pml4e, page, (void *)env->env_ipc_dstva, perm)) < 0)
            return ret;
        
        env->env_ipc_perm = perm;;
    }
    else
    {
        //  env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.
        env->env_ipc_perm = 0;
    }
    //  env_ipc_recving is set to 0 to block future sends;
    env->env_ipc_recving = 0;
    //  env_ipc_from is set to the sending envid;
    env->env_ipc_from = curenv->env_id;
    //  env_ipc_value is set to the 'value' parameter;
    //cprintf("[sys_ipc_try_send] : IPC value=%d\n", value);
    env->env_ipc_value = value;
   
    // Set the return value to 0
    env->env_tf.tf_regs.reg_rax = 0;
    
    env->env_status = ENV_RUNNABLE;

    return 0;
}

// Block until a value is ready.  Record that you want to receive
// using the env_ipc_recving and env_ipc_dstva fields of struct Env,
// mark yourself not runnable, and then give up the CPU.
//
// If 'dstva' is < UTOP, then you are willing to receive a page of data.
// 'dstva' is the virtual address at which the sent page should be mapped.
//
// This function only returns on error, but the system call will eventually
// return 0 on success.
// Return < 0 on error.  Errors are:
//	-E_INVAL if dstva < UTOP but dstva is not page-aligned.
static int
sys_ipc_recv(void *dstva)
{
	// LAB 4: Your code here.
    if (((uintptr_t)dstva < UTOP) && PGOFF((uintptr_t)dstva))
        return -E_INVAL;
    else
        curenv->env_ipc_dstva = dstva;

    curenv->env_ipc_recving = 1;
    curenv->env_ipc_from = 0;
    curenv->env_status = ENV_NOT_RUNNABLE;

    return 0;
}

//LAB 7
envid_t sleepers[NENV];
uint64_t sleep4s[NENV];
int sleepercnt=-1;

void handle_timeouts()
{
	int i = -1;
	while(i++ < sleepercnt)
    {
		if(sleep4s[i] <=0)
        {
            struct Env *env;
            envid2env(sleepers[i], &env, 0);
            env->env_status = ENV_RUNNABLE;
            sleepers[i] = sleepers[sleepercnt];
            sleep4s[i] = sleep4s[sleepercnt];
            i--;
			sleepercnt--;
		}else{  
			sleep4s[i]--;
		}
	}
}
// Sleep for msecs
int
sys_sleep(uint64_t sleep4)
{
	curenv->env_status = ENV_NOT_RUNNABLE;
	sleepers[++sleepercnt] = curenv->env_id;
	sleep4s[sleepercnt] = sleep4 / 10; //1 ticks = 10ms
    //cprintf("Done with sys_sleep\n");
    sched_yield();
    return 0;
}


// Return the current time.
static int
sys_time_msec(void)
{
	// LAB 6: Your code here.
    return (time_msec());	
}

static int
sys_send_pkt(char *s, size_t len)
{
    if( len > MAX_ETHER_MTU)
        return -E_INVAL;
	
    // Check that the user has permission to read memory [s, s+len).
	// Destroy the environment if not.
	user_mem_assert(curenv, s, len, PTE_U);

    return(e1000_tx_pkt(s, (uint32_t)len));
}

static int
sys_recv_pkt(char *s)
{
    // Check that the user has permission to access upto Max MTU.
    // Destroy the environment if not.
    user_mem_assert(curenv, s, MAX_ETHER_MTU, PTE_U);

    return(e1000_rx_pkt(s));
}

// Dispatches to the correct kernel function, passing the arguments.
int64_t
syscall(uint64_t syscallno, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5)
{
	// Call the function corresponding to the 'syscallno' parameter.
	// Return any appropriate return value.
	// LAB 3: Your code here.


	switch (syscallno) {
		case SYS_cputs:
			sys_cputs((char *)a1, a2);
			return 0;
		case SYS_cgetc:
			return(sys_cgetc());
		case SYS_getenvid:
			return(sys_getenvid());
		case SYS_env_destroy:
			return(sys_env_destroy(a1));
		case SYS_yield:
			sys_yield();
			return 0;
		case SYS_exofork:
			return(sys_exofork());
		case SYS_env_set_status:
			return(sys_env_set_status((envid_t)a1, a2));
		case SYS_page_alloc:
			return(sys_page_alloc(a1, (void *)a2, a3));
		case SYS_page_map:
			return(sys_page_map(a1, (void *)a2, a3, (void *)a4, a5));
		case SYS_page_unmap:
			return(sys_page_unmap(a1, (void *)a2));
		case SYS_env_set_pgfault_upcall:
			return(sys_env_set_pgfault_upcall(a1, (void *)a2));
		case SYS_ipc_try_send:
			return(sys_ipc_try_send(a1, a2, (void *)a3, a4));
		case SYS_ipc_recv:
			return(sys_ipc_recv((void *)a1));
		case SYS_time_msec:
			return(sys_time_msec());
		case SYS_env_set_trapframe:
			return(sys_env_set_trapframe(a1, (struct Trapframe *)a2));
		case SYS_send_pkt:
			return(sys_send_pkt((char *)a1, a2));
		case SYS_recv_pkt:
			return(sys_recv_pkt((char *)a1));
		case SYS_sleep:
			return(sys_sleep((uint64_t)a1));
		default:
			return -E_INVAL;
	}   
}

