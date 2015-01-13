#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>
#include <kern/time.h>
#include <kern/swap.h>
#include <kern/ide.h>
#include <kern/syscall.h>


extern envid_t sleepers[NENV];
extern uint64_t sleep4s[NENV];
extern uint8_t sleepercnt;


extern uintptr_t gdtdesc_64;
static struct Taskstate ts;
extern struct Segdesc gdt[];
extern long gdt_pd;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {0,0};

extern void traphandler_divide();
extern void traphandler_debug();
extern void traphandler_nmi();
extern void traphandler_brkpt();
extern void traphandler_oflow();
extern void traphandler_bound();
extern void traphandler_illop();
extern void traphandler_device();
extern void traphandler_dblflt();
extern void traphandler_tss();
extern void traphandler_segnp();
extern void traphandler_stack();
extern void traphandler_gpflt();
extern void traphandler_pgflt();
extern void traphandler_fperr();
extern void traphandler_align();
extern void traphandler_mchk();
extern void traphandler_simderr();

extern void traphandler_irq0();
extern void traphandler_irq1();
extern void traphandler_irq2();
extern void traphandler_irq3();
extern void traphandler_irq4();
extern void traphandler_irq5();
extern void traphandler_irq6();
extern void traphandler_irq7();
extern void traphandler_irq8();
extern void traphandler_irq9();
extern void traphandler_irq10();
extern void traphandler_irq11();
extern void traphandler_irq12();
extern void traphandler_irq13();
extern void traphandler_irq14();
extern void traphandler_irq15();

extern void traphandler_syscall();

static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < sizeof(excnames)/sizeof(excnames[0]))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}


void
trap_init(void)
{
	extern struct Segdesc gdt[];

	// LAB 3: Your code here.
	SETGATE(idt[T_DIVIDE], 0, GD_KT, traphandler_divide, 0);
	SETGATE(idt[T_DEBUG], 0, GD_KT, traphandler_debug, 0);
	SETGATE(idt[T_NMI], 0, GD_KT, traphandler_nmi, 0);
	SETGATE(idt[T_BRKPT], 0, GD_KT, traphandler_brkpt, 3);
	SETGATE(idt[T_OFLOW], 0, GD_KT, traphandler_oflow, 0);
	SETGATE(idt[T_BOUND], 0, GD_KT, traphandler_bound, 0);
	SETGATE(idt[T_ILLOP], 0, GD_KT, traphandler_illop, 0);
	SETGATE(idt[T_DEVICE], 0, GD_KT, traphandler_device, 0);
	SETGATE(idt[T_DBLFLT], 0, GD_KT, traphandler_dblflt, 0);
	SETGATE(idt[T_TSS], 0, GD_KT, traphandler_tss, 0);
	SETGATE(idt[T_SEGNP], 0, GD_KT, traphandler_segnp, 0);
	SETGATE(idt[T_STACK], 0, GD_KT, traphandler_stack, 0);
	SETGATE(idt[T_GPFLT], 0, GD_KT, traphandler_gpflt, 0);
	SETGATE(idt[T_PGFLT], 0, GD_KT, traphandler_pgflt, 0);
	SETGATE(idt[T_FPERR], 0, GD_KT, traphandler_fperr, 0);
	SETGATE(idt[T_ALIGN], 0, GD_KT, traphandler_align, 0);
	SETGATE(idt[T_MCHK], 0, GD_KT, traphandler_mchk, 0);
	SETGATE(idt[T_SIMDERR], 0, GD_KT, traphandler_simderr, 0);

	SETGATE(idt[IRQ_OFFSET],     0, GD_KT, traphandler_irq0, 0);
	SETGATE(idt[IRQ_OFFSET + 1], 0, GD_KT, traphandler_irq1, 0);
	SETGATE(idt[IRQ_OFFSET + 2], 0, GD_KT, traphandler_irq2, 0);
	SETGATE(idt[IRQ_OFFSET + 3], 0, GD_KT, traphandler_irq3, 0);
	SETGATE(idt[IRQ_OFFSET + 4], 0, GD_KT, traphandler_irq4, 0);
	SETGATE(idt[IRQ_OFFSET + 5], 0, GD_KT, traphandler_irq5, 0);
	SETGATE(idt[IRQ_OFFSET + 6], 0, GD_KT, traphandler_irq6, 0);
	SETGATE(idt[IRQ_OFFSET + 7], 0, GD_KT, traphandler_irq7, 0);
	SETGATE(idt[IRQ_OFFSET + 8], 0, GD_KT, traphandler_irq8, 0);
	SETGATE(idt[IRQ_OFFSET + 9], 0, GD_KT, traphandler_irq9, 0);
	SETGATE(idt[IRQ_OFFSET + 10], 0, GD_KT, traphandler_irq10, 0);
	SETGATE(idt[IRQ_OFFSET + 11], 0, GD_KT, traphandler_irq11, 0);
	SETGATE(idt[IRQ_OFFSET + 12], 0, GD_KT, traphandler_irq12, 0);
	SETGATE(idt[IRQ_OFFSET + 13], 0, GD_KT, traphandler_irq13, 0);
	SETGATE(idt[IRQ_OFFSET + 14], 0, GD_KT, traphandler_irq14, 0);
	SETGATE(idt[IRQ_OFFSET + 15], 0, GD_KT, traphandler_irq15, 0);

	SETGATE(idt[T_SYSCALL], 0, GD_KT, traphandler_syscall, 3);	

    idt_pd.pd_lim = sizeof(idt)-1;
    idt_pd.pd_base = (uint64_t)idt;
	// Per-CPU setup
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// The example code here sets up the Task State Segment (TSS) and
	// the TSS descriptor for CPU 0. But it is incorrect if we are
	// running on other CPUs because each CPU has its own kernel stack.
	// Fix the code so that it works for all CPUs.
	//
	// Hints:
	//   - The macro "thiscpu" always refers to the current CPU's
	//     struct CpuInfo;
	//   - The ID of the current CPU is given by cpunum() or
	//     thiscpu->cpu_id;
	//   - Use "thiscpu->cpu_ts" as the TSS for the current CPU,
	//     rather than the global "ts" variable;
	//   - Use gdt[(GD_TSS0 >> 3) + 2*i] for CPU i's TSS descriptor;
	//   - You mapped the per-CPU kernel stacks in mem_init_mp()
	//
	// ltr sets a 'busy' flag in the TSS selector, so if you
	// accidentally load the same TSS on more than one CPU, you'll
	// get a triple fault.  If you set up an individual CPU's TSS
	// wrong, you may not get a fault until you try to return from
	// user space on that CPU.
	//
	// LAB 4: Your code here:
	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	//ts.ts_esp0 = KSTACKTOP;
	int cpuid=cpunum(), cpu_ts_index = 2*(cpuid<<3);
	thiscpu->cpu_ts.ts_esp0 = KSTACKTOP - (KSTKSIZE + KSTKGAP) * cpuid;

	// Initialize the TSS slot of the gdt.
	//SETTSS((struct SystemSegdesc64 *)((gdt_pd>>16)+40),STS_T64A, (uint64_t) (&ts),sizeof(struct Taskstate), 0);
	SETTSS((struct SystemSegdesc64 *)((gdt_pd>>16)+ 40 + cpu_ts_index),STS_T64A, (uint64_t) (&thiscpu->cpu_ts),sizeof(struct Taskstate), 0);
	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	//ltr(GD_TSS0);
	ltr(GD_TSS0 + cpu_ts_index);

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p from CPU %d\n", tf, cpunum());
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  rip  0x%08x\n", tf->tf_rip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  rsp  0x%08x\n", tf->tf_rsp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  r15  0x%08x\n", regs->reg_r15);
	cprintf("  r14  0x%08x\n", regs->reg_r14);
	cprintf("  r13  0x%08x\n", regs->reg_r13);
	cprintf("  r12  0x%08x\n", regs->reg_r12);
	cprintf("  r11  0x%08x\n", regs->reg_r11);
	cprintf("  r10  0x%08x\n", regs->reg_r10);
	cprintf("  r9  0x%08x\n", regs->reg_r9);
	cprintf("  r8  0x%08x\n", regs->reg_r8);
	cprintf("  rdi  0x%08x\n", regs->reg_rdi);
	cprintf("  rsi  0x%08x\n", regs->reg_rsi);
	cprintf("  rbp  0x%08x\n", regs->reg_rbp);
	cprintf("  rbx  0x%08x\n", regs->reg_rbx);
	cprintf("  rdx  0x%08x\n", regs->reg_rdx);
	cprintf("  rcx  0x%08x\n", regs->reg_rcx);
	cprintf("  rax  0x%08x\n", regs->reg_rax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.

	// Handle spurious interrupts
	// The hardware sometimes raises these because of noise on the
	// IRQ line or other reasons. We don't care.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SPURIOUS) {
		cprintf("Spurious interrupt on irq 7\n");
		print_trapframe(tf);
		return;
	}

	// Handle clock interrupts. Don't forget to acknowledge the
	// interrupt using lapic_eoi() before calling the scheduler!
	// LAB 4: Your code here.

	// Add time tick increment to clock interrupts.
	// Be careful! In multiprocessors, clock interrupts are
	// triggered on every CPU.
	// LAB 6: Your code here.


	// Handle keyboard and serial interrupts.
	// LAB 5: Your code here.

	// Unexpected trap: The user process or the kernel has a bug.
	if (tf->tf_cs != GD_KT){
		switch(tf->tf_trapno){
			case T_PGFLT:
				page_fault_handler(tf);
				break;
			case T_BRKPT:
				monitor(tf);
				break;
			case T_SYSCALL:
				tf->tf_regs.reg_rax =  
					syscall(tf->tf_regs.reg_rax,
							tf->tf_regs.reg_rdx,
							tf->tf_regs.reg_rcx,
							tf->tf_regs.reg_rbx,
							tf->tf_regs.reg_rdi,
							tf->tf_regs.reg_rsi);
				break;
			case IRQ_OFFSET + IRQ_TIMER:
				lapic_eoi();
				time_tick();
                handle_timeouts();
				sched_yield();
				break;
			case IRQ_OFFSET + IRQ_KBD:
				kbd_intr();
				break;
			case IRQ_OFFSET+IRQ_SERIAL:
				serial_intr();
				break;
			default:
				print_trapframe(tf);
				env_destroy(curenv);
		}
	}else{
		// Unexpected trap: The user process or the kernel has a bug.
		switch(tf->tf_trapno){
			case IRQ_OFFSET + IRQ_TIMER:
				lapic_eoi();
				time_tick();
                handle_timeouts();
				sched_yield();
				break;
			case IRQ_OFFSET + IRQ_KBD:
				kbd_intr();
				break;
			case IRQ_OFFSET+IRQ_SERIAL:
				serial_intr();
				break;
			default:
				print_trapframe(tf);
				panic("Unexpected trap in kernel !");}	
	}
}

void
trap(struct Trapframe *tf)
{
    //struct Trapframe *tf = &tf_;
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");

	// Halt the CPU if some other CPU has called panic()
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// Re-acqurie the big kernel lock if we were halted in
	// sched_yield()
	if (xchg(&thiscpu->cpu_status, CPU_STARTED) == CPU_HALTED)
		lock_kernel();
	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
    assert(!(read_eflags() & FL_IF));

	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Acquire the big kernel lock before doing any
		// serious kernel work.
		// LAB 4: Your code here.
		lock_kernel();
		assert(curenv);

		// Garbage collect if current enviroment is a zombie
		if (curenv->env_status == ENV_DYING) {
			env_free(curenv);
			curenv = NULL;
			sched_yield();
		}

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	else
		sched_yield();
}


void
page_fault_handler(struct Trapframe *tf)
{
	uint64_t fault_va, perm = 0;
    pte_t *pte = NULL;
    uint32_t block = 0;
	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();

	// Handle kernel-mode page faults.

	// LAB 3: Your code here.
	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// The trap handler needs one word of scratch space at the top of the
	// trap-time stack in order to return.  In the non-recursive case, we
	// don't have to worry about this because the top of the regular user
	// stack is free.  In the recursive case, this means we have to leave
	// an extra word between the current top of the exception stack and
	// the new stack frame because the exception stack _is_ the trap-time
	// stack.
	//
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	// Note that the grade script assumes you will first check for the page
	// fault upcall and print the "user fault va" message below if there is
	// none.  The remaining three checks can be combined into a single test.
	//
	// Hints:
	//   user_mem_assert() and env_run() are useful here.
	//   To change what the user environment runs, modify 'curenv->env_tf'
	//   (the 'tf' variable points at 'curenv->env_tf').

    /* Handle Page Fault for swapped out Page */
    cprintf("faulted for %016x\n", fault_va);
    if ((pte = pml4e_walk(curenv->env_pml4e, (void *)fault_va, 0)))
    {
		if ((*pte & PTE_SWAP))
        {
	    cprintf("Swapped page %016x faulted for ENV[%08x]\n", fault_va, ENVX(curenv->env_id));
            block = PTE_ADDR(*pte) >> 12;
            perm = (*pte & 0xFFF) & ~PTE_SWAP; 
            assert((block >=  SWAP_BLOCK_MIN) && (block <= SWAP_BLOCK_MAX));
            
            int ret;
            if ((ret = sys_page_alloc(curenv->env_id, (void *)fault_va, perm | PTE_U | PTE_P)) < 0)
                panic("Fault Handler panic for swappable page, page not found\n");
	    cprintf("Inserted swapped page %016x back into ENV[%08x]'s PT\n", fault_va, ENVX(curenv->env_id)); //Inserted in sys page alloc
            
            /* Read the Page back in */
            ide_read(block*BLKSECTS, (void *)fault_va, BLKSECTS);
            
            cprintf("Before Page Lookup\n");
            struct PageInfo *pg = page_lookup(curenv->env_pml4e, (void *)fault_va, &pte);
            cprintf("After Page Lookup\n");
            
            update_shared_page_ptes(block, pg);
            
            if ( !(perm & PTE_COW))
                return;
        }
    }
    
	// LAB 4: Your code here.
    if (curenv->env_pgfault_upcall)
    {
        struct UTrapframe *saved_frame;
        /* Did we fault in the Exception stack itself? */
        if (UXSTACKTOP-PGSIZE <= tf->tf_rsp && tf->tf_rsp < UXSTACKTOP)
        {
            saved_frame  = (struct UTrapframe *)
                (tf->tf_rsp - sizeof(struct UTrapframe) - 8);

        }
        else
        {
            saved_frame = (struct UTrapframe *) 
                (UXSTACKTOP - sizeof(struct UTrapframe));
        }

        /* Exception stack overflow check + No stack check */
        user_mem_assert (curenv, (void *)saved_frame, 1, PTE_U|PTE_W);

        /* Save off the User Context */
        saved_frame->utf_fault_va = fault_va;
        saved_frame->utf_err = tf->tf_err;
        
        saved_frame->utf_regs = tf->tf_regs;
        saved_frame->utf_rip = tf->tf_rip;

        saved_frame->utf_eflags = tf->tf_eflags;
        saved_frame->utf_rsp = tf->tf_rsp;

        /* Jump to Exception Stack */
        curenv->env_tf.tf_rip = (uintptr_t)curenv->env_pgfault_upcall;
        curenv->env_tf.tf_rsp = (uintptr_t)saved_frame;

        env_run (curenv);
    }

	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_rip);
	print_trapframe(tf);
	env_destroy(curenv);
}

