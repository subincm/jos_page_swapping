
#include "fs.h"


//LAB 5: CHALLENGE
// Flush the contents of the block containing VA out to disk if
// necessary, then clear the PTE_D bit using sys_page_map.
// If the block is not in the block cache or is not dirty, does
// nothing.
void flush_block(void *addr)
{
	uint64_t blockno = ((uint64_t)addr - DISKMAP) / BLKSIZE;

	if (addr < (void*)DISKMAP || addr >= (void*)(DISKMAP + DISKSIZE))
		panic("flush_block bad va %08x", addr);

	void *va = ROUNDDOWN(addr, BLKSIZE);
	pte_t pte = uvpt[PGNUM(va)];

	if (!((uvpt[PDX(va)] & PTE_P) && (uvpt[PGNUM(va)] & PTE_P)) || !((uvpt[PGNUM(va)] & PTE_D) != 0))
		return;

	uint64_t secno = blockno * BLKSECTS;
	if (ide_write(secno, va, BLKSECTS))
		panic("flush_block: ide write error");

	if (sys_page_map(0, va, 0, va, pte & PTE_SYSCALL))
		panic("flush_block: map error");
}

// Return the virtual address of this disk block.
void*
diskaddr(uint64_t blockno)
{
	if (blockno == 0 || (super && blockno >= super->s_nblocks))
		panic("bad block number %08x in diskaddr", blockno);
	return (char*) (DISKMAP + blockno * BLKSIZE);
}

// Fault any disk block that is read in to memory by
// loading it from disk.
static void
bc_pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint64_t blockno = ((uint64_t)addr - DISKMAP) / BLKSIZE;
	int r;

	// Check that the fault was within the block cache region
	if (addr < (void*)DISKMAP || addr >= (void*)(DISKMAP + DISKSIZE))
		panic("page fault in FS: eip %08x, va %08x, err %04x",
		      utf->utf_rip, addr, utf->utf_err);

	// Sanity check the block number.
	if (super && blockno >= super->s_nblocks)
		panic("reading non-existent block %08x\n", blockno);

	// Allocate a page in the disk map region, read the contents
	// of the block from the disk into that page.
	// Hint: first round addr to page boundary.
	//
	// LAB 5: you code here:
	void* vastart = ROUNDDOWN(addr, BLKSIZE);
	int ret;
	if((ret=sys_page_alloc(0, vastart, PTE_P | PTE_U | PTE_W) < 0))
		panic("Allocation of page in bc failed.");
	if((ret = ide_read(blockno*BLKSECTS, vastart, BLKSECTS)) <0) //arg0 = starting sector#. i.e, sec#=0 for blkn#=0, sec#=BLKSECTS for blk#=1 etc.
		panic("IDE read in bc failed.");	
}


void
bc_init(void)
{
	struct Super super;
	set_pgfault_handler(bc_pgfault);

	// cache the super block by reading it once
	memmove(&super, diskaddr(1), sizeof super);
}

