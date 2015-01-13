#include <kern/ide.h>
#include <kern/swap.h>
#include <kern/spinlock.h>

#define DEBUG_SWAP

size_t nrempages = 0;

uint32_t swap_bitmap[(SWAP_BLOCK_MAX-SWAP_BLOCK_MIN)/32 + 1];

static int find_free_swap_block(void);

static inline void init_swap_bitmap()
{
    memset(swap_bitmap, 0xFF, sizeof(swap_bitmap));
}

typedef struct lru_list {
    struct PageInfo *head; 
    struct PageInfo *tail; 
    int size;
} lru_list_t;

lru_list_t lru_list;

inline void init_lru_list(lru_list_t *list)
{
      memset(list, 0, sizeof(lru_list_t));
}

void add_to_lru_list(struct PageInfo *pg)
{
    struct PageInfo *next = NULL;
    cprintf("add_to_lru_list: %016x\n", pg);

    cprintf("LRU Size = %d\n", lru_list.size);
#if defined(DEBUG_SWAP)
    for(next = lru_list.head; next; next = next->lru_next)
        cprintf("%016x ->", next);
    cprintf("\n");
#endif
    assert(pg);
    assert(pg->lru_next == NULL);
    assert(pg->lru_prev == NULL);
    assert(pg->flags ==  PG_SWAPPABLE);

    /* Adjust the List */
    pg->lru_prev = lru_list.tail;

    if (lru_list.tail) {
        (lru_list.tail)->lru_next = pg;
    }
    if (0 == lru_list.size) {
        lru_list.head = pg;
    }

    lru_list.tail = pg;
    lru_list.size += 1;
}

void delete_from_lru_list(struct PageInfo *pg)
{
    cprintf("delete_from_lru_list: %016x\n", pg);

    assert(pg);

    if ((pg->flags != PG_SWAPPABLE))
    {
        cprintf("Non swappable page in LRU list, ignore \n");
        return;
    }

    //assert(pg->lru_next != NULL || pg->lru_prev != NULL);
    
    //cprintf("PG_SWAPPABLE set, pg->lru_prev = %016x, pg->lru_next = %016x\n", pg->lru_prev, pg->lru_next);
    if (pg->lru_prev != NULL) {
        pg->lru_prev->lru_next = pg->lru_next;
    }   
    else {
        lru_list.head = pg->lru_next;
    }   

    if (pg->lru_next != NULL) {
        pg->lru_next->lru_prev = pg->lru_prev;
    }   
    else {
        lru_list.tail = pg->lru_prev;
    }   

    lru_list.size -= 1;

    pg->lru_next = pg->lru_prev = NULL;
}

void move_to_lru_list_tail(struct PageInfo *pg)
{
    cprintf("Moving %016x to the end of the LRU list\n", pg);
    delete_from_lru_list(pg);
    add_to_lru_list(pg);
}

/* Fancy bitmap iterator, part of my tool kit */
int findNextBitSet(uint32_t *map, uint32_t prevBit, uint32_t maxBits)
{
    /* Permit a prevBit of maxBits, but it will always return -1.   */
    /* This will enable use of a "while next bit!=-1" type of loop. */
    assert(prevBit<=maxBits);

    /* Start at the bit just after prevBit, and do an implied
     *     * conversion from 1 based to 0 based.  */

    while (prevBit < maxBits)  {
        if (1<<(prevBit & 0x1f) & map[prevBit>>5] ) {
            if ((prevBit+1) > maxBits)
                return(0xffffffff);
            return(prevBit+1);
        }    
        prevBit++;
    }

    return(0xffffffff);
}

/* Find where the disk block starts */
static int next_free_block = SWAP_BLOCK_MIN;
#define BLOCK_TO_INDEX(block)   ((block) - SWAP_BLOCK_MIN)
uint8_t swapped_page_bitmap[SWAP_BLOCK_MAX-SWAP_BLOCK_MIN][NENV/8];

/* Initialize the swap system */
void swap_init(void)
{
	// Find a JOS disk.  Use the second IDE disk (number 1) if available.
	if (ide_probe_disk1())
		ide_set_disk(1);
	else
		ide_set_disk(0);

	//Test if swap_disk can do IO
    	struct PageInfo *pg = page_alloc(ALLOC_ZERO);
	void *page_start = KADDR(page2pa(pg));
	char *msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	memcpy(page_start,msg, 12);
	int ret = 0;
	int block = 0;
	cprintf("First free block = %d\n", block);
	// Write to Swap Area at the right block
	if (ide_write(block*BLKSECTS, page_start, BLKSECTS))
		panic("flush_block: ide write error");

	if((ret = ide_read(block*BLKSECTS, page_start, BLKSECTS)) <0) //arg0 = starting sector#. i.e, sec#=0 for blkn#=0, sec#=BLKSECTS for blk#=1 etc.
		panic("IDE read in bc failed.");	

	assert(strcmp(msg, (char*)page_start));
	cprintf("Swap disk is GOOD\n");
	cprintf("Swap disk size = %d\n", SWAP_BLOCK_SZ);
	cprintf("Swap starts at   %d\%\n", START_SWAP_AT_PERCENTAGE);
	page_decref(pg);
	free_swap_block(block);
	

	init_lru_list(&lru_list);
	init_swap_bitmap();
}

/* Utility Routine to check if the swap block is free */
static bool is_swap_block_free(uint32_t block)
{
	if ((block <=  SWAP_BLOCK_MIN) || (block >= SWAP_BLOCK_MAX))
        return FALSE;

    uint32_t blockno = BLOCK_TO_INDEX(block);
    if (swap_bitmap[blockno / 32] & (1 << (blockno % 32)))
		return TRUE;
	return FALSE;
}

/* Release the swap block if there are no more references to it */
void release_swap_block_if_needed(uint32_t block, envid_t envid)
{
	int i = 0;
    assert((block >=  SWAP_BLOCK_MIN) && (block <= SWAP_BLOCK_MAX));
    
    int env_pos = ENVX(envid)/8;
    uint32_t blockno = BLOCK_TO_INDEX(block);
    uint8_t *bitmap  = swapped_page_bitmap[blockno];
    
    /* Clear this environment bit map position */
    bitmap[env_pos] &= ~(1<<(ENVX(envid) % 8));
    
    /* Free Swap block if we were the last reference to the swapped out page  */
    if (-1 == (i = findNextBitSet((uint32_t *)swapped_page_bitmap[BLOCK_TO_INDEX(block)], 0, NENV)))
    	swap_bitmap[blockno/32] |= 1<<(blockno%32);
}

/* Mark a block as free in the swap_bitmap */
void free_swap_block(uint32_t block)
{
	assert((block >=  SWAP_BLOCK_MIN) && (block <= SWAP_BLOCK_MAX));
    
    uint32_t blockno = BLOCK_TO_INDEX(block);
	swap_bitmap[blockno/32] |= 1<<(blockno%32);
}

/* Mark a block as occupied in the swap_bitmap */
static void allocate_swap_block(uint32_t block)
{
	assert((block >=  SWAP_BLOCK_MIN) && (block <= SWAP_BLOCK_MAX));
    uint32_t blockno = BLOCK_TO_INDEX(block);

	swap_bitmap[blockno/32] &= ~(1<<(blockno%32));
}
/* Search the swap_bitmap for a free block and allocate it.
 * Return block number allocated on success, -E_NO_SWAP if we are out of blocks.
 */
static int find_free_swap_block(void)
{
	int blkno = next_free_block;

	for (; blkno <= SWAP_BLOCK_MAX; ++blkno)
    {
		if (is_swap_block_free(blkno)) {
			allocate_swap_block(blkno);
            next_free_block = blkno;
			return blkno;
		}
	}
	for (blkno = SWAP_BLOCK_MIN; blkno < next_free_block; ++blkno)
    {
		if (is_swap_block_free(blkno)) {
			allocate_swap_block(blkno);
            next_free_block = blkno;
			return blkno;
		}
	}
    cprintf("Out of Swap \n");
	return -E_NO_SWAP;
}

static struct Env *find_victim_env()
{
    int max_swap_pages = 0, i;
    struct Env *victim = NULL;
    for (i = 0; i < NENV; i++)
    {
        if (ENV_FREE == envs[i].env_status)
            continue;
        else if(envs[i].num_swapped_pages >= max_swap_pages) 
        {
            max_swap_pages = envs[i].num_swapped_pages;
            victim = &envs[i];
        }
    }
    return victim;
}


/* Routine to Obtain a page from the Swapping Subsystem.
 * Called from page alloc when there is no free space in RAM.
 * Takes the Page at the Head of the LRU, writes it to disk 
 * and returns it to the caller.
 */
struct PageInfo * get_page_from_swap_ss()
{
	pte_t *pt;
	uint64_t pdeno, pteno;
	physaddr_t pa;
    struct Env *e;
	int pdeno_limit;
	uint64_t pdpe_index;
    int block, i;
    struct PageInfo *pg = lru_list.head;

    if(NULL == pg)
	    panic("System started swapping before allocating any PTE_SWAPPABLE pages to the LRU list! Minimize Min SWAP at \% threshold.");

    assert(NULL == pg->lru_prev || get_phy_mem_percentage_remaining() < START_SWAP_AT_PERCENTAGE);

    int refcount = pg->pp_ref;
    
    i = findNextBitSet((uint32_t *)pg->env_bitmap, 0, NENV);
    int found = 0;
    for(;refcount!= 0 && i>= 0 && i <= NENV; i = findNextBitSet((uint32_t *)pg->env_bitmap, i, NENV), refcount--)
    {
        e = &envs[i-1];
	cprintf("Walking %dth ENV[%d] %0x\n", i, e->env_id, pg);

        //assert(found == 0);
	assert(e->env_status != ENV_FREE);

        pdpe_t *env_pdpe = KADDR(PTE_ADDR(e->env_pml4e[0]));
        // using 3 instead of NPDPENTRIES as we have only first three indices
        // set for 4GB of address space.
        for(pdpe_index=0; pdpe_index<=3; pdpe_index++)
        {
            if(!(env_pdpe[pdpe_index] & PTE_P))
                continue;
            pde_t *env_pgdir = KADDR(PTE_ADDR(env_pdpe[pdpe_index]));
            pdeno_limit  = pdpe_index==3?PDX(UTOP):PDX(0xFFFFFFFF);
            static_assert(UTOP % PTSIZE == 0);
            for (pdeno = 0; pdeno < pdeno_limit; pdeno++)
            {
                // only look at mapped page tables
                if (!(env_pgdir[pdeno] & PTE_P))
                    continue;
                // find the pa and va of the page table
                pa = PTE_ADDR(env_pgdir[pdeno]);
                pt = (pte_t*) KADDR(pa);

                for (pteno = 0; pteno < PTX(~0); pteno++) 
                {
                    if ((pt[pteno] & PTE_P) && (PTE_ADDR(pt[pteno]) == page2pa(pg)))
                    {
                        void * va = PGADDR((uint64_t)0, pdpe_index, pdeno, pteno, 0);

                        uint64_t perm = (pt[pteno] & 0xFFF) & ~PTE_P;
                        if (0 == found)
                        {
                            /* Found the Page in this environment's Page Table.
                            */
                            while ((block = find_free_swap_block()) < 0)
                            {
                                /* Out of Swap Space, trigger "Out of Memory Killer" */
                                struct Env *victim = find_victim_env();
				                assert(victim);
				                cprintf("Killing ENV[%08x] to free pages\n", ENVX(victim->env_id));
                                env_destroy(victim);
                            }
                            /* Save the shared env. details in the bitmap, so
                             * that it can be referred to while swapping back
                             * in on a page fault
                             */
                            memcpy(swapped_page_bitmap[BLOCK_TO_INDEX(block)], pg->env_bitmap, NENV/8);

                            /* Write to Swap Area at the right block */
                            if (ide_write(block, KADDR(page2pa(pg)), BLKSECTS))
                                panic("flush_block: ide write error");
            
                            /* Flush TLB if needed etc. */ 
                            tlb_invalidate(e->env_pml4e, va);

                            found = 1;
                        }

                        /* Store the Swap Block Identifier in the PTE */
                        pt[pteno] = ((uint64_t )block << 12) | perm | PTE_SWAP;

	                    cprintf("Page %016x from ENV[%08x] swapped to disk\n", pg, ENVX(e->env_id));        
			e->num_swapped_pages++;

                        goto again;
                    }
                }
            }
        }
again:   ; 
    }
    delete_from_lru_list(pg);
    return pg;
}

/* Routine to Fix up the PTE entries of all processes which had the 
 * swapped out page in their PTEs.
 * This is done when the Page is swapped back in.
 * Called as part of Page Fault Handling of a Swapped out page. 
 */
void update_shared_page_ptes(int block, struct PageInfo *pg)
{
	pte_t *pt;
	uint64_t pdeno, pteno;
	physaddr_t pa;
    struct Env *e;
	int pdeno_limit;
	uint64_t pdpe_index;
    int i;
    int cur_envx = ENVX(curenv->env_id); /* Exclude current process */
    
    i = findNextBitSet((uint32_t *)swapped_page_bitmap[BLOCK_TO_INDEX(block)], 0, NENV);
    
    for(;i>= 0 && i <= NENV; i = findNextBitSet((uint32_t *)swapped_page_bitmap[BLOCK_TO_INDEX(block)], i, NENV))
    {
        /* We have already fixed up this environment's PTE */
        if (i-1 == cur_envx)
            continue;

        e = &envs[i-1];

        pdpe_t *env_pdpe = KADDR(PTE_ADDR(e->env_pml4e[0]));
        // using 3 instead of NPDPENTRIES as we have only first three indices
        // set for 4GB of address space.
        for(pdpe_index=0; pdpe_index<=3; pdpe_index++)
        {
            if(!(env_pdpe[pdpe_index] & PTE_P))
                continue;
            pde_t *env_pgdir = KADDR(PTE_ADDR(env_pdpe[pdpe_index]));
            pdeno_limit  = pdpe_index==3?PDX(UTOP):PDX(0xFFFFFFFF);
            static_assert(UTOP % PTSIZE == 0);
            for (pdeno = 0; pdeno < pdeno_limit; pdeno++)
            {
                // only look at mapped page tables
                if (!(env_pgdir[pdeno] & PTE_P))
                    continue;
                // find the pa and va of the page table
                pa = PTE_ADDR(env_pgdir[pdeno]);
                pt = (pte_t*) KADDR(pa);

                for (pteno = 0; pteno < PTX(~0); pteno++) 
                {
                    if ((pt[pteno] & PTE_SWAP) && (PTE_ADDR(pt[pteno]) == block))
                    {
			            cprintf("Inserting shared swapped page %08x back into ENV[%08x]'s PT", pg, ENVX(e->env_id));
                        uint64_t perm = (pt[pteno] & 0xFFF) & ~PTE_SWAP;

                        /* Store the Physical Address in the PTE */
                        pt[pteno] = PTE_ADDR(page2pa(pg)) | perm | PTE_P;

                        e->num_swapped_pages--;

                        goto again;
                    }
                }
            }
        }
again:  ;     
    }
    memset(swapped_page_bitmap[BLOCK_TO_INDEX(block)], 0, NENV/8);
    free_swap_block(block);
    move_to_lru_list_tail(pg);
}

/* Called by the Swapper Kernel Thread every few seconds
 * to update the LRU list. 
 */
void update_lru_page_list()
{
	pte_t *pt;
	uint64_t pdeno, pteno;
	physaddr_t pa;
    struct Env *e;
	int pdeno_limit, i;
	uint64_t pdpe_index;
    struct PageInfo *pg = NULL;

    for (i = 0; i < NENV; i++)
    {
        if ( ENV_FREE == envs[i].env_status || ENV_TYPE_USER != envs[i].env_type )
            continue;

        cprintf("Checking ENV[%08x] to update LRU list...\n", i);

        /* Walk the Page Table of Each Environment, updating the LRU if a page
         * which was not used recently was found 
         */
        pdpe_t *env_pdpe = KADDR(PTE_ADDR(envs[i].env_pml4e[0]));
        // using 3 instead of NPDPENTRIES as we have only first three indices
        // set for 4GB of address space.
        for(pdpe_index=0; pdpe_index<=3; pdpe_index++)
        {
            if(!(env_pdpe[pdpe_index] & PTE_P))
                continue;
            
            pde_t *env_pgdir = KADDR(PTE_ADDR(env_pdpe[pdpe_index]));
            pdeno_limit  = pdpe_index==3?PDX(UTOP):PDX(0xFFFFFFFF);
            static_assert(UTOP % PTSIZE == 0);
            
            for (pdeno = 0; pdeno < pdeno_limit; pdeno++)
            {
                // only look at mapped page tables
                if (!(env_pgdir[pdeno] & PTE_P))
                    continue;
                // find the pa and va of the page table
                pa = PTE_ADDR(env_pgdir[pdeno]);
                pt = (pte_t*) KADDR(pa);

                for (pteno = 0; pteno < PTX(~0); pteno++) 
                {
                    if (pt[pteno] & PTE_P)
                    {
                        if (pt[pteno] & PTE_A)
                        {
                            /* Freshly accessed, move to the end of the LRU list */
                            pg = pa2page(PTE_ADDR(pt[pteno]));
                            if (pg->flags & PG_SWAPPABLE)
                                move_to_lru_list_tail(pg);
                            pt[pteno] &= ~PTE_A;
                        }
                    }
                }
            }
        }
    }
}

size_t get_phy_mem_percentage_remaining(){
	return (100*nrempages/npages);
}

void swapper()
{
    lock_kernel();
    cprintf("kernel Thread:[%08x] : swapper \n", curenv->env_id);
    update_lru_page_list();
    cprintf("Done updating LRU list \n");
    cprintf("PHY MEMORY REMAINING = %d\%\n", get_phy_mem_percentage_remaining());
    sys_sleep(SWAP_INTERVAL_MS);
}

