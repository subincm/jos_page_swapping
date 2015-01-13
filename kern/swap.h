#ifndef JOS_INC_SWAP_H
#define JOS_INC_SWAP_H
#include <kern/syscall.h>
#include <kern/pmap.h>
#include <kern/env.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/types.h>
#include <inc/string.h>
#include <inc/error.h>

#define SWAP_INTERVAL_MS    1000 
#define START_SWAP_AT_PERCENTAGE 70
//#define START_SWAP_AT_PERCENTAGE 86
#define SWAP_BLOCK_MIN 0
//#define SWAP_BLOCK_SZ 1
#define SWAP_BLOCK_SZ (128*1024)
#define SWAP_BLOCK_MAX  (SWAP_BLOCK_MIN + SWAP_BLOCK_SZ) /* 512 MB, twice the Max JOS RAM */

#define BLKSIZE PGSIZE
#define FALSE 0
#define TRUE  1

void swapper();
void swap_init(void);
void add_to_lru_list(struct PageInfo *pg);
void delete_from_lru_list(struct PageInfo *pg);
void move_to_lru_list_tail(struct PageInfo *pg);
struct PageInfo * get_page_from_swap_ss();
void free_swap_block(uint32_t block);
void release_swap_block_if_needed(uint32_t block, envid_t envid);
void update_shared_page_ptes(int block, struct PageInfo *pg);
size_t get_phy_mem_percentage_remaining();
#endif /* JOS_INC_SWAP_H */
