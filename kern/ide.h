#ifndef JOS_INC_IDE_H
#define JOS_INC_IDE_H
#include <inc/types.h>
#include <inc/assert.h>
#include <inc/types.h>
#include <inc/string.h>
#include <inc/error.h>

#define SECTSIZE	512			// bytes per disk sector
#define BLKSECTS	(BLKSIZE / SECTSIZE)	// sectors per block

/* Disk block n, when in memory, is mapped into the file system
 * server's address space at DISKMAP + (n*BLKSIZE). */
#define DISKMAP		0x10000000

/* Maximum disk size we can handle (3GB) */
#define DISKSIZE	0xC0000000

struct Super *super;		// superblock
uint32_t *bitmap;		// bitmap blocks mapped in memory

/* ide.c */
bool	ide_probe_disk1(void);
void	ide_set_disk(int diskno);
int	ide_read(uint32_t secno, void *dst, size_t nsecs);
int	ide_write(uint32_t secno, const void *src, size_t nsecs);

/* int	map_block(uint32_t); */
bool	block_is_free(uint32_t blockno);
int	alloc_block(void);

#endif /* JOS_INC_IDE_H */
