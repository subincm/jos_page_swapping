#include <inc/string.h>

#include "fs.h"

// LAB 5: CHALLENGE
// Free the block in bitmap
// Check to see if the block bitmap indicates that block 'blockno' is free.
// Return 1 if the block is free, 0 if not.
bool
is_free(uint32_t blockno)
{
	if (super == 0 || blockno >= super->s_nblocks)
		return 0;
	if (bitmap[blockno / 32] & (1 << (blockno % 32)))
		return 1;
	return 0;
}

// Mark a block free in the bitmap
	void
free_to_bitmap(uint32_t blockno)
{
	// Blockno zero is the null pointer of block numbers.
	if (blockno == 0)
		panic("attempt to free zero block");
	bitmap[blockno/32] |= 1<<(blockno%32);
}

void unfree_to_bitmap(uint32_t blockno)
{
	if (blockno == 0)
		panic("unfree_to_bitmap: attempt to free zero block");
	bitmap[blockno/32] &= ~(1<<(blockno%32));
}

// Return block number allocated on success,
// -E_NO_DISK if we are out of blocks.
//
int alloc_block(void)
{
	uint32_t blkno = 0;

	for (blkno = 0; blkno != super->s_nblocks * BLKBITSIZE; ++blkno) {
		if (is_free(blkno)) {
			unfree_to_bitmap(blkno);
			flush_block(diskaddr(blkno));
			return blkno;
		}
	}
	return -E_NO_DISK;
}

// --------------------------------------------------------------
// Super block
// --------------------------------------------------------------

// Validate the file system super-block.
void
check_super(void)
{
	if (super->s_magic != FS_MAGIC)
		panic("bad file system magic number");

	if (super->s_nblocks > DISKSIZE/BLKSIZE)
		panic("file system is too large");

	cprintf("superblock is good\n");
}


// --------------------------------------------------------------
// File system structures
// --------------------------------------------------------------

// Initialize the file system
void
fs_init(void)
{
	static_assert(sizeof(struct File) == 256);

	// Find a JOS disk.  Use the second IDE disk (number 1) if available.
	if (ide_probe_disk1())
		ide_set_disk(1);
	else
		ide_set_disk(0);

	bc_init();

	// Set "super" to point to the super block.
	super = diskaddr(1);
	check_super();
}

// Find the disk block number slot for the 'filebno'th block in file 'f'.
// Set '*ppdiskbno' to point to that slot.
// The slot will be one of the f->f_direct[] entries,
// or an entry in the indirect block.
// When 'alloc' is set, this function will allocate an indirect block
// if necessary.
//
//  Note, for the read-only file system (lab 5 without the challenge), 
//        alloc will always be false.
//
// Returns:
//	0 on success (but note that *ppdiskbno might equal 0).
//	-E_NOT_FOUND if the function needed to allocate an indirect block, but
//		alloc was 0.
//	-E_NO_DISK if there's no space on the disk for an indirect block.
//	-E_INVAL if filebno is out of range (it's >= NDIRECT + NINDIRECT).
//
// Analogy: This is like pgdir_walk for files.
// Hint: Don't forget to clear any block you allocate.
static int
file_block_walk(struct File *f, uint32_t filebno, uint32_t **ppdiskbno, bool alloc)
{
	// LAB 5: Your code here.
	//cprintf("In fs/fs.c: Entered file_block_walk\n");
	int ret = -E_INVAL;

	if(filebno >= NDIRECT + NINDIRECT)
		return ret;
	if(filebno < NDIRECT){//Direct block
		*ppdiskbno = &f->f_direct[filebno];
		//cprintf("In fs/fs.c: Got direct block %d\n", *ppdiskbno);
		return 0;
	}else{//Indirect block
			int indrbno = filebno - NDIRECT;
			if (f->f_indirect) {
				uint32_t* indrblk = (uint32_t*)diskaddr(f->f_indirect);
				if(indrblk[indrbno]){
					*ppdiskbno = &indrblk[indrbno];
					//cprintf("In fs/fs.c: Got in-direct block %d\n", *ppdiskbno);
					return 0;
				}
			}else if(alloc){
				//CHALLENGE: Allocate a indir blk and return  the blkno in it.
				f->f_indirect = alloc_block();
				if (!f->f_indirect)
					return -E_NO_DISK;
				memset(diskaddr(f->f_indirect), 0, BLKSIZE); //Clear everything
				uint32_t* indrblk = (uint32_t*)diskaddr(f->f_indirect);
				if(indrblk[indrbno]){
					*ppdiskbno = &indrblk[indrbno];
					//cprintf("In fs/fs.c: Got in-direct block %d\n", *ppdiskbno);
					return 0;
				}

			}else{ 
				return -E_NOT_FOUND;
			}
		}

	return ret;
	//panic("file_block_walk not implemented");
}

// Set *blk to the address in memory where the filebno'th
// block of file 'f' would be mapped.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_NO_DISK if a block needed to be allocated but the disk is full.
//	-E_INVAL if filebno is out of range.
//
int
file_get_block(struct File *f, uint32_t filebno, char **blk)
{
	// LAB 5: Your code here.
	int ret = -E_INVAL;
	uint32_t* ptr;
	if((ret = file_block_walk(f, filebno, &ptr, false)) < 0)
		return ret;
	assert(*ptr);
	//cprintf("In fs/fs.c: Got block %d\n", *ptr);
	*blk = (char*)diskaddr(*ptr);
	//cprintf("In fs/fs.c: block addr %d\n", *blk);
	return 0;
	//panic("file_block_walk not implemented");
}

// Try to find a file named "name" in dir.  If so, set *file to it.
//
// Returns 0 and sets *file on success, < 0 on error.  Errors are:
//	-E_NOT_FOUND if the file is not found
static int
dir_lookup(struct File *dir, const char *name, struct File **file)
{
	int r;
	uint32_t i, j, nblock;
	char *blk;
	struct File *f;

	// Search dir for name.
	// We maintain the invariant that the size of a directory-file
	// is always a multiple of the file system's block size.
	assert((dir->f_size % BLKSIZE) == 0);
	nblock = dir->f_size / BLKSIZE;
	for (i = 0; i < nblock; i++) {
		if ((r = file_get_block(dir, i, &blk)) < 0)
			return r;
		f = (struct File*) blk;
		for (j = 0; j < BLKFILES; j++)
			if (strcmp(f[j].f_name, name) == 0) {
				*file = &f[j];
				return 0;
			}
	}
	return -E_NOT_FOUND;
}


// Skip over slashes.
static const char*
skip_slash(const char *p)
{
	while (*p == '/')
		p++;
	return p;
}

// Evaluate a path name, starting at the root.
// On success, set *pf to the file we found
// and set *pdir to the directory the file is in.
// If we cannot find the file but find the directory
// it should be in, set *pdir and copy the final path
// element into lastelem.
static int
walk_path(const char *path, struct File **pdir, struct File **pf, char *lastelem)
{
	const char *p;
	char name[MAXNAMELEN];
	struct File *dir, *f;
	int r;

	// if (*path != '/')
	//	return -E_BAD_PATH;
	path = skip_slash(path);
	f = &super->s_root;
	dir = 0;
	name[0] = 0;

	if (pdir)
		*pdir = 0;
	*pf = 0;
	while (*path != '\0') {
		dir = f;
		p = path;
		while (*path != '/' && *path != '\0')
			path++;
		if (path - p >= MAXNAMELEN)
			return -E_BAD_PATH;
		memmove(name, p, path - p);
		name[path - p] = '\0';
		path = skip_slash(path);

		if (dir->f_type != FTYPE_DIR)
			return -E_NOT_FOUND;

		if ((r = dir_lookup(dir, name, &f)) < 0) {
			if (r == -E_NOT_FOUND && *path == '\0') {
				if (pdir)
					*pdir = dir;
				if (lastelem)
					strcpy(lastelem, name);
				*pf = 0;
			}
			return r;
		}
	}

	if (pdir)
		*pdir = dir;
	*pf = f;
	return 0;
}

// --------------------------------------------------------------
// File operations
// --------------------------------------------------------------


// Open "path".  On success set *pf to point at the file and return 0.
// On error return < 0.
int
file_open(const char *path, struct File **pf)
{
	return walk_path(path, 0, pf, 0);
}

// Read count bytes from f into buf, starting from seek position
// offset.  This meant to mimic the standard pread function.
// Returns the number of bytes read, < 0 on error.
ssize_t
file_read(struct File *f, void *buf, size_t count, off_t offset)
{
	int r, bn;
	off_t pos;
	char *blk;

	if (offset >= f->f_size){
		//cprintf("fs/fs.c file_read(): COUNT > FILE_SZ !\n");
		return 0;
	}

	count = MIN(count, f->f_size - offset);
	//cprintf("fs/fs.c file_read(): COUNT=%d\n", count);
	for (pos = offset; pos < offset + count; ) {
		if ((r = file_get_block(f, pos / BLKSIZE, &blk)) < 0)
			return r;
		bn = MIN(BLKSIZE - pos % BLKSIZE, offset + count - pos);
		memmove(buf, blk + pos % BLKSIZE, bn);
		pos += bn;
		buf += bn;
	}

	return count;
}

// Flush the contents + metadata of file f to disk.
void
file_flush(struct File *f)
{
       int i=0;
       uint32_t *pdiskbno;

       for (;i < (f->f_size + BLKSIZE - 1) / BLKSIZE; i++) {
               if (file_block_walk(f, i, &pdiskbno, 0) < 0 ||
                   pdiskbno == NULL || *pdiskbno == 0)
                       continue;
               flush_block(diskaddr(*pdiskbno));
       }
       flush_block(f);
       if (f->f_indirect)
               flush_block(diskaddr(f->f_indirect));
}

// Set the size of file f and flushes everything to disk.
int
file_set_size(struct File *f, off_t newsize)
{
       f->f_size = newsize;
       flush_block(f);
       return 0;
}


int
file_write(struct File *f, const void *buf, size_t count, off_t offset)
{
       int r;
       int bn;
       off_t pos;
       char *blk;

       if (offset + count > f->f_size)
               if ((r = file_set_size(f, offset + count)) < 0)
                       return r;

       for (pos = offset; pos < offset + count; ) {
               if ((r = file_get_block(f, pos / BLKSIZE, &blk)) < 0)
                       return r;
               bn = MIN(BLKSIZE - pos % BLKSIZE, offset + count - pos);
               memmove(blk + pos % BLKSIZE, buf, bn);
               pos += bn;
               buf += bn;
       }

       return count;
}
