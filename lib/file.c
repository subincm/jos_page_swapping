#include <inc/fs.h>
#include <inc/string.h>
#include <inc/lib.h>

#define debug 0

union Fsipc fsipcbuf __attribute__((aligned(PGSIZE)));

// Send an inter-environment request to the file server, and wait for
// a reply.  The request body should be in fsipcbuf, and parts of the
// response may be written back to fsipcbuf.
// type: request code, passed as the simple integer IPC value.
// dstva: virtual address at which to receive reply page, 0 if none.
// Returns result from the file server.
static int
fsipc(unsigned type, void *dstva)
{
	static envid_t fsenv;
	if (fsenv == 0)
		fsenv = ipc_find_env(ENV_TYPE_FS);

	if (debug)
		cprintf("[%08x] fsipc %d %08x\n", thisenv->env_id, type, *(uint32_t *)&fsipcbuf);

	ipc_send(fsenv, type, &fsipcbuf, PTE_P | PTE_W | PTE_U);
	return (ipc_recv(NULL, dstva, NULL));
}

static int devfile_flush(struct Fd *fd);
static ssize_t devfile_read(struct Fd *fd, void *buf, size_t n);
static ssize_t devfile_write(struct Fd *fd, const void *buf, size_t n);
static int devfile_stat(struct Fd *fd, struct Stat *stat);
static int devfile_trunc(struct Fd *fd, off_t newsize);

struct Dev devfile =
{
	.dev_id =	'f',
	.dev_name =	"file",
	.dev_read =	devfile_read,
	.dev_write =	devfile_write,
	.dev_close =	devfile_flush,
	.dev_stat =	devfile_stat,
};

// Open a file (or directory).
//
// Returns:
// 	The file descriptor index on success
// 	-E_BAD_PATH if the path is too long (>= MAXPATHLEN)
// 	< 0 for other errors.
int
open(const char *path, int mode)
{
	// Find an unused file descriptor page using fd_alloc.
	// Then send a file-open request to the file server.
	// Include 'path' and 'omode' in request,
	// and map the returned file descriptor page
	// at the appropriate fd address.
	// FSREQ_OPEN returns 0 on success, < 0 on failure.
	//
	// (fd_alloc does not allocate a page, it just returns an
	// unused fd address.  Do you need to allocate a page?)
	//
	// Return the file descriptor index.
	// If any step after fd_alloc fails, use fd_close to free the
	// file descriptor.

	// LAB 5: Your code here
	int ret = -E_BAD_PATH;
	int path_len = strlen(path);
	
	if(MAXPATHLEN <= path_len)
		return ret;
	struct Fd *fd;
	if((ret = fd_alloc(&fd)) < 0)
		return ret;

	if((ret = sys_page_alloc(thisenv->env_id, fd, PTE_P | PTE_W | PTE_U)) < 0){
		fd_close(fd, 0);
		return ret;
	}

	strcpy(fsipcbuf.open.req_path, path);

	fsipcbuf.open.req_omode = mode;
	if((ret = fsipc(FSREQ_OPEN, fd)) < 0){
		cprintf("RETURNING ret=%d\n", ret);
		fd_close(fd, 0);
		return ret;
	}
	return fd2num(fd);
}

// Flush the file descriptor.  After this the fileid is invalid.
//
// This function is called by fd_close.  fd_close will take care of
// unmapping the FD page from this environment.  Since the server uses
// the reference counts on the FD pages to detect which files are
// open, unmapping it is enough to free up server-side resources.
// Other than that, we just have to make sure our changes are flushed
// to disk.
static int
devfile_flush(struct Fd *fd)
{
	fsipcbuf.flush.req_fileid = fd->fd_file.id;
	return fsipc(FSREQ_FLUSH, NULL);
}

// Write at most 'n' bytes from 'buf' to 'fd' at the current seek position.
//
// Returns:
//	 The number of bytes successfully written.
//	 < 0 on error.
static ssize_t
devfile_write(struct Fd *fd, const void *buf, size_t n)
{
    // Make an FSREQ_WRITE request to the file system server.    
    // Make request.
    struct Fsreq_write *req = &fsipcbuf.write;
    req->req_fileid = fd->fd_file.id;

    // Limit to size of req_buf.
    size_t sz = sizeof(req->req_buf);
    if (n < sz)
        sz = n;
    req->req_n = sz;
    
    // Copy the bytes to write.
    memmove(req->req_buf, buf, sz);

    // Send request.
    ssize_t szwrtn = fsipc(FSREQ_WRITE, NULL);

    return szwrtn;
}

// Read at most 'n' bytes from 'fd' at the current position into 'buf'.
//
// Returns:
// 	The number of bytes successfully read.
// 	< 0 on error.
static ssize_t
devfile_read(struct Fd *fd, void *buf, size_t n)
{
	// Make an FSREQ_READ request to the file system server after
	// filling fsipcbuf.read with the request arguments.  The
	// bytes read will be written back to fsipcbuf by the file
	// system server.
	// LAB 5: Your code here
	off_t off_set = 0;
        ssize_t nread = 0;
        struct Fsreq_read *req = &(fsipcbuf.read);
        struct Fsret_read *ret = &(fsipcbuf.readRet);
        
	while(off_set < n) {
           req->req_fileid = fd->fd_file.id;
           req->req_n = n - off_set;
           if((nread = fsipc(FSREQ_READ, &fsipcbuf)) < 0)
              return nread;
           else if(nread == 0)
              return off_set;
           memcpy(buf+off_set, ret->ret_buf, nread);
           off_set+=nread;
        }
        return off_set;
}


static int
devfile_stat(struct Fd *fd, struct Stat *st)
{
	int r;

	fsipcbuf.stat.req_fileid = fd->fd_file.id;
	if ((r = fsipc(FSREQ_STAT, NULL)) < 0)
		return r;
	strcpy(st->st_name, fsipcbuf.statRet.ret_name);
	st->st_size = fsipcbuf.statRet.ret_size;
	st->st_isdir = fsipcbuf.statRet.ret_isdir;
	return 0;
}


