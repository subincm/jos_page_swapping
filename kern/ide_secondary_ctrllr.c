/*
 * Minimal PIO-based (non-interrupt-driven) IDE driver code.
 * For information about what all this IDE/ATA magic means,
 * see the materials available on the class references page.
 */
#include <inc/x86.h>
#include <kern/ide.h>

#define IDE_BSY		0x80
#define IDE_DRDY	0x40
#define IDE_DF		0x20
#define IDE_ERR		0x01

static int diskno = 0;

static int
ide_wait_ready(bool check_error)
{
	int r;
	while (((r = inb(0x177)) & (IDE_BSY|IDE_DRDY)) != IDE_DRDY)
		/* do nothing */;

	if (check_error && (r & (IDE_DF|IDE_ERR)) != 0)
		return -1;
	return 0;
}

bool
ide_probe_disk1(void)
{
	int r, x;

	// check if secondary controller exists
	outb(0x173, 0x88);
	r = inb(0x173);
	cprintf("SECONDARY DISK CONTROLLER%s\n", r==0x88?" present":"not present");


	// wait for Device 0 to be ready
	ide_wait_ready(0);


	// switch to Device 2
	outb(0x176, 0xE0);

	// check for Device 2 to be ready for a while
	for (x = 0;
	     x < 1000 && ((r = inb(0x177)) & (IDE_BSY|IDE_DF|IDE_ERR)) != 0;
	     x++)
		// do nothing


	cprintf("Device 2 presence: %d\n", (x < 1000));
	return (x < 1000);
}

void
ide_set_disk(int d)
{
	if (d != 0)
		panic("bad disk number");
	diskno = d;
}

int
ide_read(uint32_t secno, void *dst, size_t nsecs)
{
	int r;

	assert(nsecs <= 256);

	ide_wait_ready(1);

	outb(0x172, nsecs);
	outb(0x173, secno & 0xFF);
	outb(0x174, (secno >> 8) & 0xFF);
	outb(0x175, (secno >> 16) & 0xFF);
	outb(0x176, 0xE0 | ((diskno)<<4) | ((secno>>24)&0x0F));
	outb(0x177, 0x20);	// CMD 0x20 means read sector

	for (; nsecs > 0; nsecs--, dst += SECTSIZE) {
		if ((r = ide_wait_ready(1)) < 0)
			return r;
		insl(0x170, dst, SECTSIZE/4);
	}

	return 0;
}

int
ide_write(uint32_t secno, const void *src, size_t nsecs)
{
	int r;

	assert(nsecs <= 256);

	ide_wait_ready(0);

	outb(0x172, nsecs);
	outb(0x173, secno & 0xFF);
	outb(0x174, (secno >> 8) & 0xFF);
	outb(0x175, (secno >> 16) & 0xFF);
	outb(0x176, 0xE0 | ((diskno)<<4) | ((secno>>24)&0x0F));
	outb(0x177, 0x30);	// CMD 0x30 means write sector

	for (; nsecs > 0; nsecs--, src += SECTSIZE) {
		if ((r = ide_wait_ready(1)) < 0)
			return r;
		outsl(0x170, src, SECTSIZE/4);
	}

	return 0;
}

