#ifndef JOS_KERN_SYSCALL_H
#define JOS_KERN_SYSCALL_H
#ifndef JOS_KERNEL
# error "This is a JOS kernel header; user programs should not #include it"
#endif

#include <inc/syscall.h>
#include <inc/env.h>

int64_t syscall(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5);
int sys_sleep(uint64_t ms);
int sys_page_alloc(envid_t envid, void *va, int perm);
void handle_timeouts();
#endif /* !JOS_KERN_SYSCALL_H */
