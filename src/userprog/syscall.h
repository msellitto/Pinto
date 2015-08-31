#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>

#define MAX_SYSCALL_ARGS 3

void syscall_init (void);

typedef int mmapid_t;

struct mmap_file {
   struct file *file;
   struct list page_list;
   void *uaddr;
   size_t numPages;
};


extern struct semaphore filesys_sema;
#endif /* userprog/syscall.h */
