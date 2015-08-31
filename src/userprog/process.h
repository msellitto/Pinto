#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

#define USERPROG_STACK_LIMIT 8*1024*1024 // 8MB user process stack limit

//lowest userprog stack address
#define USERPROG_STACK_LIMIT_ADDR PHYS_BASE - USERPROG_STACK_LIMIT 

bool install_stack_page (void *upage, void *kpage, bool writable);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

void add_child_pinfo(struct pinfo *pinfo);
void free_children_pinfo(void);
void set_pinfo_load_status(bool load_status);
void set_pinfo_complete(int retval);
int wait_for_child(pid_t child_pid);

struct pinfo* get_child_pinfo_by_pid(pid_t pid);

//JENNY
extern struct page* test_page;
struct page* get_test_page(void);

#endif /* userprog/process.h */










