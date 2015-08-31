#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include <pid.h>
#include <stdbool.h>
#include <hash.h>
#include "threads/synch.h"
#include "userprog/syscall.h"

extern int page_count;

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

enum process_status
  {
    PROCESS_RUNNING,
    PROCESS_COMPLETE
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

#define MAX_FILES 128
#define START_FD 2

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct pinfo;

struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    struct hash sp_table;               /* Supplemental page table (SPT) */
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */

    /* Userprog variables */
    pid_t pid;                          /* Process Identifier */
    struct thread *parent_thread;       /* Pointer to parent thread */
    struct pinfo *pinfo;                /* Pointer to processes pinfo struct */
    struct list child_pinfo_list;       /* List of all child pinfo structs */
    struct semaphore child_pinfo_list_sema;  /* Sema for accessing child_list */


    struct file* fd_table[MAX_FILES];   /* File descriptor table */
    struct mmap_file* mmap_file_table[MAX_FILES];
    /* vm variables */
    struct list page_list;            /* List of page structs */
    struct semaphore page_list_sema;  /* Sema to access process's page_list */
    void *aux_frame_esp;

  };

struct pinfo 
  {
    pid_t pid;                          /* Process Id */
    enum process_status status;         /* Process state */ 
    struct thread *t;                          /* Pointer to thread of process */
    bool load_status;                   /* Process loaded successfully */
    int ret_val;                        /* Return status (only relevant if 
                                           completed */
    struct semaphore wait_sema;         /* Semaphore used in process_wait()*/
    struct list_elem elem;              
  };

/* Create a structure to hold the auxilary data which will be passed to the
 * start_process function from thread_create() */
struct child_aux_data
  {
    char* command;                       /* Command (filename and arguments */
    struct pinfo *pinfo;                 /* pointer to childs pinfo struct */
    struct semaphore pinfo_setup_sema;   /* Wait for process_execute to fill 
                                              in the necessary information 
                                              before allowing child to 
                                              continue */
    struct semaphore load_sema;          /* Wait for child to finish loading 
                                            before process_execute returns so 
                                            that it can return the appropriate 
                                            error code. */
  };

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

struct thread* get_thread_from_tid(tid_t tid);


#endif /* threads/thread.h */
