#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <console.h>
#include <pid.h>
#include "threads/log.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "lib/user/syscall.h"
#include "threads/palloc.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"



static void syscall_handler (struct intr_frame*);
static void syscall_halt(void);
static void syscall_exit(int);
static pid_t syscall_exec(const char*);
static int syscall_wait(pid_t);
static bool syscall_create(const char*, unsigned);
static bool syscall_remove(const char*);
static int syscall_open(const char*);
static int syscall_filesize(int);
static int syscall_read(int, void*, unsigned);
static int syscall_write(int, const void*, unsigned);
static void syscall_seek(int, unsigned);
static unsigned syscall_tell(int);
static void syscall_close(int);
static mapid_t syscall_mmap(int fd, void *addr);
static void syscall_munmap(mapid_t mapping);

static inline int arg_as_int(void * arg);
static inline unsigned arg_as_uint(void * arg);
static inline pid_t arg_as_pid_t(void *arg);
static inline char *arg_as_cstr(void *arg);
static inline void *arg_as_pvoid(void *arg);

static void unpin_pages(void* addr, unsigned int size);

//static bool verify_pointer(void* addr);
static bool verify_pointer_range(void* addr, unsigned int size);

static inline bool verify_args(void *args, unsigned int num_args);
static inline bool verify_cstr(const char * str, int* size);

struct semaphore filesys_sema;

extern struct semaphore io_sema;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  sema_init(&filesys_sema, 1);

}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_id;
  int* stack_pointer;
  void *args[MAX_SYSCALL_ARGS];
  int i;
  struct page* ip_pg;                /* Page holding next instruction: Pin it */
  struct page* sp_pg;                /* Page holding stack pointer: Pin it */
  struct thread* t = thread_current();

  /*
   * Arguements are either 32-bit integers or pointers (char*), either way it
   * is a 4-byte value so just increment up 4-byte increments until frame
   * pointer 
   *
   * First, check that all pointers point below PHYS_BASE.  With
   * userproj/pagedir.c, account for the page fault that will occur if it
   * attempts to pass a NULL or unmapped pointer.
   */

  thread_current()->aux_frame_esp = f->esp;

  if(!verify_pointer_range(f->esp, sizeof(int))) 
     syscall_exit(-1);

  if((ip_pg = get_page_from_spt(t, pg_round_down(f->eip))) == NULL) {
     printf("IP not in spt\n");
  }
  if((sp_pg = get_page_from_spt(t, pg_round_down(f->esp))) == NULL) {
     printf("SP not in spt\n");
  }

  /* Pin the page to physical memory */
  ip_pg->pinned = true;
  sp_pg->pinned = true;

  stack_pointer = (int*)(f->esp);
  syscall_id = (int)(*stack_pointer);

  /* grab the syscall arguments */
  for(i = 0; i < MAX_SYSCALL_ARGS; i++)
  {
     args[i] = (void *)(stack_pointer+i+1); 
  }

  /* switch on the syscall_id, verify the arguments and
    call the appropiate syscall handler */
  switch(syscall_id){
  case SYS_HALT:
    {
      syscall_halt();
      break;
    }
  case SYS_EXIT:
    {
       if(!verify_args(args[0], 1)) 
          syscall_exit(-1);
      
       syscall_exit(arg_as_int(args[0]));
       break;
    }
  case SYS_EXEC:
    {
       if(!verify_args(args[0], 1)) 
          syscall_exit(-1); 
      
       f->eax = (uint32_t)syscall_exec(arg_as_cstr(args[0]));
       break;
    }
  case SYS_WAIT:
    {
       if(!verify_args(args[0], 1)) 
          syscall_exit(-1); 
       
       f->eax = (uint32_t)syscall_wait(arg_as_pid_t(args[0]));
      break;
    }
  case SYS_CREATE:
    {
       if(!verify_args(args[0], 2)) 
          syscall_exit(-1); 
       
       f->eax = (uint32_t)syscall_create(arg_as_cstr(args[0]),
                                        arg_as_uint(args[1]));
      break;
    }
  case SYS_REMOVE:
    {
       if(!verify_args(args[0], 1)) 
          syscall_exit(-1); 
       
       f->eax = (uint32_t)syscall_remove(arg_as_cstr(args[0]));
       break;
    }
  case SYS_OPEN:
    {
       if(!verify_args(args[0], 1)) 
          syscall_exit(-1); 
      
       f->eax = (uint32_t)syscall_open(arg_as_cstr(args[0]));
      break;
    }
  case SYS_FILESIZE:
    {
       if(!verify_args(args[0], 1)) 
          syscall_exit(-1); 
       
       f->eax = (uint32_t)syscall_filesize(arg_as_int(args[0]));
      break;
    }
  case SYS_READ:
    {
       if(!verify_args(args[0], 3)) 
          syscall_exit(-1); 
       
       f->eax = (uint32_t)syscall_read(arg_as_int(args[0]), 
                                      arg_as_pvoid(args[1]),
                                      arg_as_uint(args[2]));
      break;
    }
  case SYS_WRITE:
    {
       if(!verify_args(args[0], 3)) 
          syscall_exit(-1); 
       
       f->eax = (uint32_t)syscall_write(arg_as_int(args[0]),
                                       arg_as_pvoid(args[1]),
                                       arg_as_uint(args[2]));
      break;
    }
  case SYS_SEEK: 
    {
       if(!verify_args(args[0], 2)) 
          syscall_exit(-1);
       
       syscall_seek(arg_as_int(args[0]), arg_as_uint(args[1]));
      break;
    }
  case SYS_TELL:
    {
       if(!verify_args(args[0], 1)) 
          syscall_exit(-1);
       
       f->eax = (uint32_t)syscall_tell(arg_as_int(args[0]));
      break;
    }
  case SYS_CLOSE:
    {
       if(!verify_args(args[0], 1)) 
          syscall_exit(-1); 
       
       syscall_close(arg_as_int(args[0]));
      break;
    }

  case SYS_MMAP:
    {
       if(!verify_args(args[0], 2)) 
          syscall_exit(-1);

       f->eax = (uint32_t)syscall_mmap(arg_as_int(args[0]),
             arg_as_pvoid(args[1]));
       break;
    }

  case SYS_MUNMAP:
    {
       if(!verify_args(args[0], 1)) 
          syscall_exit(-1);

       syscall_munmap(arg_as_int(args[0]));
       break;
    }

  }

  ip_pg->pinned = false;
  sp_pg->pinned = false;
}

/* halts the system */
static void syscall_halt()
{

  shutdown_power_off();

  return;
}

/* cleanly exits the current process with return value status */
static void syscall_exit(int status)
{
  printf ("%s: exit(%d)\n", thread_current()->name, status);

  set_pinfo_complete(status);

  thread_exit();
  return;
}

/* executes a new process with command line cmd_line as a new child for the
 * current process */
static pid_t syscall_exec(const char *cmd_line)
{
  tid_t retval;
  int size = -1;;

  if(!verify_cstr(cmd_line, &size)) 
     syscall_exit(-1);

  if(size == -1)
     printf("SIZE SCARE!\n");

  retval = process_execute(cmd_line);

  unpin_pages((void*)cmd_line, size);

  return retval;

}

/* wait for child process with pid pid to finish and return its return value */
/* if the process is not a child it will return -1, if the child has already
 * been waited on it will return -1 */
static int syscall_wait(pid_t pid)
{
  return process_wait(pid);
}

/* 
 * Create a new file called file which is initial_size in bytes.  Until
 * project 4, a file cannot grow in size, so this size should be large enough
 * to handle the data which will be written to it.  Creating a file does not
 * open it.
 */
static bool syscall_create(const char* file, unsigned initial_size)
{
  bool retval;
  int size = -1; 

  if(!verify_cstr(file, &size)) 
     syscall_exit(-1);

  if(size == -1)
     printf("SIZE SCARE!\n");

  sema_down(&filesys_sema);
  retval = filesys_create(file, initial_size);
  sema_up(&filesys_sema);

  unpin_pages((void*)file, size);

  return retval;

}

/* Removes (deletes) a file from the file system */
/* return true if successfull, false otherwise */
static bool syscall_remove(const char* file)
{
  bool retval;
  int size = -1;
 
  if(!verify_cstr(file, &size)) 
     syscall_exit(-1);

  if(size == -1)
     printf("SIZE SCARE!\n");

  sema_down(&filesys_sema);
  retval = filesys_remove(file);
  sema_up(&filesys_sema);

  unpin_pages((void*)file, size);

  return retval;
}

/* 
 * Opens the file file and returns the nonnegative integer "file descriptor",
 * fd, or -1 if hte file could not be opened.
 */
static int syscall_open(const char* file)
{
  struct file* f;
  int i, fd;
  int size = -1;

  if(!verify_cstr(file, &size)) 
     syscall_exit(-1);

  if(size == -1)
     printf("SIZE SCARE!\n");

  sema_down(&filesys_sema);
  if((f = filesys_open(file)) == NULL){
    fd = -1;
  }
  else{
    /* Put new file in fd table and return index */
    for(i = START_FD; i < MAX_FILES; i++){
      if(thread_current()->fd_table[i] == NULL){
        fd = i;
        thread_current()->fd_table[i] = f;
        break;
      }
    }
    if(i == MAX_FILES){
      fd = -1;
    }
  }
  sema_up(&filesys_sema);

  unpin_pages((void*)file, size);

  return fd;
}

/* returns the file size of the file descriptor fd */
static int syscall_filesize(int fd)
{
   int retval = 0;
  
   if(fd >= MAX_FILES) 
   {
      retval = -1;
   }

   else if(thread_current()->fd_table[fd] == NULL)
   {
      retval = -1;
   }

   else if((fd == STDIN_FILENO) || (fd == STDOUT_FILENO))
   {
      retval = 0;
   }

   else
   {
      sema_down(&filesys_sema);
      retval = (int)file_length(thread_current()->fd_table[fd]);
      sema_up(&filesys_sema);
   }

  return retval;
}

/* reads size bytes of data from the file associated with file descriptor fd
  into the memory location buffer
  returns the number of bytes read.
  FD 0 reads from STDIN */
static int syscall_read(int fd, void* buffer, unsigned size)
{
   int retval = 0;

   if(!verify_pointer_range(buffer, size)) 
   {
      syscall_exit(-1);  
   }

   switch(fd){
   case STDIN_FILENO:
      {
         unsigned i;
         uint8_t *buf = (uint8_t*)buffer;

         for(i = 0;; i++)
         {
            uint8_t inval = input_getc();
            
            if(i < size)
            {
               buf[i] = inval;
            }
           
           if(inval == 0x0D) {
              i++;
              break;
           }
         }

         if(i > size) i = size;
         retval = i;

         // Read from keyboard using input_getc()
         break;
      }
   case STDOUT_FILENO:
      {
         retval = 0;
         break;
      }
   default:
      {
         // Read from file
         if((fd >= MAX_FILES) || (fd < 0)) 
         {
            retval = -1;
         }

         else if(thread_current()->fd_table[fd] == NULL)
         {
            retval = -1;
         }

         else
         {
            struct file *f = thread_current()->fd_table[fd];
            sema_down(&filesys_sema);
            retval = (int)file_read(f, buffer, (off_t)size);
            sema_up(&filesys_sema);
         }
      
         break;
      }
   }

   unpin_pages((void*)buffer, size);
   return retval;
}

/* 
 * Writes size bytes from buffer to the open file fd.  Returns the number of
 * bytes actually written.  FD 1 writes to the console.
 */
static int syscall_write(int fd, const void* buffer, unsigned size)
{
  int retval;
  struct file* write_file;

  if(!verify_pointer_range((void*)buffer, size)){
    syscall_exit(-1);
  }

  switch(fd){
  case STDIN_FILENO:
     {  
        /* Cannot write to stdin */
        retval = 0;
        break;
    }
  case STDOUT_FILENO:
    {
       /* Write to stdout */
       putbuf(buffer, (size_t)size);
       retval = size;
       break;
    }
  default:
    {
       /* Write to a file */
       if((fd >= MAX_FILES) || (fd < 0)) 
       {
          retval = -1;
       }
       else if(thread_current()->fd_table[fd] == NULL)
       {
          retval = -1;
       }
       else
       {
          sema_down(&filesys_sema);
          if(!(thread_current()->fd_table[fd]->deny_write)){
             write_file = thread_current()->fd_table[fd];
             retval = file_write(write_file, buffer, size);
          }
          sema_up(&filesys_sema);
       }
      break;
    }
  }

  unpin_pages((void*)buffer, size);

  return retval;
}

/* seeks to position position of the file associated with file descriptor fd */
static void syscall_seek(int fd, unsigned position)
{
  if(thread_current()->fd_table[fd] == NULL){
    return;
  }

  sema_down(&filesys_sema);
  file_seek(thread_current()->fd_table[fd], position);
  sema_up(&filesys_sema);

  return;
}

/* grabs the next byte of the file associated with file descriptor and returns
 * its value, or -1 if error */
static unsigned syscall_tell(int fd)
{

  int retval = 0;
  
  if(fd >= MAX_FILES) 
   {
      retval = -1;
   }

   else if(thread_current()->fd_table[fd] == NULL)
   {
      retval = -1;
   }

   else if((fd == STDIN_FILENO) || (fd == STDOUT_FILENO))
   {
      retval = 0;
   }

   else
   {
      sema_down(&filesys_sema);
      retval = (int)file_tell(thread_current()->fd_table[fd]);
      sema_up(&filesys_sema);
   }

  return retval;
}


/* closes the file at file associated with file descriptor fd */
static void syscall_close(int fd) 
{
  if(fd >= MAX_FILES) 
   {
      return;
   }

   else if(thread_current()->fd_table[fd] == NULL)
   {
      return;
   }

   else if((fd == STDIN_FILENO) || (fd == STDOUT_FILENO))
   {
      return;
   }

   else
   {
      sema_down(&filesys_sema);
      file_close(thread_current()->fd_table[fd]);
      thread_current()->fd_table[fd] = NULL;
      sema_up(&filesys_sema);
   }

  return;
}

/* Map a file page to physical memory */
static mapid_t syscall_mmap(int fd, void *addr)
{

   /* cannot mmap fd 0 or 1 */
   /* must be a valid fd */

   int filesize;
   mapid_t mapid;
   struct mmap_file* mmap_file;

   if((fd < 2) || (fd >= MAX_FILES) ) 
   {
      return -1;
   }

   /* must be a valid open file */
   else if(thread_current()->fd_table[fd] == NULL)
   {
      return -1;
   }

   else
   {
      sema_down(&filesys_sema);
      filesize = (int)file_length(thread_current()->fd_table[fd]);
      sema_up(&filesys_sema);

      /* filesize must be at least one byte long to mmap */
      if(filesize < 1) return -1;
   }

   /* addr must be in userspace, not 0, and page aligned */
   if(is_kernel_vaddr(addr) || (addr == 0) || (addr != pg_round_down(addr)))
   {
      return -1;
   }

   /* file must be able to fit in the user virtual address range */
   else if(is_kernel_vaddr(addr + filesize))
   {
      return -1;
   }

   else
   {
      int pages_needed = 1 + (filesize / PGSIZE);
      int idx;
      struct thread *curr_t = thread_current();

      /* the region being mapped must not already be mapped */
      for(idx = 0; idx < pages_needed; idx++)
      {
         void *page_addr = addr + (idx*PGSIZE);

         if(get_page_from_spt(curr_t, page_addr) != NULL)
         {
            return -1;
         }
      }

      // search for a map id to give out
      for(idx = 0; idx < MAX_FILES; idx++) 
      {
         if(thread_current()->mmap_file_table[idx] == NULL){
            mapid = idx;
            thread_current()->mmap_file_table[idx] = 
               malloc(sizeof(struct mmap_file));

            mmap_file = thread_current()->mmap_file_table[idx];
            sema_down(&filesys_sema);
            mmap_file->file = file_reopen(curr_t->fd_table[fd]);
            sema_up(&filesys_sema);
            list_init (&mmap_file->page_list);
            mmap_file->uaddr = addr;
            mmap_file->numPages = pages_needed;
            break;
         }
      }
      // no more mmap ids left to give
      if(idx == MAX_FILES){
         return -1;
      }
      sema_down(&frame_table_sema);

      // add the pages needed to mmap the file
      for(idx = 0; idx < pages_needed; idx++)
      {
         void *page_addr = addr + (idx*PGSIZE);

         struct page *pg = add_page_to_spt(curr_t, page_addr, NULL);

         pg->is_mmapped_file = true;
         pg->writable = true;

         pg->load_info.file = mmap_file->file;
         pg->load_info.offset = idx*PGSIZE;

         // the last page may be only a partial one
         if(idx == (pages_needed -1))
         {
            pg->load_info.page_read_bytes = (filesize % PGSIZE);
            pg->load_info.page_zero_bytes = PGSIZE -
               pg->load_info.page_read_bytes;
         }

         else
         {            
            pg->load_info.page_read_bytes = PGSIZE;
            pg->load_info.page_zero_bytes = 0;
         }

         pg->location = FS_FILE;
         
         list_push_back (&mmap_file->page_list, &pg->mmap_file_list_elem);
      }

      sema_up(&frame_table_sema);

      return mapid;
   }
}



/* Unmap a file page from physcial memory */
static void syscall_munmap(mapid_t mapping)
{
   struct mmap_file* mmap_file = thread_current()->mmap_file_table[mapping]; 
   struct thread *t = thread_current();

   if(mmap_file == NULL) return;
   else 
   {
      struct list_elem* e;

      sema_down(&frame_table_sema);

      for(e = list_begin(&mmap_file->page_list); 
          e != list_end(&mmap_file->page_list); )
      {
         struct page* pg = list_entry(e, struct page, mmap_file_list_elem);
         free_page_frame(pg);
         e = list_next(e);
         list_remove(&(pg->mmap_file_list_elem));
         list_remove(&(pg->page_list_elem)); 
         hash_delete(&t->sp_table, &pg->spt_hash_elem);      
         free(pg);
      }
      sema_down(&filesys_sema);
      file_close(thread_current()->mmap_file_table[mapping]->file);
      sema_up(&filesys_sema);

      free(mmap_file);
      thread_current()->mmap_file_table[mapping] = NULL;
      sema_up(&frame_table_sema);
   }
}

/* these macro functions interpret the syscall argument arg as C datatypes */

static inline int arg_as_int(void *arg)
{
   return *((int*)arg);
}

static inline unsigned arg_as_uint(void *arg)
{
   return *((unsigned*)arg);
}

static inline pid_t arg_as_pid_t(void *arg)
{
   return *((pid_t*)arg);
}

static inline char *arg_as_cstr(void *arg)
{
   return *((char**)arg);
}

static inline void *arg_as_pvoid(void *arg)
{
   return *((void**)arg);
}

/* verifies size bytes of data at memory address addr to make sure its valid
 * userspace data, returns true if its valid and false otherwise */
static bool verify_pointer_range(void* addr, unsigned int size)
{
  unsigned int idx;
  void* check_page;
  void* last_page = NULL;
  void* this_page = NULL;
  struct page* pg;
  struct thread* t = thread_current();
  bool success = true;

  if(is_kernel_vaddr(addr + size)){
     return false;
  }

  sema_down(&frame_table_sema);
  for(idx = 0; idx < size; idx++){
    /* See if page is in page directory */
    this_page = pg_round_down(addr + idx);
    pg = get_page_from_spt(t, this_page);

    check_page = pagedir_get_page(thread_current()->pagedir, addr + idx);

    if(check_page != NULL){
       pg->pinned = true;
       continue;
    }

    if(pg == NULL) {
       if(!(success = increase_stack(&pg, addr+idx, 
                                     thread_current()->aux_frame_esp))){
          /* Couldn't increase stack.  Break to return false. */
          break;
       }
    }
    else{
       if(this_page != last_page){
          /* We don't want to do this for every address in the same page */
          if(pg->location == SWAP){
             obtain_frame_for_page(pg);
             read_page_from_swap(pg);
          }
          if(pg->location == FS_FILE){
             obtain_frame_for_page(pg);
             load_page_from_file(pg);
          }
          last_page = this_page;
       }
    }
    pg->pinned = true;
  }
  sema_up(&frame_table_sema);
  return success;
}

/* verifies that the data at str is valid userspace data */
/* return true if its valid and false otherwise */
static bool verify_cstr(const char *str, int* size)
{
  void * addr = (void *)str;
  unsigned int idx;
  struct page* pg;
  void* last_page = NULL;
  void* this_page = NULL;
  struct thread* t = thread_current();
  void* check_page;
  bool success = true;

  sema_down(&frame_table_sema);
  for(idx = 0 ;; idx++){
     if(is_kernel_vaddr(addr + idx)){
        success = false;
        break;
     }

    /* See if page is in page directory */
    this_page = pg_round_down(addr + idx);
    pg = get_page_from_spt(t, this_page);

    check_page = pagedir_get_page(thread_current()->pagedir, addr + idx);

    if(check_page != NULL){
       pg->pinned = true;
       if(*(str + idx) == '\0') {
          *size = idx + 1;
          break;
       }
       continue;
    }

    if(pg == NULL) {
       if(!(success = increase_stack(&pg, addr+idx, 
                                     thread_current()->aux_frame_esp))){
          /* Couldn't increase stack.  Break to return false. */
          break;
       }
    }
    else{
       if(this_page != last_page){
          /* We don't want to do this for every address in the same page */
          if(pg->location == SWAP){
             obtain_frame_for_page(pg);
             read_page_from_swap(pg);
          }
          if(pg->location == FS_FILE){
             obtain_frame_for_page(pg);
             load_page_from_file(pg);
          }
          last_page = this_page;
       }
    }
    pg->pinned = true;
  }
  sema_up(&frame_table_sema);
  return success;
}

static void unpin_pages(void* addr, unsigned int size)
{
   unsigned int idx;
   struct page* pg;
   struct thread* t = thread_current();

   for(idx = 0; idx < size; idx++){
     pg = get_page_from_spt(t, pg_round_down(addr+idx));
     pg->pinned = false;
   }
}

/* Verify that all arguments on the stack point are located in user space */
static inline bool verify_args(void *args, unsigned int num_args)
{
   return verify_pointer_range(args, num_args * sizeof(int));
}

