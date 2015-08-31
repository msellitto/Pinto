#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/log.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
bool push_ptr_to_stack(void**, void*, uint8_t*);
bool adjust_and_check_tos(uint8_t**, uint8_t*, int);
static int process_file_open(const char* file);

static void close_all_files(void);
static void unmmap_all_mmapped_file(void);

struct list process_list;

/* Starts a new thread running a user program loaded from
   COMMAND.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *command) 
{
  char *command_copy;
  char *command_mod;
  char *name;
  char* save_ptr = NULL;
  tid_t tid;

  struct pinfo *child_pinfo;
  struct child_aux_data* aux;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  command_copy = palloc_get_page (0);
  if (command_copy == NULL)
    return TID_ERROR;
  command_mod = palloc_get_page (0);
  if (command_mod == NULL)
    return TID_ERROR;
  name = palloc_get_page (0);
  if (name == NULL)
    return TID_ERROR;

  /* Struct to describe child process */
  child_pinfo = malloc(sizeof(struct pinfo));
  if(child_pinfo == NULL)
    return TID_ERROR;
  
  aux = malloc(sizeof(struct child_aux_data));
  if(aux == NULL)
    return TID_ERROR;
  
  strlcpy (command_mod, command, PGSIZE);
  strlcpy (command_copy, command, PGSIZE);

  name = strtok_r(command_mod, " ", &save_ptr);
  
  sema_init(&(aux->load_sema), 0);             /* One-time event */
  sema_init(&(aux->pinfo_setup_sema), 0);        /* One-time event */

  /* Fill auxiliary structure to be passed to start_process */
  aux->command = command_copy;
  aux->pinfo = child_pinfo;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (name, PRI_DEFAULT, start_process, (void*)aux);

  child_pinfo->pid = (pid_t) tid;
  child_pinfo->t = get_thread_from_tid(tid);
  child_pinfo->status = PROCESS_RUNNING;
  child_pinfo->load_status = false;
  child_pinfo->ret_val = 0;
  sema_init(&(child_pinfo->wait_sema), 0);         

  add_child_pinfo(child_pinfo);

  sema_up(&(aux->pinfo_setup_sema));
  sema_down(&(aux->load_sema));

  if(child_pinfo->load_status == false)
  {
     tid = TID_ERROR;
  }
  if(tid == TID_ERROR){
     palloc_free_page (command_mod);
  }

  free(aux);

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *aux)
{
  struct intr_frame if_;
  bool success;
  struct thread *curr_t = thread_current();

  /* Get auxiliary data */
  struct child_aux_data* aux_data = (struct child_aux_data*)aux;
  char *command = aux_data->command;
  curr_t->pinfo = aux_data->pinfo;
  sema_down(&(aux_data->pinfo_setup_sema));


  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (command, &if_.eip, &if_.esp);

  set_pinfo_load_status(success);

  sema_up(&(aux_data->load_sema));

  /* If load failed, quit. */
  //palloc_free_page (aux_data->command);

  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */

int
process_wait (tid_t child_tid UNUSED) 
{
  int ret_val =  wait_for_child((pid_t) child_tid);

  return ret_val;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  free_children_pinfo();
  close_all_files();
  unmmap_all_mmapped_file();

  sema_down(&frame_table_sema);
  delete_thread_frames(cur);
  delete_thread_swaps(cur);
  free_page_structs(cur);
  sema_up(&frame_table_sema);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, const char* command);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *command, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  char* file_name;
  char* command_copy;
  char* save_ptr = NULL;
  int fd;

  /* Make a copy of command since strtok_r will modify the string */
  file_name = palloc_get_page (PAL_ZERO);
  command_copy = palloc_get_page (PAL_ZERO);
  strlcpy (command_copy, command, PGSIZE);
  file_name = strtok_r(command_copy, " ", &save_ptr);

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */

  fd = process_file_open(file_name);
  if (fd == -1)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  file = t->fd_table[fd];
  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, command))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  palloc_free_page(command_copy);

  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE){
    return false;
  }

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);
  struct page* pg;
  off_t curr_offset = ofs;

  struct thread *t = thread_current ();

  //file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      
      pg = add_page_to_spt(t, upage, NULL);

      pg->writable = writable;

      pg->load_info.page_read_bytes = page_read_bytes;
      pg->load_info.page_zero_bytes = page_zero_bytes;
      pg->load_info.file = file;
      pg->load_info.offset = curr_offset;

      pg->location = FS_FILE;
      pg->was_loaded = true;

      /* Advance. */
      curr_offset += page_read_bytes;
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char* command) 
{
  bool success = false;

  uint8_t** argv;                     /* Array of addresses of arguments
                                         in user's stack space */
  uint8_t* tos;                       /* Top of simulated stack */   
  uint8_t* offset;                    /* Offset from top of page */
  uint8_t* top_of_page;               /* Value of top of page */

  int cpy_size;
  int num_tokens = 0;
  int idx = 0;
  int num_bytes_pad;
  char* token;
  char* save_ptr;

  struct thread* t = thread_current();
  void* upage = ((uint8_t *) PHYS_BASE) - PGSIZE;
  struct page* pg;
  
  sema_down(&frame_table_sema);
  pg = add_page_to_spt(t, upage, NULL);
  obtain_frame_for_page(pg);
  zero_page(pg);

  if (pg->kpage != NULL) 
  {
    tos = (pg->kpage + PGSIZE);
    top_of_page = tos;
    offset = tos;

    token = palloc_get_page(PAL_ZERO);
    if(token == NULL)
      return false;

    save_ptr = token;

    argv = palloc_get_page(PAL_ZERO);
    if(argv == NULL)
      return false;

    for(token = strtok_r((char*)command, " ", &save_ptr); token != NULL;
        token = strtok_r(NULL, " ", &save_ptr)){

      /* strltok_r will modify the original string.  So we have to save each
       * token as we come across it. */
      if(!(adjust_and_check_tos(&tos, pg->kpage, strlen(token) + 1)))
         return false;
      cpy_size = strlcpy((char*)tos, token, strlen(token) + 1);
      offset = (uint8_t*)((unsigned int)top_of_page - (unsigned int)tos);
      argv[num_tokens++] = (void*)(PHYS_BASE - (void*)offset);
    }

    /* Pad the stack with 0's until it is byte-aligned again */
    num_bytes_pad = (unsigned int)(tos) % 4;
    for(idx = 0; idx < num_bytes_pad; idx++){
      if(!(adjust_and_check_tos(&tos, pg->kpage, sizeof(char))))
         return false;
      *tos = (char)0;
    }

    /* Push null pointer sential on the stack */
    if(!(push_ptr_to_stack((void**)&tos, (void*)0, pg->kpage)))
       return false;

    /* Push argv[i] onto the stack in right-to-left order */
    for(idx = num_tokens - 1; idx >= 0; idx--){
      if(!(push_ptr_to_stack((void**)&tos, (void*)(argv[idx]), pg->kpage)))
         return false;
    }

    /* Push argv (the address of argv[0], which is the address that the stack
     * pointer currently points to) to the stack */
    offset = (uint8_t*)((unsigned int)top_of_page - (unsigned int)tos);
    if(!(push_ptr_to_stack((void**)&tos, (void*)(PHYS_BASE - (void*)offset), 
                           pg->kpage)))
       return false;

    /* Push argc to stack */
    if(!(push_ptr_to_stack((void**)&tos, (void*)num_tokens, pg->kpage)))
       return false;

    /* Push a fake return address to stack */
    if(!(push_ptr_to_stack((void**)&tos, (void*)0, pg->kpage)))
       return false;

    success = 
       install_stack_page (((uint8_t *) PHYS_BASE) - PGSIZE, pg->kpage, true);

    palloc_free_page(token);
    palloc_free_page(argv);

    if (success){
      offset = (uint8_t*)((unsigned int)top_of_page - (unsigned int)tos);
      *esp = (void*)(PHYS_BASE - (void*)offset);
    }
    else{
      printf("setup_stack: Could not load executable\n");
      palloc_free_page (pg->kpage);
    }
  }
  sema_up(&frame_table_sema);
  return success;
}

/* Adjust and check the tos by the size of a pointer.  Then write the value of
 * value to the simulated stack at this address. */
bool push_ptr_to_stack(void** tos, void* value, uint8_t* page_base){
  void** push_to_addr;

  if(!(adjust_and_check_tos((uint8_t**)tos, page_base, sizeof(void*))))
     return false;
  push_to_addr = *tos;
  *push_to_addr = value;

  return true;
}

/* 
 * Adjust the tos (the location on the simulated stack to write to) by the
 * amount specified in size, and check that this location does not overflow
 * the stack page */
bool adjust_and_check_tos(uint8_t** tos, uint8_t* base, int size)
{
  *tos -= size; 

  if(*tos < base){
     printf("setup_stack: Exceeded bottom of allocated stack frame!\n");
     return false;
  }

  return true;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_stack_page (void *upage, void *kpage, bool writable)
{
   return create_frame_mapping(upage, kpage, writable, false);
}

/* adds a pinfo struct to the currents thread child_pinfo_list */
void add_child_pinfo(struct pinfo *pinfo)
{
   struct thread *curr_t = thread_current();

   sema_down(&(curr_t->child_pinfo_list_sema));

   list_push_back(&(curr_t->child_pinfo_list), &(pinfo->elem));

   sema_up(&(curr_t->child_pinfo_list_sema));
}

/* sets the load status of the current processes pinfo struct to load_status */
void set_pinfo_load_status(bool load_status)
{
   struct thread *curr_t = thread_current();
   struct thread *parent_t = curr_t->parent_thread;

   if(parent_t != NULL)
   {
      sema_down(&(parent_t->child_pinfo_list_sema));

      if(curr_t->pinfo != NULL)
      {
         curr_t->pinfo->load_status = load_status;
      }

      sema_up(&(parent_t->child_pinfo_list_sema));
   }


}

/* sets the current process status in its pinfo to PROCESS_COMPLETE as well as 
  setting its return value to ret_val and unblocking the parent if its waiting
  for it to complete */
void set_pinfo_complete(int ret_val)
{

   struct thread *curr_t = thread_current();
   struct thread *parent_t = curr_t->parent_thread;

   if(parent_t != NULL)
   {
      sema_down(&(parent_t->child_pinfo_list_sema));

      if(curr_t->pinfo != NULL)
      {
         curr_t->pinfo->ret_val = ret_val;
         sema_up(&(curr_t->pinfo->wait_sema));
         curr_t->pinfo->t = NULL;
         curr_t->pinfo->status = PROCESS_COMPLETE;
      }

      sema_up(&(parent_t->child_pinfo_list_sema));
   }

}


/* implements waiting for a child and returning its exit value */
/* will return -1 if its not a child or if the parent has already waited for it
 * */
int wait_for_child(pid_t child_pid)
{
   struct thread *curr_t = thread_current();
   struct pinfo *child_pinfo = get_child_pinfo_by_pid(child_pid);

   if(child_pinfo == NULL) return -1; /* child pinfo not found, return -1 */

   sema_down(&(curr_t->child_pinfo_list_sema));

   /* if process has completed, free its pinfo and return its exit value */
   if(child_pinfo->status == PROCESS_COMPLETE)
   {
      int ret_val = child_pinfo->ret_val;

      list_remove(&(child_pinfo->elem));
      free(child_pinfo);

      sema_up(&(curr_t->child_pinfo_list_sema));
      return ret_val;
   }

   /* process has not completed yet, wait for child process to up its wait_sema
      before continuing, then free its pinfo and return its exit values */
   else
   {
      int ret_val;
      sema_up(&(curr_t->child_pinfo_list_sema));
      sema_down(&(child_pinfo->wait_sema));
      
      sema_down(&(curr_t->child_pinfo_list_sema));
      ret_val = child_pinfo->ret_val;
 
      list_remove(&(child_pinfo->elem));
      free(child_pinfo);

      sema_up(&(curr_t->child_pinfo_list_sema));

      return ret_val;
   }
}

/* get pinfo of a child by its pid */
/* if its not a child it returns NULL */
struct pinfo* get_child_pinfo_by_pid(pid_t pid)
{
   struct thread *curr_t = thread_current();
   struct list_elem *e;

   sema_down(&(curr_t->child_pinfo_list_sema));

   for (e = list_begin (&(curr_t->child_pinfo_list)); e != list_end
         (&(curr_t->child_pinfo_list));
         e = list_next (e))
   {
      struct pinfo *child_pinfo = list_entry (e, struct pinfo, elem);
      if(child_pinfo->pid == pid) {
         sema_up(&(curr_t->child_pinfo_list_sema));
         return child_pinfo;
      }
   }

   sema_up(&(curr_t->child_pinfo_list_sema));
   return NULL;
}


/* frees all child processes pinfo structures, will also alert all still
 * running processes that its parent has completed by setting their parent and
 * pinfo pointers to NULL */
void free_children_pinfo(void)
{
   struct thread *curr_t = thread_current();
   struct list_elem *e;

   sema_down(&(curr_t->child_pinfo_list_sema));

   for (e = list_begin (&(curr_t->child_pinfo_list)); e != list_end
         (&(curr_t->child_pinfo_list));)
   {
      struct pinfo *child_pinfo = list_entry (e, struct pinfo, elem);

      if(child_pinfo->status == PROCESS_COMPLETE)
      {
         e = list_next(e);
         list_remove(&(child_pinfo->elem));
         free(child_pinfo);
      }
  
      else {

         if(child_pinfo->t != NULL)
         {
            child_pinfo->t->parent_thread = NULL;
            child_pinfo->t->pinfo = NULL;
         }
         e = list_next(e);
         list_remove(&(child_pinfo->elem));
         free(child_pinfo);
      }
   }

   sema_up(&(curr_t->child_pinfo_list_sema));
}

static int
process_file_open(const char* file)
{
  struct file* f;
  int i, fd;

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

  return fd;
}

/* close all open files by the current process */
static void close_all_files(void)
{
   struct thread *curr_t = thread_current();
   int i;

   sema_down(&filesys_sema);
    
   for(i = 2; i < MAX_FILES; i++){
      if(curr_t->fd_table[i] != NULL){
         file_close(curr_t->fd_table[i]);
         curr_t->fd_table[i] = NULL;
      }
    }

   sema_up(&filesys_sema);
}


static void unmmap_all_mmapped_file(void)
{
   int i;

   for(i = 0; i < MAX_FILES; i++)
   {
      struct mmap_file* mmap_file = thread_current()->mmap_file_table[i]; 

  
      if(mmap_file != NULL)
      {
         struct list_elem* e;

         sema_down(&frame_table_sema);

         for(e = list_begin(&mmap_file->page_list); e != list_end(&mmap_file->page_list); )
         {
            struct page* pg = list_entry(e, struct page, mmap_file_list_elem);
            free_page_frame(pg);
            e = list_next(e);
            list_remove(&(pg->mmap_file_list_elem));
            list_remove(&(pg->page_list_elem));        
            free(pg);
         }


         sema_down(&filesys_sema);
         file_close(thread_current()->mmap_file_table[i]->file);
         sema_up(&filesys_sema);

         free(mmap_file);
         thread_current()->mmap_file_table[i] = NULL;
         sema_up(&frame_table_sema);
      }
   }
}



