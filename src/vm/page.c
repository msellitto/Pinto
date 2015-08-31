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

/* SPT --> Supplemental Page Table */
unsigned spt_hash_func(const struct hash_elem*, void*);
bool spt_hash_less_func(const struct hash_elem*, 
                        const struct hash_elem*, void*);

/* Initialize the Supplemental Page Table hash */
void page_init(struct thread* t)
{
   hash_init(&t->sp_table, spt_hash_func, spt_hash_less_func, NULL);

   return;
}

/* Hash function required for hash insert and lookup */
unsigned spt_hash_func(const struct hash_elem* p_, void* aux UNUSED){

   const struct page* p = hash_entry(p_, struct page, spt_hash_elem);

   /* Hash on the virtual address */
   return hash_bytes(&p->upage, sizeof(p->upage));
}

/* Hash less function required to traverse the list attached to a hash bucket */
bool
spt_hash_less_func(const struct hash_elem *a_, const struct hash_elem *b_,
                     void* aux UNUSED){

   const struct page *a = hash_entry(a_, struct page, spt_hash_elem);
   const struct page *b = hash_entry(b_, struct page, spt_hash_elem);

   return a->upage < b->upage;
}

/* Returns a page struct with the given upage and kpage mapping, or creates a
 * new page struct if no such struct already exists. 
 */
struct page* add_page_to_spt(struct thread* t, void* upage, void* kpage){
   struct page* pg;

   pg = get_page_from_spt(t, upage);

   /* Page did not already exist in Supplemental Page Table.  
    * Create a page and add it */
   if(pg == NULL){
      pg = malloc(sizeof(struct page));
      memset(pg, 0, sizeof(struct page));
      pg->kpage = kpage;
      pg->upage = upage;
      pg->pinned = false;
      pg->never_modified = true;
      pg->location = INIT;

      hash_insert(&t->sp_table, &pg->spt_hash_elem);
      list_push_back(&t->page_list, &pg->page_list_elem);
   }

   return pg;
}

/* Find a page correponding to virtual address upage in the supplemental
 * page table of the given thread.  If no such page exists, return NULL
 */
struct page* get_page_from_spt(struct thread* t, void* upage){
   struct page* pg;
   struct hash_elem* h_elem;
   struct page* pg_tmp = malloc(sizeof(struct page));

   pg_tmp->upage = upage;

   h_elem = hash_find(&t->sp_table, &pg_tmp->spt_hash_elem);
   if(h_elem == NULL){
      free(pg_tmp);
      return NULL;
   }
   else{
      pg = hash_entry(h_elem, struct page, spt_hash_elem);
      free(pg_tmp);
      return pg;
   }
}

/* Increase the size of the stack */
bool increase_stack(struct page** pg, void* fault_addr, void* esp)
{
   bool retval = true;
   struct thread* t = thread_current();
   void* page_trunc;

   page_trunc = pg_round_down(fault_addr);

   if(fault_addr >= USERPROG_STACK_LIMIT_ADDR)
   {
      /* Fault address is ok only if its within 32 bytes of the user stack
       * pointer */
      if((esp - fault_addr) > 32) {
        retval = false;
      } 
      else
      {
        /* Grow the user stack by one page */
        *pg = add_page_to_spt(t, page_trunc, NULL);
        obtain_frame_for_page(*pg);
        zero_page(*pg);
        bool success = create_frame_mapping((*pg)->upage, (*pg)->kpage, true, 
              false);
        if(success) {
           retval = true;
        }
        else{
          retval = false;
        }
     }
  }
  else{
    /* Don't grow the stack; this address is invalid */
    retval = false;
  }
  return retval;
}

/* Load a page from file into memory */
void load_page_from_file(struct page* pg){

   file_seek(pg->load_info.file, pg->load_info.offset);

   /* Load the page */
   if(file_read(pg->load_info.file, pg->kpage, pg->load_info.page_read_bytes) !=
      (int) pg->load_info.page_read_bytes)
   {
      thread_exit();
   }

   memset(pg->kpage + pg->load_info.page_read_bytes, 0, 
         pg->load_info.page_zero_bytes);

   /* Add the page to the process's address space */
   if(!create_frame_mapping(pg->upage, pg->kpage, pg->writable, true)){
      thread_exit();
  }

  return;
}

/* Write a page to the filesystem */
void write_page_to_file(struct page* pg){

   sema_down(&filesys_sema);
   file_seek(pg->load_info.file, pg->load_info.offset);
   sema_up(&filesys_sema);

   /* Load the page */
   if(file_write(pg->load_info.file, pg->kpage, pg->load_info.page_read_bytes) 
      != (int) pg->load_info.page_read_bytes)
   {
      thread_exit();
   }

  return;
}

/* Zero contents of a page */
void zero_page(struct page* pg){
   memset(pg->kpage, 0, PGSIZE);
}

/* Remove a page from the supplemental page table and free its memory */
void free_page_structs(struct thread* t)
{
   struct list_elem* e;

   for(e = list_begin(&t->page_list); e != list_end(&t->page_list); )
   {
      struct page* pg = list_entry(e, struct page, page_list_elem);
      e = list_next(e);
      list_remove(&(pg->page_list_elem));
      memset(pg, 0, sizeof(struct page));
      free(pg);
   }
}

