#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bitmap.h>
#include <random.h>
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

/* Global Variables */
struct hash frame_table;            /* Frame Table (FT): Stored as hash */
struct semaphore frame_table_sema;  /* Semaphore to synch access to FT */
struct list fifo_list;              /* FIFO to pick page to evict from FT */
struct page *next_page;             /* Next elem to evict using second chance */

/* Function prototypes */
unsigned frame_hash_func(const struct hash_elem*, void*);
void swap_page_out(struct page* page_in);
struct page* pick_page_to_swap_rand(void);
struct page* pick_page_to_swap_sc(void);
bool frame_hash_less_func(const struct hash_elem*, const struct hash_elem*, 
                          void*);


/* Initialize structures for Frame Table */
void frame_init(void)
{
   sema_init(&frame_table_sema, 1);

   hash_init(&frame_table, frame_hash_func, frame_hash_less_func, NULL);

   list_init(&fifo_list);

   next_page = NULL;

   random_init(0);

   return;
}

/* Specify hash function for hash to call on insert and lookup */
unsigned frame_hash_func(const struct hash_elem* p_, void* aux UNUSED){

   const struct page* p = hash_entry(p_, struct page, ft_hash_elem);

   return hash_bytes(&p->kpage, sizeof(p->kpage));
}

/* Less function required for hash to traverse lists within buckets */
bool 
frame_hash_less_func(const struct hash_elem *a_, const struct hash_elem *b_,
                     void* aux UNUSED){

   const struct page *a = hash_entry(a_, struct page, ft_hash_elem);
   const struct page *b = hash_entry(b_, struct page, ft_hash_elem);

   return a->kpage < b->kpage;
}

/* Obtains a free frame for page pg.  Internally modifies to kpage member
 * variable to reflect the frame it has been allocated to */
void obtain_frame_for_page(struct page* pg){
   void* kpage;
   
   struct thread *t = thread_current();

   kpage = palloc_get_page(PAL_USER);

   if(kpage == NULL){
      swap_page_out(pg);
   }
   else{
      pg->kpage = kpage;
   }

   /* Add a mapping to our frame table */
   hash_insert(&frame_table, &pg->ft_hash_elem);

   if(next_page == NULL){
      next_page = pg;
   }

   /* Add it to the FIFO queue */
   if((list_empty(&fifo_list)) || 
      (&next_page->fifo_list_elem  == list_front(&fifo_list))){
      list_push_front(&fifo_list, &pg->fifo_list_elem);
   }
   else{
      list_insert(&next_page->fifo_list_elem, &pg->fifo_list_elem);
   }

   pagedir_set_accessed(t->pagedir, pg->kpage, false);
   pagedir_set_accessed(t->pagedir, pg->upage, false);
   pagedir_set_dirty(t->pagedir, pg->kpage, false);
   pagedir_set_dirty(t->pagedir, pg->upage, false);

   return;
}


// Free the frame that the page pg is taking up and write it back to
// its backing store if necessary
void free_page_frame(struct page* pg){
   struct hash_elem* h;
   struct thread* t = thread_current();

   // if its not in physical memory, just return
   if(pg->location != PHYSICAL) return;

   /* Mark the virtual page "not present* in page directory so that later
    * accesses will fault */
   pagedir_clear_page(t->pagedir, pg->upage);

   /* If this page has been modified, it should always use swap from here on
    * out */
   if((pagedir_is_dirty(t->pagedir, pg->kpage)) ||
      (pagedir_is_dirty(t->pagedir, pg->upage)))
   {
      pg->never_modified = false;
   }

   /* If page was a loaded page and has never been modified, it is safe to 
    * just reuse the old version in the filesystem */
   if((pg->was_loaded) && (pg->never_modified)){
      pg->location = FS_FILE;
   }
   else{
      // if page is part of a memory mapped file
      if(pg->is_mmapped_file)
      {
         // if page is dirty, write it back to the file
         if((pagedir_is_dirty(t->pagedir, pg->kpage)) ||
            (pagedir_is_dirty(t->pagedir, pg->upage)))
         {
            write_page_to_file(pg);
         }
         list_remove(&pg->fifo_list_elem);
         pg->location = FS_FILE;
      }

      else
      {
         /* Otherwise, it is either a stack page or a data segment page, so we
          * must write it swap */
         pg->location = SWAP;
         write_page_to_swap(pg);
      }
   }

   /* Remove the mapping from the frame table */
   if((h = hash_delete(&frame_table, &pg->ft_hash_elem)) == NULL){
      //printf("swap_page_out: There was no hash to delete!!\n");
   }

   /* Free the frame the outgoing page used to occupy */
   palloc_free_page(pg->kpage);

   return;
}


/* Swap a page out to memory and give that frame to a new page */
void swap_page_out(struct page* page_in){
   struct page* page_out;

   page_out = pick_page_to_swap_sc();

   free_page_frame(page_out);

   if((page_in->kpage = palloc_get_page(PAL_USER)) == NULL){
      printf("swap_page_out: No page found\n");
      thread_exit();
   }

   return;
}

/* Pick a page to swap out based on the second chance algorithm */
struct page* pick_page_to_swap_sc(){
   struct page* page_out;
   struct list_elem* e;
   struct thread* t = thread_current();
   bool found = false;
   int its = 0;
   int idx;

   ASSERT (!list_empty(&fifo_list));
   ASSERT (next_page != NULL);

   its = 0;

   e = &next_page->fifo_list_elem;
   for(idx = 0; idx < 6; idx++){
      for(; e != list_end(&fifo_list);)
      {
         page_out = list_entry(e, struct page, fifo_list_elem);

         if(page_out->pinned){
            if(e->next != NULL){
               e = list_next(e);
               continue;
            }
            else{
               e = list_begin(&fifo_list);
               break;
            }
         }
         
         if(e->next != NULL){
            e = list_next(e);
         }
         else{
            e = list_begin(&fifo_list);
            break;
         }

         if(pagedir_is_accessed(t->pagedir, page_out->kpage) ||
            pagedir_is_accessed(t->pagedir, page_out->upage))
         {
            /* Reset its accessed bit */
            pagedir_set_accessed(t->pagedir, page_out->kpage, false);
            pagedir_set_accessed(t->pagedir, page_out->upage, false);
         }
         else{
            list_remove(&page_out->fifo_list_elem);

            /* List is empty: There is no next page */
            if(list_empty(&fifo_list)){
               next_page = NULL;
            }
            /* 'e' currently points to the tail.  Make it point to the front
             * element (since we know now that the list is non-empty,
             * to simulate a circular buffer */
            else if(e == list_tail(&fifo_list)){
               e = list_front(&fifo_list);
               next_page = list_entry(e, struct page, fifo_list_elem);
            }
            else{
               /* 'e' is a middle element.  We can use it for our next
                * page */
               next_page = list_entry(e, struct page, fifo_list_elem);
            }

            found = true;
            return page_out;
         }
      }
      e = list_begin(&fifo_list);
   }

   if(!found) {
      PANIC("Cannot find a frame to release.  Too many pages pinned\n");
   }

   return page_out;
}

/* Randomly pick a page to swap out */
struct page* pick_page_to_swap_rand(){
   struct page* page_out;
   struct hash_iterator i;
   int count;
   bool found = false;
   int random;

   while(!found){
      random = (int)(random_ulong() % hash_size(&frame_table));
      
      count = 0;
      hash_first(&i, &frame_table);
      while(hash_next(&i))
      {
         page_out = hash_entry(hash_cur(&i), struct page, ft_hash_elem);
         if((count++ == random) && (!page_out->pinned)){
            found = true;
            break;
         }
      }
   }
   return page_out;
}

/* Create a mapping between a virtual and physical address */
bool create_frame_mapping(void* upage, void* kpage, bool writable, 
                          bool was_loaded)
{
   struct thread* t = thread_current ();
   struct page* pg; 

   pg = add_page_to_spt(t, upage, kpage);
   pg->writable = writable;
   pg->was_loaded = was_loaded;
   
   /* If upage is already mapped, return false */
   if(pagedir_get_page(t->pagedir, upage) != NULL){
      printf("create_frame_mapping: page already mapped\n");
      return false;
   }
   /* Map the user page to the kernel virtual address kpage */
   if(!pagedir_set_page (t->pagedir, upage, kpage, writable)){
      printf("create_frame_mapping: Could not set page\n");
      return false;
   }
   
   pg->location = PHYSICAL;

   pagedir_set_accessed(t->pagedir, pg->kpage, false);
   pagedir_set_accessed(t->pagedir, pg->upage, false);
   pagedir_set_dirty(t->pagedir, pg->kpage, false);
   pagedir_set_dirty(t->pagedir, pg->upage, false);

   return true;
}

/* Delete frames from frame table, remove them from the FIFO list, and clear
 * the page from the page table directory */
void delete_thread_frames(struct thread* t)
{
   struct list_elem* e;

   for(e = list_begin(&t->page_list); e != list_end(&t->page_list); )
   {
      struct page* pg = list_entry(e, struct page, page_list_elem);
      e = list_next(e);
      if(pg->location == PHYSICAL){
         hash_delete(&frame_table, &pg->ft_hash_elem);
         pg->location = INIT;
         list_remove(&pg->fifo_list_elem);
         pagedir_clear_page(t->pagedir, pg->upage);
         palloc_free_page(pg->kpage);
      }
   }
}

