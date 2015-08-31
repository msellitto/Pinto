#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bitmap.h>
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
struct semaphore swap_table_sema;  /* Semaphore to synch access to swap table */
struct bitmap* swap_bitmap;
struct block* swap_block;

/* Initialize swap structures */
void swap_init()
{
   uint32_t num_blocks;

   if((swap_block = block_get_role(BLOCK_SWAP)) == NULL)
   {
      printf("swap_init: No block device with role BLOCK_SWAP\n");
      thread_exit();
   }

   num_blocks = block_size(swap_block);

   if((swap_bitmap = bitmap_create(num_blocks)) == NULL){
      printf("Failed to allocate swap bitmap\n");
      thread_exit();
   }

   return;
}

/* Write a page to swap */
void write_page_to_swap(struct page* pg) {
   size_t swap_idx;
   int num_sectors = (PGSIZE / BLOCK_SECTOR_SIZE);
   int idx;

   /* Find an empty swap slot using bitmap */
   if((swap_idx = 
      bitmap_scan_and_flip(swap_bitmap, 0, num_sectors, false)) == BITMAP_ERROR)
   {
      PANIC("Out of Swap Space\n");
   } 
   pg->block_idx = swap_idx;

   /* Copy the data to the appropriate swap slot */
   for(idx = 0; idx < num_sectors; idx++){
      block_write(swap_block, swap_idx + idx, 
                  pg->kpage + (BLOCK_SECTOR_SIZE * idx));
   }

   return;
}

/* Read a page from swap into physical memory */
void read_page_from_swap(struct page* pg){
   int idx;
   int num_sectors = (PGSIZE / BLOCK_SECTOR_SIZE);

   create_frame_mapping(pg->upage, pg->kpage, pg->writable, pg->was_loaded);

   for(idx = 0; idx < num_sectors; idx++){
      block_read(swap_block, pg->block_idx + idx, 
                 pg->kpage + (BLOCK_SECTOR_SIZE * idx));
   }

   bitmap_scan_and_flip(swap_bitmap, pg->block_idx, num_sectors, true);

   return;
}

/* Delete the swap table entries of an exiting thread */
void delete_thread_swaps(struct thread* t)
{
   struct list_elem* e;
   int num_sectors = (PGSIZE / BLOCK_SECTOR_SIZE);

   for(e = list_begin(&t->page_list); e != list_end(&t->page_list); )
   {
      struct page* pg = list_entry(e, struct page, page_list_elem);
      e = list_next(e);

      if(pg->location == SWAP){
         bitmap_scan_and_flip(swap_bitmap, pg->block_idx, num_sectors, true);
      }
   }
}









