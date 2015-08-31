#ifndef FRAME_H
#define FRAME_H

#include <hash.h>
#include "threads/thread.h"
#include "vm/page.h"

struct frame_table_bitmap
  {
     struct bitmap* bitmap;          /* Bitmap */
     size_t user_start;              /* Bit index to start user pages */
     size_t user_pages;              /* Number of user pages */
  };

extern struct semaphore frame_table_sema;

void frame_init(void);
void init_frame_table_bitmap(size_t, size_t);
bool create_frame_mapping(void*, void*, bool, bool);
void obtain_frame_for_page(struct page*);
void delete_thread_frames(struct thread*);
void free_page_frame(struct page* pg);

#endif
