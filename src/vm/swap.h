#ifndef SWAP_H
#define SWAP_H

#include "vm/page.h"
#include "threads/thread.h"

void swap_init(void);
void write_page_to_swap(struct page*);
void read_page_from_swap(struct page*);
void delete_thread_swaps(struct thread*);

#endif
