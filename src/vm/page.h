#ifndef PAGE_H
#define PAGE_H

#include <hash.h>
#include "devices/block.h"
#include "filesys/off_t.h"

enum page_location
  {
     /* Add more if needed... */
     INIT,                        /* Init state: It doesn't reside anywhere */
     PHYSICAL,                    /* Physical memory (Frame Table) */
     SWAP,                        /* Swap space */
     FS_FILE                      /* File in filesystem */
  };

struct file_load_info
  {
    struct file* file;
    size_t page_read_bytes;
    size_t page_zero_bytes;
    off_t offset;
  };

struct page 
  {
    uint32_t* pd;
    void* upage;
    void* kpage;                    /* Frame Table: Kernel virtual address and 
                                       corresponding frame */ 
    bool writable;
    bool was_loaded;                /* Was a loadable page from the filesystem*/
    bool never_modified;            /* Page has ever been modified */
    bool is_mmapped_file;           /* Page contains a memory mapped file */

    enum page_location location;    /* Location of page data */

    bool pinned;

    /* Frame Table variables */
    struct hash_elem ft_hash_elem;         /* Frame table hash elem */
    struct list_elem fifo_list_elem;       /* List element for FIFO list */
    struct list_elem mmap_file_list_elem;  /* List element for memory mapping*/
    struct hash_elem spt_hash_elem;        /* Keep list of all process pages */
    bool ref_bit;                          /* Reference bit for 2nd chance */

    /* Supplemental Page Table variables */
    struct file_load_info load_info;       /* Information to load page from FS*/
    struct list_elem page_list_elem;       /* SPT list element */

    /* Swap Table variables */
    struct hash_elem swap_hash_elem;       /* Swap table hash elem */
    block_sector_t block_idx;              /* Swap: Sector in swap device */

  };

void page_init(struct thread*);
struct page* add_page_to_spt(struct thread*, void*, void*);
struct page* get_page_from_spt(struct thread*, void*);
void load_page_from_file(struct page*);
void write_page_to_file(struct page* pg);
void free_page_structs(struct thread*);
void zero_page(struct page*);
bool increase_stack(struct page**, void*, void*);

#endif
