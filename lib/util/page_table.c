#include <util/page_table.h>
#include <aos/slab.h>
#include <hashtable/hashtable.h>

// Helper function prototypes

// Page table initialization helpers

static errval_t create_initial_hashtables(struct paging_state *state, struct page_table_entry *l1_init, 
            struct page_table_entry *l2_init, struct page_table_entry *l3_init, lvaddr_t vaddr);
static errval_t allocate_initial_tables(struct paging_state* state, struct page_table_entry* l1_entry, 
            struct page_table_entry* l2_entry, struct page_table_entry* l3_entry, lvaddr_t vaddr);
static errval_t copy_table_and_put(struct paging_state *state, struct hashtable *current_level, 
            struct page_table_entry *entry, uint64_t index);

static errval_t insert_initial_pages_to_tables(struct paging_state *state, struct page_table_entry *pte_entry, 
            struct page_table_entry *ht_entry, struct page_table_entry *he_entry, lvaddr_t init_vaddr, lvaddr_t current_vaddr);

static errval_t copy_page_and_put(struct paging_state *state, struct hashtable *current_level, 
            struct page_table_entry *entry, uint64_t index);
static errval_t allocate_initial_slabs(struct paging_state *state, struct page_table_entry *pte_entry, struct page_table_entry *ht_entry,
            struct page_table_entry *he_entry, lvaddr_t *current_vaddr, struct capref page_table);

static errval_t copy_to_parent_and_map(struct capref table, struct capref entry, capaddr_t slot, uint64_t flags, uint64_t offset, uint64_t pte_count, struct capref mapping);


static bool is_foreign_table(struct capref table) {
    return (get_croot_addr(table) != CPTR_ROOTCN);
}


// Page table allocators

static errval_t pt_alloc(struct paging_state *st, enum objtype type, struct capref *ret);
static errval_t pt_alloc_l1(struct paging_state *st, struct capref *ret);
static errval_t pt_alloc_l2(struct paging_state *st, struct capref *ret);
static errval_t pt_alloc_l3(struct paging_state *st, struct capref *ret);

static errval_t init_slab_and_map(struct paging_state *st, struct slab_allocator *slab, size_t slab_size, struct page_table_entry *entry, 
            lvaddr_t *current_vaddr, struct capref page_table);
static errval_t refill_and_hashtable_put(struct paging_state *state, struct hashtable* ht, uint64_t key, void* value);
static errval_t map_frame_entry_to_table(struct capref table, struct page_table_entry *entry, 
            uint64_t index, size_t bytes, uint64_t offset, uint64_t flags);

// Allocator helpers:
static errval_t refill_page_table_slabs(struct paging_state *st, struct slab_allocator *slabs);
static void check_refill_elem_slab(struct page_table_state *state);
static errval_t alloc_page_table_entry(struct paging_state *state, struct page_table_entry **entry);
static struct hashtable *alloc_hashtable(struct page_table_state *state);
static errval_t create_table_and_put(struct paging_state *state, struct hashtable *current_level, 
            struct page_table_entry *entry, uint64_t index);
static errval_t alloc_and_map_table(struct paging_state *state, struct capref table, 
            struct page_table_entry* entry, uint64_t index, page_table_alloc alloc_func);
static errval_t alloc_and_map_frame_entry(struct paging_state *state, struct page_table_entry *table, 
            struct capref frame, uint64_t index, size_t num_pages, uint64_t offset, bool is_frame_start, uint64_t flags);

// Page table helpers
static errval_t ensure_vnodes(struct paging_state *state, lvaddr_t vaddr);


errval_t init_page_table_state(struct paging_state *state, struct capref root, uintptr_t init_vaddr, lvaddr_t *current_vaddr) {

    errval_t err;

    struct page_table_state *pt_state = &state->page_table_state;

    pt_state->root_pte.pt_ref = root;
    pt_state->root_pte.ref_slot = NULL_CAP; // There is no slot for the root


    *current_vaddr = init_vaddr;

    struct page_table_entry l1_init, l2_init, l3_init; // Temp stack space for table entries.
    err = allocate_initial_tables(state, &l1_init, &l2_init, &l3_init, init_vaddr);
    if (err_is_fail(err)) return err;

    
    struct page_table_entry pte_entry, ht_entry, he_entry; // Temp stack space for the slab entries
    err = allocate_initial_slabs(state, &pte_entry, &ht_entry, &he_entry, current_vaddr, l3_init.pt_ref);
    if (err_is_fail(err)) return err;
    

    // Now everything has memory, should be able to map.
    err = create_initial_hashtables(state, &l1_init, &l2_init, &l3_init, init_vaddr);
    if (err_is_fail(err)) return err;


    err = insert_initial_pages_to_tables(state, &pte_entry, &ht_entry, &he_entry, init_vaddr, *current_vaddr);

    DEBUG_PRINTF("paging_init_state: 2\n");
    DEBUG_PRINTF("current_vaddt: %lx\n", current_vaddr);


    return SYS_ERR_OK;
}

/**
 * Maps a frame at vaddr and returns a buf. Assumes vaddr is properly allocated
 */
errval_t map_new_frame(struct paging_state *state, lvaddr_t vaddr, size_t bytes) {
    // TODO: Can add superpage stuff here maybe?

    DEBUG_PRINTF("Mapping new frame to %p\n", vaddr);

    struct capref frame;
    size_t retbytes;
    errval_t err = frame_alloc(&frame, bytes, &retbytes);
    if (err_is_fail(err)) return err;

    err = map_frame(state, frame, vaddr, retbytes, 0, VREGION_FLAGS_READ_WRITE);

    if (err_is_fail(err)) {
        cap_destroy(frame);
    }

    return err;

}


errval_t map_frame(struct paging_state *state, struct capref frame, lvaddr_t vaddr, size_t bytes, size_t offset, uint64_t flags) {
    

    size_t page_nums = DIVIDE_ROUND_UP(bytes, BASE_PAGE_SIZE);
    size_t remaining_pages = page_nums;
    lvaddr_t current_vaddr = vaddr;
    size_t current_offset = offset;

    while (remaining_pages > 0) {
        size_t l2_index = VMSAv8_64_L2_INDEX(current_vaddr);
        size_t l3_index = VMSAv8_64_L3_INDEX(current_vaddr);

        // Calculate how many pages can be mapped in the current L2 table
        size_t pages_in_current_l2 = VMSAv8_64_PTABLE_NUM_ENTRIES - l3_index;
        size_t pages_to_map = (remaining_pages < pages_in_current_l2) ? remaining_pages : pages_in_current_l2;

        DEBUG_PRINTF("map_frame: Mapping %zu pages starting at vaddr: 0x%lx (L2 index: %zu, L3 index: %zu)\n",
                     pages_to_map, current_vaddr, l2_index, l3_index);
        DEBUG_PRINTF("map_frame: Remaining pages: %zu, pages_to_map: %zu\n", remaining_pages, pages_to_map);

        // Ensure the L3 table is allocated for the current vaddr
        errval_t err = ensure_vnodes(state, current_vaddr);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to ensure vnodes for vaddr: 0x%lx", current_vaddr);
            return err_push(err, LIB_ERR_VNODE_MAP);
        }

        // Retrieve the L3 table for the current vaddr
        struct page_table_entry *table = get_l3_table(state, current_vaddr);
        if (!table) {
            DEBUG_PRINTF("Failed to get L3 table for vaddr: 0x%lx\n", current_vaddr);
            return LIB_ERR_VNODE_MAP;
        }

        err = alloc_and_map_frame_entry(state, table, frame, l3_index, pages_to_map, current_offset, offset == current_offset, flags);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to allocate and map %ld frame entries at %lx\n", pages_to_map, current_vaddr);
            return err;
        }        


        // Retrieve the frame entry for the current vaddr
        struct page_table_entry *frame_entry = get_frame(state, current_vaddr);
        if (!frame_entry) {

            debug_dump_hw_ptables((void *) current_vaddr);

            DEBUG_PRINTF("Failed to get frame entry for vaddr: 0x%lx\n", current_vaddr);
            // Optionally, unmap the previously mapped region here
            return LIB_ERR_VREGION_NOT_FOUND;
        }

        frame_entry->data.fe.total_frame_bytes = bytes;

        // Update the tracking variables for the next iteration
        current_vaddr += pages_to_map * BASE_PAGE_SIZE;
        current_offset += pages_to_map * BASE_PAGE_SIZE;
        remaining_pages -= pages_to_map;
    }

    return SYS_ERR_OK;
}


/////////////
// Helpers //
/////////////

/**
 * Creates a table for this entry and puts it into the current_level at index
 */
static errval_t create_table_and_put(struct paging_state *state, struct hashtable *current_level, struct page_table_entry *entry, uint64_t index) {
    
    DEBUG_PRINTF("Creating new table and inserting it into table at %p\n", current_level);

    struct page_table_state *pt_state = &state->page_table_state;

    struct hashtable *table = alloc_hashtable(pt_state);
    if (table == NULL) {
        DEBUG_PRINTF("create_page_table_entry: slab_alloc failed\n");
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    // Replace the hash table slab allocator
    create_hashtable2_slab_fill(table, PAGE_TABLE_CAPACITY, &pt_state->slabs.hash_elem_slab);

    entry->data.pe.page_table = table;
    entry->is_page_table = true;

    errval_t err = refill_and_hashtable_put(state, current_level, index, (void *) entry);
    if (err) return LIB_ERR_VNODE_CREATE; // Idk what error to use here.

    return SYS_ERR_OK;
}

static errval_t insert_initial_pages_to_tables(struct paging_state *state, struct page_table_entry *pte_entry, 
    struct page_table_entry *ht_entry, struct page_table_entry *he_entry, lvaddr_t init_vaddr, lvaddr_t current_vaddr) {

    DEBUG_PRINTF("Inserting pages to tables\n");

    struct page_table_state *pt_state = &state->page_table_state;

    struct page_table_entry *l3_table = get_l3_table(state, init_vaddr);
    if (l3_table == NULL) {
        user_panic_fn("page_table.c", "insert_initial_pages_to_tables", 333, "L3 table was NULL");
    }

    lvaddr_t vaddr = init_vaddr;
    errval_t err;

    DEBUG_PRINTF("L3 table hash table: %p\n", &l3_table->data);
    DEBUG_PRINTF("Copying page table entry\n");

    err = copy_page_and_put(state, l3_table->data.pe.page_table, pte_entry, VMSAv8_64_L3_INDEX(vaddr));
    if (err) return err;

    vaddr += BASE_PAGE_SIZE;
    err = copy_page_and_put(state, l3_table->data.pe.page_table, ht_entry, VMSAv8_64_L3_INDEX(vaddr));
    if (err) return err;

    vaddr += BASE_PAGE_SIZE;
    err = copy_page_and_put(state, l3_table->data.pe.page_table, he_entry, VMSAv8_64_L3_INDEX(vaddr));
    if (err) return err;

    assert(vaddr + BASE_PAGE_SIZE == current_vaddr);
    
    return SYS_ERR_OK;
}


static errval_t refill_and_hashtable_put(struct paging_state *state, struct hashtable* ht, uint64_t key, void* value) {

    DEBUG_PRINTF("Calling refill and put with key: %d and value %p\n", key, value);

    struct page_table_state *pt_state = &state->page_table_state;

    check_refill_elem_slab(pt_state);

    return hashtable_put(ht, key, value);
}


/**
 * ALLOCATORS
 */
static void check_refill_elem_slab(struct page_table_state *state) {
    
    uint64_t min_size_needed = (PAGE_TABLE_CAPACITY * 3 + 4);// 3 hash tables (33) + 4 entries (4) + 1 (L1 + L2 + L3 + frame + extra)?

    uint64_t refill_amount = min_size_needed + PAGE_TABLE_CAPACITY; // If a hashtable is created, it needs PAGE_TABLE_CAPACITY slots, so there is a chance it is called at a bad time and we have no more space

    // refill_amount += 20; // extra space for fragmentation (idk how to deal with the fragmentation rn, I could check only the first slab, as that is the biggest one? but that does not help when we start dealing with free)

    DEBUG_PRINTF("Checking elem allocator, freecount: %ld, refill_amount %ld\n", slab_freecount(&state->slabs.hash_elem_slab), refill_amount)

    if (state->slabs.hash_elem_slab.slabs->free <= refill_amount && !state->slabs.hash_elem_is_refilling) { 
        
        DEBUG_PRINTF("REFILLING ELEM ALLOCATOR\n");
        
        state->slabs.hash_elem_is_refilling = true;
        slab_default_refill(&state->slabs.hash_elem_slab); // TODO: foreign state, this refills it for the parent, we need a specific one for the child.
        state->slabs.hash_elem_is_refilling = false;

        DEBUG_PRINTF("DONE REFILLING ELEM ALLOCATOR, NEW SIZE: %ld\n", slab_freecount(&state->slabs.hash_elem_slab));
    } 
}

/**
 * Creates a frame entry without a frame in it, returns the frame into entry.
 */
static errval_t alloc_page_table_entry(struct paging_state *state, struct page_table_entry **entry) {

    struct page_table_state *pt_state = &state->page_table_state;

    if (slab_freecount(&pt_state->slabs.entry_slab) < 10 && !pt_state->slabs.entry_slab_is_refilling) {
        pt_state->slabs.entry_slab_is_refilling = true;
        slab_default_refill(&pt_state->slabs.entry_slab);
        pt_state->slabs.entry_slab_is_refilling = false;
    }

    *entry = slab_alloc(&state->page_table_state.slabs.entry_slab);

    state->slot_alloc->alloc(state->slot_alloc, &(*entry)->ref_slot);

    
    if (entry == NULL) {
        DEBUG_PRINTF("create_page_table_entry: slab_alloc failed\n");
        return MM_ERR_OUT_OF_MEMORY; // TODO: use a better error
    }

    return SYS_ERR_OK;
}

static struct hashtable *alloc_hashtable(struct page_table_state *state) {
    

    check_refill_elem_slab(state);

    if (slab_freecount(&state->slabs.hash_table_slab) < 6 && !state->slabs.htable_slab_is_refilling) {

        DEBUG_PRINTF("REFILLING HASHTABLE ALLOCATOR\n");

        state->slabs.htable_slab_is_refilling = true;
        slab_default_refill(&state->slabs.hash_table_slab);
        state->slabs.htable_slab_is_refilling = false;

        DEBUG_PRINTF("DONE REFILLING HASHTABLE ALLOCATOR\n");
    }

    return slab_alloc(&state->slabs.hash_table_slab);
}


/**
 * Allocates the initial L1, L2, and L3 tables.
 */
static errval_t allocate_initial_tables(struct paging_state* state, struct page_table_entry* l1_entry, 
                struct page_table_entry* l2_entry, struct page_table_entry* l3_entry, lvaddr_t vaddr) {
    errval_t err;
    
    DEBUG_PRINTF("Allocating initial tables\n");

    struct page_table_state *pt_state = &state->page_table_state;
    
    // alloc initial tables
    err = alloc_and_map_table(state, pt_state->root_pte.pt_ref, l1_entry, VMSAv8_64_L0_INDEX(vaddr), pt_alloc_l1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Error allocating initial L1 table");
        return err;
    }

    err = alloc_and_map_table(state, l1_entry->pt_ref, l2_entry, VMSAv8_64_L1_INDEX(vaddr), pt_alloc_l2);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Error allocating initial L2 table");
        return err;
    }

    err = alloc_and_map_table(state, l2_entry->pt_ref, l3_entry, VMSAv8_64_L2_INDEX(vaddr), pt_alloc_l3);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Error allocating initial L3 table");
        return err;
    }

    return SYS_ERR_OK;
}

static errval_t allocate_initial_slabs(struct paging_state *state, struct page_table_entry *pte_entry, struct page_table_entry *ht_entry,
        struct page_table_entry *he_entry, lvaddr_t *current_vaddr, struct capref page_table) {
    
    DEBUG_PRINTF("Allocating page_table_state slabs\n");

    errval_t err;

    struct page_table_state *pt_state = &state->page_table_state;

    err = init_slab_and_map(state, &pt_state->slabs.entry_slab, sizeof(struct page_table_entry), pte_entry, current_vaddr, page_table);
    if (err_is_fail(err)) {
        return err;
    }
    DEBUG_PRINTF("(after init pte_slab) current_vaddr:%lx\n", current_vaddr);

    err = init_slab_and_map(state, &pt_state->slabs.hash_table_slab, sizeof(struct hashtable), ht_entry, current_vaddr, page_table);
    if (err_is_fail(err)) {
        return err;
    } 
    DEBUG_PRINTF("(after init htable_slab) current_vaddr:%lx\n", current_vaddr);

    err = init_slab_and_map(state, &pt_state->slabs.hash_elem_slab, sizeof(struct _ht_entry), he_entry, current_vaddr, page_table);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}


static errval_t create_and_map_frame_entry(struct capref page_table, struct page_table_entry* entry, uint64_t index, size_t size) {
    
    DEBUG_PRINTF("Create and map frame entry\n");

    size_t retbytes;
    errval_t err = frame_alloc(&entry->pt_ref, size, &retbytes);
    if (err_is_fail(err)) return err;

    err = slot_alloc(&entry->ref_slot);
    if (err_is_fail(err)) return err; // TODO: do proper error handling

    entry->is_page_table = false;
    return map_frame_entry_to_table(page_table, entry, index, DIVIDE_ROUND_UP(retbytes, BASE_PAGE_SIZE), 0, VREGION_FLAGS_READ_WRITE);
}


/**
 * @brief Helper function to handle slab initialization and mapping
 * @param[in] slab              pointer to slab allocator we are initializing
 * @param[in] slab_size         size of blocks to be allocated by this slab
 * @param[in] frame             pointer to capref struct we are filling in to create a new cap frame
 * @param[in] frame_slots       we allocate a slot and this is pointer to the allocated slot
 * @param[in] current_vaddr     start vaddr for the initial slab
 * @param[in] page_table          capref pointer where we store the Vnode
 * @param[in] page_num          number of pages we are allocating
 */
static errval_t init_slab_and_map(struct paging_state *st, struct slab_allocator *slab, size_t slab_size, struct page_table_entry *entry, 
                        lvaddr_t *current_vaddr, struct capref page_table) {

    DEBUG_PRINTF("init_slab_and_map called with slab_size:%zu \n", slab_size);

    // Initialize slab
    slab_init(slab, slab_size, NULL);

    errval_t err = create_and_map_frame_entry(page_table, entry, VMSAv8_64_L3_INDEX(*current_vaddr), BASE_PAGE_SIZE);
    if (err_is_fail(err)) return err;
    entry->data.fe.is_frame_start = true;

    DEBUG_PRINTF("BEFORE SLAB_GROW\n");

    if (st != get_current_paging_state()) {
        err = paging_map_fixed(get_current_paging_state(), *current_vaddr + CHILD_VADDR_OFFSET, entry->pt_ref, BASE_PAGE_SIZE);
        if (err_is_fail(err)) return err; // Should do some cleanup but if this fails something went horrbly wrong.

        slab_grow(slab, (void*) (*current_vaddr + CHILD_VADDR_OFFSET), BASE_PAGE_SIZE);
    } else {
        slab_grow(slab, (void*) (*current_vaddr), BASE_PAGE_SIZE);
    }
    

    *current_vaddr += BASE_PAGE_SIZE;
    // Grow slab and update the current virtual address
    return SYS_ERR_OK;
}

static errval_t copy_table_and_put(struct paging_state *state, struct hashtable *current_level, struct page_table_entry *entry, uint64_t index) {
    
    struct page_table_state *pt_state = &state->page_table_state;

    struct page_table_entry *new_entry = slab_alloc(&pt_state->slabs.entry_slab);

    new_entry->is_page_table = true;
    new_entry->pt_ref = entry->pt_ref;
    new_entry->ref_slot = entry->ref_slot;

    return create_table_and_put(state, current_level, new_entry, index);

}

static errval_t refill_page_table_slabs(struct paging_state *st, struct slab_allocator *slabs) {
    errval_t err;
    if (st != get_current_paging_state()) {
        void *slab_buf;
        struct capref frame;
        size_t retbytes;

        err = st->slot_alloc->alloc(st->slot_alloc, &frame);
        if (err_is_fail(err)) return err;
        err = frame_create(frame, BASE_PAGE_SIZE, &retbytes);
        if (err_is_fail(err)) return err;

        err = paging_map_frame(st, &slab_buf, retbytes, frame); // map to child and get address
        if (err_is_fail(err)) return err;
        err = paging_map_fixed(get_current_paging_state(), (lvaddr_t) (slab_buf + CHILD_VADDR_OFFSET), frame, retbytes); // map to parent
        if (err_is_fail(err)) return err;

        slab_grow((struct slab_allocator*) slabs, (lvaddr_t) (slab_buf + CHILD_VADDR_OFFSET), retbytes);

    } else {
        return slab_default_refill(slabs);
    }
}

static errval_t map_frame_entry_to_table(struct capref table, struct page_table_entry *entry, 
        uint64_t index, size_t num_pages, uint64_t offset, uint64_t flags) {
    
    DEBUG_PRINTF("Mapping %ld entries into table\n", num_pages);

    assert(!entry->is_page_table);

    errval_t err;

    
    debug_print_cap_at_capref(table);
    DEBUG_PRINTF("Tried to map at index %d for %d pages with %d offset\n", index, num_pages, offset);


    if (is_foreign_table(table)) {
        DEBUG_PRINTF("Foreign table found\n");

        err = copy_to_parent_and_map(table, entry->pt_ref, index, flags, offset, num_pages, entry->ref_slot);
        if (err_is_fail(err)) return err;

    } else {
        err = vnode_map(table, entry->pt_ref, index, flags, offset, num_pages, entry->ref_slot);
        if (err_is_fail(err)) return err;
    }

    entry->data.fe.flags = VREGION_FLAGS_READ_WRITE;
    entry->data.fe.frame_size = num_pages * BASE_PAGE_SIZE;
    entry->data.fe.page_nums = num_pages;

    return SYS_ERR_OK;
}

static errval_t create_initial_hashtables(struct paging_state *state, struct page_table_entry *l1_init, 
            struct page_table_entry *l2_init, struct page_table_entry *l3_init, lvaddr_t vaddr) {

    DEBUG_PRINTF("Creating initial hashtables\n");

    struct page_table_state *pt_state = &state->page_table_state;

    pt_state->root_pte.data.pe.page_table = (struct hashtable*) slab_alloc(&pt_state->slabs.hash_table_slab);
    pt_state->root_pte.is_page_table = true;

    struct page_table_entry *current_entry = &pt_state->root_pte;
    struct hashtable *current_level = pt_state->root_pte.data.pe.page_table;

    create_hashtable2_slab_fill(current_level, PAGE_TABLE_CAPACITY, &pt_state->slabs.hash_elem_slab);

    errval_t err;


    err = copy_table_and_put(state, current_level, l1_init, VMSAv8_64_L0_INDEX(vaddr));
    if (err_is_fail(err)) return err;

    current_entry = (struct page_table_entry*) hashtable_get(current_level, VMSAv8_64_L0_INDEX(vaddr)); // Get next level of hashtable
    current_level = current_entry->data.pe.page_table;

    err = copy_table_and_put(state, current_level, l2_init, VMSAv8_64_L1_INDEX(vaddr));
    if (err_is_fail(err)) return err;

    current_entry = hashtable_get(current_level, VMSAv8_64_L1_INDEX(vaddr)); // Get next level of hashtable
    current_level = current_entry->data.pe.page_table;

    err = copy_table_and_put(state, current_level, l3_init, VMSAv8_64_L2_INDEX(vaddr));
    if (err_is_fail(err)) return err;

    return SYS_ERR_OK;
}

/**
 * Allocates a frame, maps it to the table and puts it into the page table
 */
static errval_t alloc_and_map_frame_entry(struct paging_state *state, struct page_table_entry *table, struct capref frame, uint64_t index, size_t num_pages, uint64_t offset, bool is_frame_start, uint64_t flags) {
    
    struct page_table_entry *frame_entry;
    errval_t err = alloc_page_table_entry(state, &frame_entry);
    if (err_is_fail(err)) return err;

    frame_entry->pt_ref = frame;
    frame_entry->is_page_table = false;

    err = map_frame_entry_to_table(table->pt_ref, frame_entry, index, num_pages, offset, flags); // TODO: can change with superpaging
    if (err_is_fail(err)) {
        slab_free(&state->page_table_state.slabs.entry_slab, frame_entry);
        
        return err;
    } // TODO: clean up

    frame_entry->data.fe.is_frame_start = is_frame_start;

    err = refill_and_hashtable_put(state, table->data.pe.page_table, index, frame_entry);
    if (err_is_fail(err)) return err; // TODO: clean up

    return SYS_ERR_OK;
}

static errval_t alloc_and_map_table(struct paging_state *state, struct capref table, 
        struct page_table_entry* entry, uint64_t index, page_table_alloc alloc_func) {

    struct page_table_state *pt_state = &state->page_table_state;

    debug_print_cap_at_capref(table);

    errval_t err = alloc_func(state, &entry->pt_ref);
    if (err_is_fail(err)) {
        return err;
    }

    DEBUG_PRINTF("alloc_and_map_table - table.cnode.croot = %lx\n", table.cnode.croot);
    DEBUG_PRINTF("alloc_and_map_table - table.cnode.cnode = %lx\n", table.cnode.cnode);
    DEBUG_PRINTF("alloc_and_map_table - entry->pt_ref.cnode.croot = %lx\n", entry->pt_ref.cnode.croot);
    DEBUG_PRINTF("alloc_and_map_table - entry->pt_ref.cnode.cnode = %lx\n", entry->pt_ref.cnode.cnode);


    state->slot_alloc->alloc(state->slot_alloc, &entry->ref_slot);

    if (is_foreign_table(table)) {
        err = copy_to_parent_and_map(table, entry->pt_ref, index, VREGION_FLAGS_READ_WRITE, 0, 1, entry->ref_slot);
    } else {
        err = vnode_map(table, entry->pt_ref, index, VREGION_FLAGS_READ_WRITE, 0, 1, entry->ref_slot);
    }

    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

static errval_t copy_page_and_put(struct paging_state *state, struct hashtable *current_level, struct page_table_entry *entry, uint64_t index) {
    
    struct page_table_state *pt_state = &state->page_table_state;

    struct page_table_entry *new_entry = slab_alloc(&pt_state->slabs.entry_slab);

    DEBUG_PRINTF("new_entry %p\n", new_entry);

    new_entry->is_page_table = false;
    new_entry->pt_ref = entry->pt_ref;
    new_entry->ref_slot = entry->ref_slot;
    new_entry->data.fe = entry->data.fe;

    errval_t err = refill_and_hashtable_put(state, current_level, index, new_entry);
    if (err_is_fail(err)) return LIB_ERR_VNODE_CREATE; // Idk what error to use here.

    return SYS_ERR_OK;
}


static errval_t copy_to_parent_and_map(struct capref table, struct capref entry, capaddr_t slot, 
            uint64_t flags, uint64_t offset, uint64_t pte_count, struct capref mapping) {

    errval_t err;
    struct capref copied_table;
    err = slot_alloc(&copied_table);
    if (err_is_fail(err)) return err;

    err = cap_copy(copied_table, table);
    if (err_is_fail(err)) return err;

    err = vnode_map(copied_table, entry, slot, flags, offset, pte_count, mapping);
    if (err_is_fail(err)) return err;

    cap_destroy(copied_table);

    return SYS_ERR_OK;
}


static errval_t ensure_vnodes(struct paging_state *state, lvaddr_t vaddr)
{
    DEBUG_PRINTF("ensure_vnodes called with vaddr: %lx\n", vaddr);
    // errval_t err;

    // TODO: fix error handling

    // ensure L1 table
    struct page_table_entry *table = &state->page_table_state.root_pte;
    struct page_table_entry *entry;

    entry = get_l1_table(state, vaddr);
    if (entry == NULL) {
        assert(table->is_page_table);
        alloc_page_table_entry(state, &entry);
        alloc_and_map_table(state, table->pt_ref, entry, VMSAv8_64_L0_INDEX(vaddr), pt_alloc_l1);
        create_table_and_put(state, table->data.pe.page_table, entry, VMSAv8_64_L0_INDEX(vaddr));
    }
    table = entry; // table is now L1 table

    entry = get_l2_table(state, vaddr);
    if (entry == NULL) {
        assert(table->is_page_table);
        alloc_page_table_entry(state, &entry);
        alloc_and_map_table(state, table->pt_ref, entry, VMSAv8_64_L1_INDEX(vaddr), pt_alloc_l2);
        create_table_and_put(state, table->data.pe.page_table, entry, VMSAv8_64_L1_INDEX(vaddr));
    }
    table = entry; // table is now L2 table
    
    entry = get_l3_table(state, vaddr);
    if (entry == NULL) {
        assert(table->is_page_table);
        alloc_page_table_entry(state, &entry);
        alloc_and_map_table(state, table->pt_ref, entry, VMSAv8_64_L2_INDEX(vaddr), pt_alloc_l3);
        create_table_and_put(state, table->data.pe.page_table, entry, VMSAv8_64_L2_INDEX(vaddr));
    }
    
    DEBUG_PRINTF("ensure_vnodes: end!!\n");
    return SYS_ERR_OK;
}



/**
 * Page table entry getters
 */
struct page_table_entry *get_l1_table(struct paging_state *state, lvaddr_t vaddr)
{
    DEBUG_PRINTF("L0 table entry: %p\n", &state->page_table_state.root_pte);
    debug_print_cap_at_capref(state->page_table_state.root_pte.pt_ref);

    return hashtable_get(state->page_table_state.root_pte.data.pe.page_table, VMSAv8_64_L0_INDEX(vaddr));
}

struct page_table_entry *get_l2_table(struct paging_state *state, lvaddr_t vaddr)
{
    struct page_table_entry *l1_table = get_l1_table(state, vaddr);
    DEBUG_PRINTF("L1 table entry: %p\n", l1_table);
    if (l1_table == NULL || !l1_table->is_page_table) {
        return NULL;
    }
    debug_print_cap_at_capref(l1_table->pt_ref);
    return (struct page_table_entry*)hashtable_get(l1_table->data.pe.page_table, VMSAv8_64_L1_INDEX(vaddr));
}

struct page_table_entry *get_l3_table(struct paging_state *state, lvaddr_t vaddr)
{
    struct page_table_entry *l2_table = get_l2_table(state, vaddr);
    if (l2_table == NULL || !l2_table->is_page_table) {
        return NULL;
    }
    DEBUG_PRINTF("L2 table entry: %p\n", l2_table);
    return (struct page_table_entry*)hashtable_get(l2_table->data.pe.page_table, VMSAv8_64_L2_INDEX(vaddr));
}

struct page_table_entry *get_frame(struct paging_state *state, lvaddr_t vaddr)
{
    struct page_table_entry *l3_table = get_l3_table(state, vaddr);
    DEBUG_PRINTF("L3 table entry: %p\n", l3_table);
    if (l3_table == NULL || !l3_table->is_page_table) {
        return NULL;
    }
    debug_print_cap_at_capref(l3_table->pt_ref);
    return (struct page_table_entry*)hashtable_get(l3_table->data.pe.page_table, VMSAv8_64_L3_INDEX(vaddr));
}





/**
 * @brief allocates a new page table for the given paging state with the given type
 *
 * @param[in]  st    paging state to allocate the page table for (required for slot allcator)
 * @param[in]  type  the type of the page table to create
 * @param[out] ret   returns the capref to the newly allocated page table
 *
 * @returns error value indicating success or failure
 *   - @retval SYS_ERR_OK if the allocation was successfull
 *   - @retval LIB_ERR_SLOT_ALLOC if there couldn't be a slot allocated for the new page table
 *   - @retval LIB_ERR_VNODE_CREATE if the page table couldn't be created
 */
static errval_t pt_alloc(struct paging_state *st, enum objtype type, struct capref *ret)
{
    errval_t err;

    assert(type == ObjType_VNode_AARCH64_l0 || type == ObjType_VNode_AARCH64_l1
           || type == ObjType_VNode_AARCH64_l2 || type == ObjType_VNode_AARCH64_l3);

    // try to get a slot from the slot allocator to hold the new page table
    err = st->slot_alloc->alloc(st->slot_alloc, ret);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    // create the vnode in the supplied slot
    err = vnode_create(*ret, type);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_VNODE_CREATE);
    }

    return SYS_ERR_OK;
}

static errval_t pt_alloc_l1(struct paging_state *st, struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l1, ret);
}

static errval_t pt_alloc_l2(struct paging_state *st, struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l2, ret);
}

static errval_t pt_alloc_l3(struct paging_state *st, struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l3, ret);
}