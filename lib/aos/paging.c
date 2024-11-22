/**
 * \file
 * \brief AOS paging helpers.
 */

#include <aos/aos.h>
#include <aos/paging.h>
#include <aos/except.h>
#include <aos/slab.h>
#include "threads_priv.h"

#include <stdio.h>
#include <string.h>

#include <util/bitmap.h>


#define EXCEPTION_STACK_SIZE 2*BASE_PAGE_SIZE + sizeof(arch_registers_state_t) + sizeof(uint64_t) // Look at threads.c:1462

// Not sure how to have a guard table on the stack, this might not work with multiple threads (will they overwrite each other?).
static uintptr_t static_exceptionhandler_stack[EXCEPTION_STACK_SIZE / sizeof(uintptr_t)]
__attribute__((aligned(sizeof(uint64_t)))); 

static struct paging_state current;


/**
 * @brief initializes the paging state struct for the current process
 *
 * @param[in] st           the paging state to be initialized
 * @param[in] start_vaddr  start virtual address to be managed
 * @param[in] root         capability to the root leve page table
 * @param[in] ca           the slot allocator instance to be used
 *
 * @return SYS_ERR_OK on success, or LIB_ERR_* on failure
 */
errval_t paging_init_state(struct paging_state *st, lvaddr_t start_vaddr, struct capref root, struct slot_allocator *ca)
{
    DEBUG_PRINTF("paging_init called with start_vaddr:%lx\n", start_vaddr);
    // 0. initialize the paging state
    st->virtual_mm.start_vaddr = start_vaddr;
    st->slot_alloc = ca;

    DEBUG_PRINTF("paging_init_state: 1\n");
    // 1. create base page tables to use for slab allocation
    lvaddr_t current_vaddr;
    
    errval_t err = init_page_table_state(st, root, start_vaddr, &current_vaddr);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed initializing page_table\n");
        return err;
    }

    DEBUG_PRINTF("current_vaddr: %lx\n", current_vaddr);

    err = init_vmm(st, start_vaddr, current_vaddr);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed initializing vmm\n");
        return err;
    }

    assert(st->page_table_state.root_pte.data.pe.page_table != NULL);
    assert(get_l1_table(st, start_vaddr) != NULL);
    assert(get_l2_table(st, start_vaddr) != NULL);
    assert(get_l3_table(st, start_vaddr) != NULL);
    assert(get_frame(st, start_vaddr) != NULL);
    assert(get_frame(st, start_vaddr + BASE_PAGE_SIZE * 1) != NULL);
    assert(get_frame(st, start_vaddr + BASE_PAGE_SIZE * 2) != NULL);
    assert(get_frame(st, start_vaddr + BASE_PAGE_SIZE * 3) != NULL);
    assert(get_frame(st, start_vaddr + BASE_PAGE_SIZE * 4) != NULL);
    
    DEBUG_PRINTF("INITIALIZED PAGE TABLES \n");
    return SYS_ERR_OK;
}


/**
 * @brief initializes the paging state struct for a foreign process when spawning a new one
 *
 * @param[in] st           the paging state to be initialized
 * @param[in] start_vaddr  start virtual address to be managed
 * @param[in] root         capability to the root leve page table
 * @param[in] ca           the slot allocator instance to be used
 *
 * @return SYS_ERR_OK on success, or LIB_ERR_* on failure
 */
errval_t paging_init_state_foreign(struct paging_state *st, lvaddr_t start_vaddr,
                                   struct capref root, struct slot_allocator *ca)
{
    // TODO (M3): Implement state struct initialization
    // ** Implementation:
    DEBUG_PRINTF("paging_init_state_foreign called with start_vaddr:%lx\n", start_vaddr);
    errval_t err;
    // TODO: do something beforehand
    // mapping before hand

    //struct capref mapping;
    debug_print_cap_at_capref(root);

    // is this being used?
    struct capref mapping;
    err = slot_alloc(&mapping);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    paging_init_state(st, start_vaddr, root, ca);

    return SYS_ERR_OK;
}

/**
 * @brief This function initializes the paging for this domain
 *
 * Note: The function is called once before main.
 */
errval_t paging_init(void)
{
    // TODO (M1): Call paging_init_state for &current

    // This root pagetable is used for only kernel? Not sure what to pass when other processes are created.
    // l0[0] was used, so start from l0[1]
    lvaddr_t start_vaddr = VADDR_OFFSET;
    set_current_paging_state(&current);
    paging_init_state(&current, start_vaddr, cap_vroot, get_default_slot_allocator());
    // TODO (M2): initialize self-paging handler
    // TIP: use thread_set_exception_handler() to setup a page fault handler
    // TIP: Think about the fact that later on, you'll have to make sure that
    // you can handle page faults in any thread of a domain.
    // TIP: it might be a good idea to call paging_init_state() from here to
    // avoid code duplication.
    set_current_paging_state(&current);

    exception_handler_fn old_handler;

    thread_set_exception_handler(page_fault_handler, &old_handler, static_exceptionhandler_stack, 
                static_exceptionhandler_stack + EXCEPTION_STACK_SIZE/sizeof(uintptr_t), NULL, NULL);

    current.old_handler = old_handler;

    DEBUG_PRINTF("paging_init finished\n");

    return SYS_ERR_OK;
}


/**
 * @brief frees up the resources allocate in the foreign paging state
 *
 * @param[in] st   the foreign paging state to be freed
 *
 * @return SYS_ERR_OK on success, or LIB_ERR_* on failure
 *
 * Note: this function will free up the resources of *the current* paging state
 * that were used to construct the foreign paging state. There should be no effect
 * on the paging state of the foreign process.
 */
errval_t paging_free_state_foreign(struct paging_state *st)
{
    // TODO: add some child number/offset to child paging states to differentiate between them
    (void)st;

    errval_t err;
    struct paging_state *curr = get_current_paging_state();
    struct vmm *vmm = &curr->virtual_mm;
    for (struct virtual_region *vr = vmm->virtual_regions; vr != NULL; vr = vr->next) {
        if (vr->base_addr > CHILD_VADDR_OFFSET) {
            for (size_t index = 0; index < vr->bitmap_size_aligned; index++) {
                if (bitmap_is_set(vr->bitmap, index)) {
                    err = paging_unmap(curr, (void *) (vr->base_addr + index * BASE_PAGE_SIZE));
                    if (err_is_fail(err)) return err;
                }
            }
        }
    }
    DEBUG_PRINTF("Done unmapping child pages\n");
    return SYS_ERR_OK;
}


/**
 * @brief Initializes the paging functionality for the calling thread
 *
 * @param[in] t   the tread to initialize the paging state for.
 *
 * This function prepares the thread to handing its own page faults
 */
errval_t paging_init_onthread(struct thread *t)
{
    // make compiler happy about unused parameters
    (void)t;

    void* stackbase;
    void* stacktop;

    errval_t err = allocate_exception_stack(t, &stackbase, &stacktop);

    if (err_is_fail(err)) return err;

    t->exception_handler = page_fault_handler;
    t->exception_stack = stackbase;
    t->exception_stack_top = stacktop;


    return SYS_ERR_OK;
}

/**
 * @brief Find and reserve(flip bitmap to 1) a free region of virtual address space that is large enough to accomodate a
 *        buffer of size 'bytes'.
 *
 * @param[in]  st          A pointer to the paging state to allocate from
 * @param[out] buf         Returns the free virtual address that was found.
 * @param[in]  bytes       The requested (minimum) size of the region to allocate
 * @param[in]  alignment   The address needs to be a multiple of 'alignment'.
 *
 * @return Either SYS_ERR_OK if no error occured or an error indicating what went wrong otherwise.
 */
errval_t paging_alloc(struct paging_state *st, void **buf, size_t bytes, size_t alignment)
{
    DEBUG_PRINTF("paging_alloc called with %d bytes and %d alignment, st is at %p\n", bytes, alignment, st);
    
    return vmm_alloc(st, buf, bytes, alignment);
}



/**
 * @brief Find and reserve (set bitmap to 1) a free region of virtual address space that is large enough to accommodate a buffer of size 'bytes' at a fixed address.
 *
 * This function attempts to allocate a region of virtual address space at a specific address `vaddr` with a given size and alignment.
 * If the address overlaps with an existing region or is not properly aligned, it will return an error. 
 * If the allocation succeeds, the corresponding bits in the region's bitmap will be marked as reserved.
 *
 * @param[in]  st          A pointer to the paging state to allocate from.
 * @param[in]  vaddr       The virtual address to allocate at.
 * @param[in]  bytes       The requested size (minimum) of the region to allocate.
 * @param[in]  alignment   The address must be a multiple of 'alignment'.
 * 
 * @return SYS_ERR_OK if the allocation succeeded or an error indicating what went wrong otherwise.
 */
errval_t paging_alloc_fixed(struct paging_state *st, lvaddr_t vaddr, size_t bytes, size_t alignment) {
    DEBUG_PRINTF("paging_alloc_fixed called with vaddr: %lx, bytes: %zu, alignment: %zu\n", vaddr, bytes, alignment);
    
    return vmm_alloc_fixed(st, vaddr, bytes, alignment);
}



/**
 * @brief maps a frame at a free virtual address region and returns its address
 *
 * @param[in]  st      paging state of the address space to create the mapping in
 * @param[out] buf     returns the virtual address of the mapped frame
 * @param[in]  bytes   the amount of bytes to be mapped
 * @param[in]  frame   frame capability of backing memory to be mapped
 * @param[in]  offset  offset into the frame capability to be mapped
 * @param[in]  flags   mapping flags
 *
 * @return SYS_ERR_OK on sucecss, LIB_ERR_* on failure.
 */
errval_t paging_map_frame_attr_offset(struct paging_state *st, void **buf, size_t bytes,
                                      struct capref frame, size_t offset, int flags)
{
    DEBUG_PRINTF("paging_map_frame_attr_offset: virtual_regions base: %lx\n", st->virtual_mm.virtual_regions->base_addr);
    // 1. Check for free virtual address space using paging_alloc()
    errval_t err = paging_alloc(st, buf, bytes, BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_OUT_OF_VIRTUAL_ADDR);
    }
    DEBUG_PRINTF("paging_map_frame_attr_offset: paging_alloc is done with vaddr: %lx, bytes: %zu\n", (lvaddr_t)*buf, bytes);
    // 2. Cast the allocated buffer to a virtual address
    lvaddr_t vaddr = (lvaddr_t)*buf;
    // 3. Map the physical frame to the virtual address
    return paging_map_reserved_vaddr(st, vaddr, frame, bytes, offset, flags);
}


/**
 * @brief Maps a frame at a free virtual address region and returns its address.
 *
 * This function maps a given frame into a reserved virtual address region within the
 * provided paging state. It handles cases where the mapping spans multiple L2 page tables.
 *
 * @param[in]  st       Paging state of the address space to create the mapping in.
 * @param[in]  vaddr    Starting virtual address for the mapping.
 * @param[in]  frame    Frame capability of backing memory to be mapped.
 * @param[in]  bytes    Number of bytes to be mapped.
 * @param[in]  offset   Offset into the frame capability to be mapped.
 * @param[in]  flags    Mapping flags.
 *
 * @return SYS_ERR_OK on success, LIB_ERR_* on failure.
 */
errval_t paging_map_reserved_vaddr(struct paging_state *st, lvaddr_t vaddr, struct capref frame,
                                   size_t bytes, size_t offset, int flags)
{
    DEBUG_PRINTF("paging_map_reserved_vaddr called with vaddr: 0x%lx, bytes: %zu (%zu pages)\n",
                 vaddr, bytes, (bytes + BASE_PAGE_SIZE - 1) / BASE_PAGE_SIZE);

    // Ensure all virtual addresses are reserved
    if (!is_all_vaddr_reserved(&st->virtual_mm, vaddr, DIVIDE_ROUND_UP(bytes, BASE_PAGE_SIZE))) {
        DEBUG_PRINTF("Virtual address range is not reserved\n");
        return LIB_ERR_VSPACE_REGION_OVERLAP;
    }

    errval_t err = map_frame(st, frame, vaddr, bytes, offset, flags);
    if (err_is_fail(err)) return err;

    DEBUG_PRINTF("paging_map_reserved_vaddr completed successfully\n");
    return SYS_ERR_OK;
}

/**
 * @brief maps a frame at a user-provided virtual address region
 *
 * @param[in] st      paging state of the address space to create the mapping in
 * @param[in] vaddr   provided virtual address to map the frame at
 * @param[in] frame   frame capability of backing memory to be mapped
 * @param[in] bytes   the amount of bytes to be mapped
 * @param[in] offset  offset into the frame capability to be mapped
 * @param[in] flags   mapping flags
 *
 * @return SYS_ERR_OK on success, LIB_ERR_* on failure
 *
 * The region at which the frame is requested to be mapped must be free (i.e., hasn't been
 * allocated), otherwise the mapping request shoud fail.
 */
errval_t paging_map_fixed_attr_offset(struct paging_state *st, lvaddr_t vaddr, struct capref frame,
                                      size_t bytes, size_t offset, int flags)
{
    DEBUG_PRINTF("paging_map_fixed_attr_offset is called\n");
    if(vaddr < MINIMUM_VADDR){
        return LIB_ERR_VSPACE_REGION_OVERLAP;
    }
    errval_t err;
    // Check if the vaddr is reserved
    err = paging_alloc_fixed(st, vaddr, bytes, BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_VSPACE_REGION_OVERLAP);
    }
    // Map the frame to the virtual address
    return paging_map_reserved_vaddr(st, vaddr, frame, bytes, offset, flags);

    // TODO(M2):
    //  - General case: you will need to handle mappings spanning multiple leaf page tables.
    //  - Make sure to update your paging state to reflect the newly mapped region
    //  - Map the user provided frame at the provided virtual address
    //
    // Hint:
    //  - think about what mapping configurations are actually possible
    //
}

/**
 * Handles mapping a frame for a page fault if it is allocated in the paging_state.
 */
void page_fault_handler(enum exception_type type, int subtype, void *addr, arch_registers_state_t *regs) {
    DEBUG_PRINTF("Page Fault Handler was called\n");
    DEBUG_PRINTF("Thread id %lx\n", thread_id());
    
    struct paging_state *curr = get_current_paging_state();

    if (type != EXCEPT_PAGEFAULT) curr->old_handler(type, subtype, addr, regs); // I don't know if we need this line

    // COPIED FROM dispatch.c:
    DEBUG_PRINTF("Page fault encountered (error code 0x%"
             PRIxPTR ") on %" PRIxPTR "\n",
             type, addr);

    lvaddr_t aligned_addr = trunc_page(addr);

    // It was a page fault
    if (!is_all_vaddr_reserved(&curr->virtual_mm, aligned_addr, 1)) {

        DEBUG_PRINTF("Addresses not reserved\n");

        // dump hw page tables
        debug_dump_hw_ptables(addr);
        debug_dump(regs);
        printf("Segmentation fault\n");
        exit(EXIT_FAILURE);
    }

    // Does a frame exist?
    if (get_frame(curr, aligned_addr)) {
        DEBUG_PRINTF("Frame found for address %p\n", aligned_addr);
        debug_dump_hw_ptables((void *)aligned_addr);
        return;
    }


    DEBUG_PRINTF("Allocating and mapping frame for pointer\n");
    errval_t err = map_new_frame(curr, aligned_addr, BASE_PAGE_SIZE);

    if (err_is_fail(err)) {
        // There was an error mapping the frame? maybe it was already mapped:
        if (get_frame(curr, aligned_addr)) return;
        else user_panic_fn("paging.c", "page_fault_handler", 77, "Error occured mapping the frame");
    }

    DEBUG_PRINTF("Frame was successfully allocated\n");
}

/**
 * Allocates the exception stack for the new thread.
 */
errval_t allocate_exception_stack(struct thread* t, void **stackbase, void **stacktop) {
    if ((uintptr_t) (t->stack_top - t->stack) <= EXCEPTION_STACK_SIZE) {
        DEBUG_ERR(LIB_ERR_VREGION_PAGEFAULT_HANDLER, "There was not enough size in the thread to properly handle exceptions");
        return LIB_ERR_VREGION_PAGEFAULT_HANDLER; // Is there a good error for this?
    }

    *stacktop = t->stack_top;
    t->stack_top -= EXCEPTION_STACK_SIZE;
    *stackbase = t->stack_top;

    errval_t err = map_new_frame(get_current_paging_state(), (lvaddr_t) *stackbase, (lvaddr_t) (*stacktop - *stackbase));

    DEBUG_ERR(err, "Error in allocate_exception_stack while mapping frame (Must already be mapped)");

    return SYS_ERR_OK;

}

/**
 * @brief Unmaps the region starting at the supplied pointer.
 *
 * @param[in] st      The paging state from which to unmap the region.
 * @param[in] region  Starting address of the region to unmap.
 *
 * @return SYS_ERR_OK on success, or an error code indicating the kind of failure.
 *
 * @note The supplied `region` must be the start of a previously mapped frame.
 */
errval_t paging_unmap(struct paging_state *st, const void *region)
{
    DEBUG_PRINTF("paging_unmap called\n");
    lvaddr_t vaddr_start = (lvaddr_t)region;
    errval_t err;

    // 1. Check if the region is currently mapped by retrieving the frame entry.
    struct page_table_entry *frame_entry = get_frame(st, vaddr_start);

    if (!frame_entry || frame_entry->is_page_table || !frame_entry->data.fe.is_frame_start) {
        DEBUG_PRINTF("paging_unmap: Region not found or not a frame start\n");
        return LIB_ERR_VREGION_NOT_FOUND;
    }

    size_t total_frame_bytes = frame_entry->data.fe.total_frame_bytes;
    size_t total_page_nums = (total_frame_bytes + BASE_PAGE_SIZE - 1) / BASE_PAGE_SIZE;
    lvaddr_t vaddr_end = vaddr_start + total_frame_bytes;

    DEBUG_PRINTF("paging_unmap: frame stats: vaddr_start: 0x%lx, total_frame_size: %zu, total_page_nums: %zu, vaddr_end: 0x%lx\n",
                 vaddr_start, total_frame_bytes, total_page_nums, vaddr_end);

    // 2. Ensure that all virtual addresses in the region are reserved.
    assert(is_all_vaddr_reserved(&st->virtual_mm, vaddr_start, total_page_nums));

    // 3. Iterate through all virtual regions to find overlapping regions for unmapping.
    struct virtual_region *vr = st->virtual_mm.virtual_regions;
    while (vr != NULL) {
        lvaddr_t vr_start = (lvaddr_t)vr->base_addr;
        lvaddr_t vr_end = vr_start + (vr->bitmap_size_aligned * BASE_PAGE_SIZE);

        // Check if the unmap region overlaps with the current virtual region.
        if (vaddr_start < vr_end  && vaddr_end > vr_start) {
            break;
        }

        vr = vr->next;
    }

    DEBUG_PRINTF("paging_unmap: Found overlapping virtual region\n");
    // Iterate over each page within the overlapping range to perform unmapping.

    struct capref frame_capref = get_frame(st, vaddr_start)->pt_ref;

    lvaddr_t current_vaddr = vaddr_start;
    while (current_vaddr < vaddr_end) {
        struct page_table_entry *current_entry = get_frame(st, current_vaddr);
        if (current_entry == NULL) {
            return LIB_ERR_VREGION_NOT_FOUND;
        }
        DEBUG_PRINTF("paging_unmap: current_entry: unmapping page_nums: %zu, vaddr: 0x%lx\n",
                        current_entry->data.fe.page_nums, current_vaddr);
        // 4. Clear the corresponding bits in the bitmap to mark pages as free.
        size_t offset = (current_vaddr - vr->base_addr) / BASE_PAGE_SIZE;
        bitmap_clear_bits(vr->bitmap, offset, current_entry->data.fe.page_nums);


        // Ensure that the virtual address is no longer reserved.
        assert(!is_any_vaddr_reserved(&st->virtual_mm, current_vaddr, current_entry->data.fe.page_nums));

        // 5. Retrieve the L3 table entry associated with the current virtual address.
        struct page_table_entry *l3_table = get_l3_table(st, current_vaddr);
        if (!l3_table) {
            DEBUG_PRINTF("paging_unmap: Failed to get L3 table for vaddr: 0x%lx\n", current_vaddr);
            return LIB_ERR_VNODE_MAP;
        }

        // 6. Unmap the frame from the page table.
        err = vnode_unmap(l3_table->pt_ref, current_entry->ref_slot);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "paging_unmap: vnode_unmap failed for vaddr: 0x%lx", current_vaddr);
            return err_push(err, LIB_ERR_VNODE_UNMAP);
        }
        err = cap_destroy(current_entry->ref_slot);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "paging_unmap: Failed to destroy cap for vaddr: 0x%lx", current_vaddr);
            return err_push(err, LIB_ERR_CAP_DESTROY);
        }
        slab_free(&st->page_table_state.slabs.entry_slab, current_entry);

        // 9. Remove the entry from the hashtable to maintain consistency.
        hashtable_remove(l3_table->data.pe.page_table, VMSAv8_64_L3_INDEX(current_vaddr));

        // it should move to next L2 entry's top
        current_vaddr += current_entry->data.fe.page_nums * BASE_PAGE_SIZE;
        if(current_vaddr < vaddr_end) assert(VMSAv8_64_L3_INDEX(current_vaddr) == 0);
    }

    err = cap_destroy(frame_capref);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "paging_unmap: Failed to destroy the frame cap for vaddr: 0x%lx", current_vaddr);
        return err_push(err, LIB_ERR_CAP_DESTROY);
    }

    assert(!is_any_vaddr_reserved(&st->virtual_mm, vaddr_start, total_page_nums));
    DEBUG_PRINTF("paging_unmap: Unmapping completed successfully\n");
    return SYS_ERR_OK;
}

errval_t paging_map_child_and_parent(struct paging_state *st, void **buf, size_t bytes,
                                        struct capref frame, uint64_t attr)
{
    // Map into child
    errval_t err = paging_map_frame_attr(st, buf, bytes, frame, attr);
    if (err_is_fail(err)) return err;

    // Map into parent
    err = paging_map_fixed(get_current_paging_state(), ((lvaddr_t) *buf) + CHILD_VADDR_OFFSET, frame, bytes);
    if (err_is_fail(err)) {
        paging_unmap(st, buf); // This might also return an error but there isn't really a good way to handle it
        return err;
    }
    return err;
}

errval_t paging_map_child_and_parent_fixed(struct paging_state *st, lvaddr_t vaddr, size_t bytes,
                                        struct capref frame, uint64_t attr)
{
    // Map into child
    errval_t err = paging_map_fixed_attr(st, vaddr, frame, bytes, attr);
    if (err_is_fail(err)) return err;

    // Map into parent
    err = paging_map_fixed(get_current_paging_state(), vaddr + CHILD_VADDR_OFFSET, frame, bytes);
    if (err_is_fail(err)) {
        paging_unmap(st, (void *) vaddr); // This might also return an error but there isn't really a good way to handle it
        return err;
    }
    return err;
}