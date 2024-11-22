/**
 * \file
 * \brief A library for managing physical memory (i.e., caps)
 */

#include <string.h>
#include <aos/debug.h>
#include <aos/solution.h>
#include <mm/mm.h>
#include <aos/domain.h>
#include <util/bitmap.h>

enum alloc_strategy {
    BEST_FIT,
    FIRST_FIT
};


/**
 * @brief initializes the memory manager instance
 *
 * @param[in] mm        memory manager instance to initialize
 * @param[in] objtype   type of the capabilities stored in the memory manager
 * @param[in] ca        capability slot allocator to be used
 * @param[in] refill    slot allocator refill function to be used
 * @param[in] slab_buf  initial buffer space for slab allocators
 * @param[in] slab_sz   size of the initial slab buffer
 *
 * @return error value indicating success or failure
 *  - @retval SYS_ERR_OK if the memory manager was successfully initialized
 */
errval_t mm_init(struct mm *mm, enum objtype objtype, struct slot_allocator *ca,
                 slot_alloc_refill_fn_t refill, void *slab_buf, size_t slab_sz)
{
    DEBUG_PRINTF("mm_init was called with:\n");
    DEBUG_PRINTF("\tobjtype: %d\n", objtype);
    DEBUG_PRINTF("\tslab at %p with size %d\n", slab_buf, slab_sz);

    mm->objtype = objtype;
    mm->ca = ca;
    mm->refill = refill;

    slab_init(&mm->region_slab, sizeof(struct mm_region), slab_default_refill);
    // ASK: where does the memory come from when we initialize slab?
    slab_grow(&mm->region_slab, slab_buf, slab_sz);

    mm->regions = NULL; // start with no regions

    return SYS_ERR_OK;
}


/**
 * @brief destroys an mm instance
 *
 * @param[in] mm  memory manager instance to be freed
 *
 * @return error value indicating success or failure
 *  - @retval SYS_ERR_OK if the memory manager was successfully destroyed
 *
 * @note: does not free the mm object itself
 *
 * @note: This function is here for completeness. Think about how you would implement it.
 *        It's implementation is not required.
 */
errval_t mm_destroy(struct mm *mm)
{
    // make the compiler happy
    (void)mm;

    UNIMPLEMENTED();
    return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * @brief adds new memory resources to the memory manager represented by the capability
 *
 * @param[in] mm   memory manager instance to add resources to
 * @param[in] cap  memory resources to be added to the memory manager instance
 *
 * @return error value indicating the success of the operation
 *  - @retval SYS_ERR_OK              on success
 *  - @retval MM_ERR_CAP_INVALID      if the supplied capability is invalid (size, alignment)
 *  - @retval MM_ERR_CAP_TYPE         if the supplied capability is not of the expected type
 *  - @retval MM_ERR_ALREADY_PRESENT  if the supplied memory is already managed by this allocator
 *  - @retval MM_ERR_SLAB_ALLOC_FAIL  if the memory for the new node's meta data could not be allocate
 *
 * @note: the memory manager instance must be initialized before calling this function.
 *
 * @note: the function transfers ownership of the capability to the memory manager
 *
 * @note: to return allocated memory to the allocator, see mm_free()
 */
errval_t mm_add(struct mm *mm, struct capref cap)
{
    DEBUG_PRINTF("mm_add called\n");
    #ifndef NDEBUG 
        debug_print_cap_at_capref(cap);
    #endif


    errval_t err;
    struct capability cap_info;
    err = cap_direct_identify(cap, &cap_info);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Invalid capability passed in\n");

        return err_push(err, MM_ERR_CAP_INVALID);
    }

    if (cap_info.type != mm->objtype) {
        // Can't print out names of objtype. Look above for the capability printout
        DEBUG_ERR(err, "Wrong capability type was passed in. Got capability with type: %d\n", cap_info.type);

        return MM_ERR_CAP_TYPE;
    }

    // Extract base and size
    lpaddr_t cap_base = cap_info.u.ram.base;
    size_t cap_size = cap_info.u.ram.bytes;

    // Allocate a new mm_region structure from the slab allocator
    struct mm_region *region = slab_alloc(&mm->region_slab);
    if (region == NULL) {
        DEBUG_ERR(MM_ERR_SLAB_ALLOC_FAIL, "slab allocator out of memory\n");

        return MM_ERR_SLAB_ALLOC_FAIL;
    }

    // Calculate bitmap size
    size_t num_bits = cap_size / BASE_PAGE_SIZE;
    size_t bitmap_bytes = (num_bits + 7) / 8;
    size_t bitmap_size_aligned = ROUND_UP(bitmap_bytes, BASE_PAGE_SIZE); // size of bitmap in bytes rounded up to align with page size

    if (cap_size <= bitmap_size_aligned) {
        slab_free(&mm->region_slab, region);

        DEBUG_ERR(MM_ERR_CAP_INVALID, "Aborting, memory added was too small to manage\n");

        return MM_ERR_CAP_INVALID; // Not enough memory to manage
    }

    // Reserve space for the bitmap by adjusting the managed memory region
    region->base_addr = cap_base + bitmap_size_aligned;
    region->memory_size = cap_size - bitmap_size_aligned;
    region->bitmap_bits = region->memory_size / BASE_PAGE_SIZE;
    region->bitmap_size_aligned = bitmap_size_aligned;

    // Retype the reserved memory to Frame capability
    struct capref bitmap_frame;

    // allocate slot for frame
    err = allocate_slot_with_refill(mm, &bitmap_frame, region);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Error allocating slot in mm_add\n");

        return err;
    }

    // Retype the reserved memory
    err = cap_retype(bitmap_frame, cap, 0, ObjType_Frame, bitmap_size_aligned);
    if (err_is_fail(err)) {
        slot_free(bitmap_frame);
        slab_free(&mm->region_slab, region);

        DEBUG_ERR(err, "Error retyping capability to frame\n");

        return err_push(err, LIB_ERR_CAP_RETYPE);
    }

    // // Map the frame into virtual address space
    void *vaddr;
    err = paging_map_frame_attr(get_current_paging_state(), &vaddr, bitmap_size_aligned,
                                bitmap_frame, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        cap_destroy(bitmap_frame);
        slot_free(bitmap_frame);
        slab_free(&mm->region_slab, region);

        DEBUG_ERR(err, "Failed to map frame to page\n");

        return err_push(err, MM_ERR_MM_ADD);
    }

    // Initialize bitmap
    region->bitmap = (uint8_t *)vaddr;
    memset(region->bitmap, 0, bitmap_bytes); //fill bitmap with 0's (non-allocated memory)

    // Store the capabilities
    region->memory_cap = cap;
    region->bitmap_cap = bitmap_frame;

    // Add the region to the linked list
    region->next = mm->regions;
    mm->regions = region;

    return SYS_ERR_OK;
}


/**
 * @brief allocates memory with the requested size and alignment
 *
 * @param[in]  mm         memory manager instance to allocate from
 * @param[in]  size       minimum requested size of the memory region to allocate
 * @param[in]  alignment  minimum alignment requirement for the allocation
 * @param[out] retcap     returns the capability to the allocated memory
 *
 * @return error value indicating the success of the operation
 *  - @retval SYS_ERR_OK                on success
 *  - @retval MM_ERR_BAD_ALIGNMENT      if the requested alignment is not a power of two
 *  - @retval MM_ERR_OUT_OF_MEMORY      if there is not enough memory to satisfy the request
 *  - @retval MM_ERR_ALLOC_CONSTRAINTS  if there is memory, but the constraints are too tight
 *  - @retval MM_ERR_SLOT_ALLOC_FAIL    failed to allocate slot for new capability
 *  - @retval MM_ERR_SLAB_ALLOC_FAIL    failed to allocate memory for meta data
 *
 * @note The function allocates memory and returns a capability to it back to the caller.
 * The size of the returned capability is a multiple of BASE_PAGE_SIZE. Alignment requests
 * must be a power of two starting from BASE_PAGE_SIZE.
 *
 * @note The returned ownership of the capability is transferred to the caller.
 */
errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment, struct capref *retcap) {
    errval_t err;

    // Validate alignment
    if ((alignment & (alignment - 1)) != 0 || alignment < BASE_PAGE_SIZE || alignment == 0) {
        return MM_ERR_BAD_ALIGNMENT;
    }

    // calculate num of pages needed
    size_t num_pages = (size + BASE_PAGE_SIZE - 1) / BASE_PAGE_SIZE;
    size_t alignment_factor = alignment / BASE_PAGE_SIZE; // alignment in number of pages

    enum alloc_strategy strategy = FIRST_FIT;

    // Select allocation strategy based on the flag
    if (strategy == BEST_FIT) {
        err = mm_alloc_best_fit(mm, num_pages, alignment_factor, retcap);
    } else if (strategy == FIRST_FIT) {
        err = mm_alloc_first_fit(mm, num_pages, alignment_factor, retcap);
    } else {
        return MM_ERR_OUT_OF_MEMORY;  // Return an error if the strategy is unknown
    }

    return err;
}

/**
 * @brief allocates memory of a given size within a given base-limit range (EXTRA CHALLENGE)
 *
 * @param[in]  mm         memory manager instance to allocate from
 * @param[in]  base       minimum requested address of the memory region to allocate
 * @param[in]  limit      maximum requested address of the memory region to allocate
 * @param[in]  size       minimum requested size of the memory region to allocate
 * @param[in]  alignment  minimum alignment requirement for the allocation
 * @param[out] retcap     returns the capability to the allocated memory
 *
 * @return error value indicating the success of the operation
 *  - @retval SYS_ERR_OK                on success
 *  - @retval MM_ERR_BAD_ALIGNMENT      if the requested alignment is not a power of two
 *  - @retval MM_ERR_OUT_OF_MEMORY      if there is not enough memory to satisfy the request
 *  - @retval MM_ERR_ALLOC_CONSTRAINTS  if there is memory, but the constraints are too tight
 *  - @retval MM_ERR_OUT_OF_BOUNDS      if the supplied range is not within the allocator's range
 *  - @retval MM_ERR_SLOT_ALLOC_FAIL    failed to allocate slot for new capability
 *  - @retval MM_ERR_SLAB_ALLOC_FAIL    failed to allocate memory for meta data
 *
 * The returned capability should be within [base, limit] i.e., base <= cap.base,
 * and cap.base + cap.size <= limit.
 *
 * The requested alignment should be a power two of at least BASE_PAGE_SIZE.
 */
errval_t mm_alloc_from_range_aligned(struct mm *mm, size_t base, size_t limit, size_t size,
                                     size_t alignment, struct capref *retcap)
{
    errval_t err;

    // Validate parameters
    if ((alignment & (alignment - 1)) != 0 || alignment < BASE_PAGE_SIZE || alignment == 0) {
        return MM_ERR_BAD_ALIGNMENT;
    }

    if (base > limit) {
        return MM_ERR_OUT_OF_BOUNDS;
    }

    // Ensure base and limit are aligned
    if ((base % BASE_PAGE_SIZE) != 0 || (limit % BASE_PAGE_SIZE) != 0) {
        return MM_ERR_BAD_ALIGNMENT;
    }

    // Calculate number of pages needed
    size_t num_pages = (size + BASE_PAGE_SIZE - 1) / BASE_PAGE_SIZE;
    size_t alignment_factor = alignment / BASE_PAGE_SIZE;
    // Iterate over memory regions
    for (struct mm_region *region = mm->regions; region != NULL; region = region->next) {
        // allocatable range within this region based on [base, limit]
        genpaddr_t region_start = region->base_addr;
        genpaddr_t region_end = region->base_addr + region->memory_size;
        // Calculate the overlapping range
        genpaddr_t alloc_start = (base > region_start) ? base : region_start;
        genpaddr_t alloc_end = (limit < region_end) ? limit : region_end;
        alloc_start = ROUND_UP(alloc_start, alignment); // Adjust alloc_start to the next aligned address
        alloc_end = ROUND_DOWN(alloc_end, alignment); // Adjust alloc_end to the previous aligned address
        // Check if there is an overlap
        if (alloc_start >= alloc_end) {
            continue; // No overlap with this region
        }

        // Calculate the starting and ending page indices within the bitmap
        size_t start_index = (alloc_start - region_start) / BASE_PAGE_SIZE;
        size_t end_index = (alloc_end - region_start) / BASE_PAGE_SIZE;
        DEBUG_PRINTF("the start is %d\n", start_index);
        DEBUG_PRINTF("the end is %d\n", end_index);

        // Iterate through the bitmap within [start_index, end_index)
        for (size_t i = start_index; i < end_index; i += alignment_factor) { // we skip because of alignment
            if (bitmap_is_set(region->bitmap, i)) {
                continue; // if the first bit within the alignment is set. go next
            }
            
            size_t free_count = 0;
            for (size_t k = 0; k < num_pages; k++) {
                if (i + k >= end_index || bitmap_is_set(region->bitmap, i + k)) {
                    break;  // Not enough consecutive free pages
                }
                free_count++;
            }

            // If we've found enough free consecutive pages, mark them as allocated
            if (free_count == num_pages) {
                for (size_t k = 0; k < num_pages; k++) {
                    bitmap_set_bit(region->bitmap, i + k);
                }

                // Perform the allocation
                err = perform_allocation(mm, region, i, num_pages, retcap, ObjType_RAM);
                if (err_is_fail(err)) {
                    // Roll back bitmap changes
                    for (size_t k = 0; k < num_pages; k++) {
                        bitmap_clear_bit(region->bitmap, i + k);
                    }
                    return err;
                }
    
                return SYS_ERR_OK;
            }
        }
    }

    // no suitable block was found within the range
    return MM_ERR_OUT_OF_MEMORY;
}

/**
 * @brief frees a previously allocated memory by returning it to the memory manager
 *
 * @param[in] mm   the memory manager instance to return the freed memory to
 * @param[in] cap  capability of the memory to be freed
 *
 * @return error value indicating the success of the operation
 *   - @retval SYS_ERR_OK            The memory was successfully freed and added to the allocator
 *   - @retval MM_ERR_NOT_FOUND      The memory was not allocated by this allocator
 *   - @retval MM_ERR_DOUBLE_FREE    The (parts of) memory region has already been freed
 *   - @retval MM_ERR_CAP_TYPE       The capability is not of the correct type
 *   - @retval MM_ERR_CAP_INVALID    The supplied cabability was invalid or does not exist.
 *
 * @pre  The function assumes that the capability passed in is no where else used.
 *       It is the only copy and there are no descendants of it. Calling functions need
 *       to ensure this. Later allocations can safely hand out the freed capability again.
 *
 * @note The memory to be freed must have been added to the `mm` instance and it must have been
 *       allocated before, otherwise an error is to be returned.
 *
 * @note The ownership of the capability slot is transferred to the memory manager and may
 *       be recycled for future allocations.
 */
errval_t mm_free(struct mm *mm, struct capref cap)
{

    DEBUG_PRINTF("mm_free called with capability\n");
    #ifndef NDEBUG
        debug_print_cap_at_capref(cap);
    #endif

    // TODO:
    //   - add the memory back to the allocator by markint the region as free
    //
    // You can assume that the capability was the one returned by a previous call
    // to mm_alloc() or mm_alloc_aligned(). For the extra challenge, you may also
    // need to handle partial frees, where a capability was split up by the client
    // and only a part of it was returned.
    errval_t err;

    struct capability cap_info;
    err = cap_direct_identify(cap, &cap_info);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to identify capability\n");

        return err_push(err, MM_ERR_CAP_INVALID);
    }

    enum objtype type = cap_info.type;
    if (type != mm->objtype) { // check object type
        DEBUG_ERR(MM_ERR_CAP_TYPE, "Capability type is incorrect, expecting: %d\n", mm->objtype);
        return MM_ERR_CAP_TYPE;
    }

    // Get the physical base address and size
    genpaddr_t phys_base = get_address(&cap_info);
    gensize_t size = get_size(&cap_info);

    // Ensure size is a multiple of BASE_PAGE_SIZE
    if (size % BASE_PAGE_SIZE != 0) {
        DEBUG_ERR(MM_ERR_BAD_ALIGNMENT, "size is %d, size \% BASE_PAGE_SIZE = %d\n", size, size % BASE_PAGE_SIZE);

        return MM_ERR_BAD_ALIGNMENT;
    }

    // Find the region containing the physical address
    struct mm_region *region = mm->regions;
    while (region != NULL) {
        genpaddr_t region_start = region->base_addr;
        genpaddr_t region_end = region->base_addr + region->memory_size;

        if (phys_base >= region_start && (phys_base + size) <= region_end) {
            // Found the region
            break;
        }
        region = region->next;
    }

    if (region == NULL) {
        // Region not found
        return MM_ERR_NOT_FOUND;
    }

    // Calculate the starting index in the bitmap
    genpaddr_t offset = phys_base - region->base_addr;
    if (offset % BASE_PAGE_SIZE != 0) {
        DEBUG_ERR(MM_ERR_BAD_ALIGNMENT, "offset into memory is %d, offset \% BASE_PAGE_SIZE = %d\n", offset, offset % BASE_PAGE_SIZE);

        return MM_ERR_BAD_ALIGNMENT;
    }
    size_t start_index = offset / BASE_PAGE_SIZE;

    // Calculate the number of pages we need to free
    size_t num_pages = size / BASE_PAGE_SIZE;

    // Ensure indices are within the bitmap bounds
    size_t total_pages = region->bitmap_bits;

    assert(start_index + num_pages <= total_pages); // This should never happen if this was checked for before

    // Check if the pages are currently allocated
    for (size_t i = 0; i < num_pages; i++) {
        if (!bitmap_is_set(region->bitmap, start_index + i)) {
            DEBUG_ERR(MM_ERR_DOUBLE_FREE, "Double free at %p\n", region->base_addr + (start_index + i) * BASE_PAGE_SIZE);

            // Page is already free
            return MM_ERR_DOUBLE_FREE;
        }
    }

    // Mark the pages as free
    for (size_t i = 0; i < num_pages; i++) {
        bitmap_clear_bit(region->bitmap, start_index + i);
    }

    // Destroy the capability and free the slot
    err = cap_destroy(cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Capability could not be destroyed\n");

        return err_push(err, LIB_ERR_CAP_DESTROY);
    }

    return SYS_ERR_OK;
}


/**
 * @brief returns the amount of available (free) memory of the memory manager
 *
 * @param[in] mm   memory manager instance to query
 *
 * @return the amount of memory available in bytes in the memory manager
 */
size_t mm_mem_available(struct mm *mm)
{
    // TODO: Add metadata to the mmregion object to hold this + total memory
    // go through the bitmap in every region and calculate
    size_t free_pages = 0;
    for (struct mm_region *region = mm->regions; region != NULL; region = region->next) {
        for (size_t i = 0; i < region->bitmap_bits; i++) {
            if (!bitmap_is_set(region->bitmap, i)) {
                free_pages++;
            }
        }
    }

    return free_pages * BASE_PAGE_SIZE;
}


/**
 * @brief returns the total amount of memory this mm instances manages.
 *
 * @param[in] mm   memory manager instance to query
 *
 * @return the total amount of memory in bytes of the memory manager
 */
size_t mm_mem_total(struct mm *mm)
{
    size_t total_bytes = 0;
    for (struct mm_region *region = mm->regions; region != NULL; region = region->next) {
        total_bytes += region->memory_size;
    }

    return total_bytes;
}


/**
 * @brief obtains the range of free memory of the memory allocator instance
 *
 * @param[in]  mm     memory manager instance to query
 * @param[out] base   returns the minimum address of free memroy
 * @param[out] limit  returns the maximum address of free memory
 *
 * Note: This is part of the extra challenge. You can ignore potential (allocation)
 *       holes in the free memory regions, and just return the smallest address of
 *       a region than is free, and likewise the highest address
 */
void mm_mem_get_free_range(struct mm *mm, lpaddr_t *base, lpaddr_t *limit)
{
    // make compiler happy about unused parameters
    (void)mm;
    (void)base;
    (void)limit;

    UNIMPLEMENTED();
}

/**************************         HELPER FUNCTIONS       ******************************/

size_t min(size_t a, size_t b) {
    return (a < b) ? a : b;
}

/**
 * @brief Allocates memory pages in the bitmap and retypes them as Frame capabilities.
 *
 * @param[in]  mm                The memory manager instance.
 * @param[in]  region            The memory region from which to allocate.
 * @param[in]  best_current_index The starting index in the bitmap for allocation.
 * @param[in]  num_pages         The number of pages to allocate.
 * @param[in]  objtype           The object type of the derived capability
 * @param[out] retcap            Returns the capability for the allocated memory.
 *
 * @return SYS_ERR_OK on success, or an error code on failure.
 *
 * This function calculates the physical base address of the free pages, allocates a slot, 
 * retypes the memory capability, and handles any errors or rollbacks.
 */
errval_t perform_allocation(struct mm *mm, struct mm_region *region, size_t best_current_index, size_t num_pages, struct capref *retcap, enum objtype objtype) {
    DEBUG_PRINTF("Performing allocation for %d pages at %p;\n", num_pages, region->base_addr + best_current_index * BASE_PAGE_SIZE);
    
    errval_t err;

    // Calculate the physical base address of the allocated memory
    genpaddr_t alloc_offset = region->bitmap_size_aligned + best_current_index * BASE_PAGE_SIZE;
    assert(alloc_offset % BASE_PAGE_SIZE == 0); // sanity check
    gensize_t alloc_size = num_pages * BASE_PAGE_SIZE;

    // Allocate a slot for the capability
    err = allocate_slot_with_refill(mm, retcap, region);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not allocate slot");

        return err;
    }
    
    // Retype the memory
    err = cap_retype(*retcap, region->memory_cap, alloc_offset, objtype, alloc_size);
    if (err_is_fail(err)) {
        slot_free(*retcap);
        return err_push(err, LIB_ERR_CAP_RETYPE);
    }

    DEBUG_PRINTF("Allocated capability\n");
    #ifndef NDEBUG
    debug_print_cap_at_capref(*retcap);
    #endif

    return SYS_ERR_OK;
}

errval_t mm_alloc_best_fit(struct mm *mm, size_t num_pages, size_t alignment_factor, struct capref *retcap) {
    // best-fit implementation
    for (struct mm_region *region = mm->regions; region != NULL; region = region->next) {
        size_t bitmap_size = region->bitmap_bits;
        uint8_t *bitmap = region->bitmap;
        size_t best_current_index = 0; // assign to 0 initially
        size_t current_best_metric = SIZE_MAX; // metric to check best-fit

        // Calculate the starting index to ensure alignment with the region's base address
        size_t region_base_page = (region->base_addr / BASE_PAGE_SIZE) % alignment_factor;
        size_t start_index = (region_base_page) % alignment_factor;

        // MAY BE AN ERROR: when we allocate the bitmap, we allocate at least a whole page to it, but this allocated page does not count as 
        //                  being part of the memory. this may interfere with alignment. may need to check later!
        for (size_t i = start_index; i < bitmap_size; i += alignment_factor) { // we skip because of alignment
            if (bitmap_is_set(bitmap, i)) {
                continue; // if the first bit within the alignment is set. go next
            }

            size_t forward_count = count_forward_pages(bitmap, i, num_pages * 2, bitmap_size);
            
            // Only consider this block if we found enough free pages
            if (forward_count >= num_pages && i > 0) {
                // Compute backward free pages
                size_t backward_metric = free_backward_pages(bitmap, i - 1, num_pages * 2);
                size_t forward_metric = forward_count - num_pages;
            
                // Combine forward and backward free counts for the total metric
                size_t total_metric = backward_metric + forward_metric;

                if (total_metric == 0) {
                    best_current_index = i; // found exact fit. stop looking
                    break;
                }
            
                // Update best fit if this block is better
                if (total_metric < current_best_metric) {
                    current_best_metric = total_metric;
                    best_current_index = i;
                }
            }
        }

        // we found the best fit so switch bits
        if (best_current_index != SIZE_MAX) {
            // Mark pages as allocated in the bitmap
            for (size_t k = 0; k < num_pages; k++) {
                bitmap_set_bit(bitmap, best_current_index + k);
            }

            // Perform the allocation
            errval_t err = perform_allocation(mm, region, best_current_index, num_pages, retcap, ObjType_RAM);
            if (err_is_fail(err)) {
                // Roll back bitmap changes
                for (size_t k = 0; k < num_pages; k++) {
                    bitmap_clear_bit(bitmap, best_current_index + k);
                }
                return err;
            }

            return SYS_ERR_OK;
        }
    }

    return MM_ERR_OUT_OF_MEMORY;
}

errval_t mm_alloc_first_fit(struct mm *mm, size_t num_pages, size_t alignment_factor, struct capref *retcap) {
    // first-fit implementation
    for (struct mm_region *region = mm->regions; region != NULL; region = region->next) {
        size_t bitmap_size = region->bitmap_bits;
        uint8_t *bitmap = region->bitmap;
        size_t start_index; // Variable to hold the start index of the allocated pages

        // Call the bitmap allocation function
        errval_t err = bitmap_alloc_first_fit(bitmap, bitmap_size, num_pages, alignment_factor, &start_index);

        if (err_is_ok(err)) {
            // Perform the allocation
            err = perform_allocation(mm, region, start_index, num_pages, retcap, ObjType_RAM);
            if (err_is_fail(err)) {
                // Roll back bitmap changes
                for (size_t k = 0; k < num_pages; k++) {
                    bitmap_clear_bit(bitmap, start_index + k);
                }
                return err;
            }
            return SYS_ERR_OK; // Allocation successful
        }

    }

    return MM_ERR_OUT_OF_MEMORY;
}

/**
 * @brief Helper function to allocate a slot and refill the allocator if necessary.
 *
 * @param[in]  mm         Memory manager instance.
 * @param[out] retcap     Pointer to the capref where the allocated slot will be stored.
 * @param[in]  region     Pointer to the memory region structure (used for slab freeing on failure).
 *
 * @return SYS_ERR_OK on success
 *
 * The function attempts to allocate a slot using the provided memory manager's slot allocator.
 * If the allocation fails due to no available slots, it will attempt to refill the allocator and retry.
 * If the refill or the retry fails, it will return an error and free the associated resources.
 */
errval_t allocate_slot_with_refill(struct mm *mm, struct capref *retcap, struct mm_region *region) {
    errval_t err;
// TODO: check if there are 3(?) slots remaining before trying to alloc

    DEBUG_PRINTF("Attempting to allocate new slot\n");

    // Attempt to allocate a slot
    err = slot_alloc(retcap);
    if (err_is_fail(err)) {
        if (err_no(err) == MM_ERR_SLOT_ALLOC_FAIL) {
            DEBUG_PRINTF("Slot allocator is full, attempting to refill...\n");

            // Need to refill the slot allocator
            err = mm->refill(mm->ca);
            if (err_is_fail(err)) {
                slab_free(&mm->region_slab, region);
                return err_push(err, MM_ERR_SLOT_ALLOC_FAIL);
            }
            // Try allocating again after refill
            err = slot_alloc(retcap);
            if (err_is_fail(err)) {
                slab_free(&mm->region_slab, region);
                return err_push(err, MM_ERR_SLOT_ALLOC_FAIL);
            }
        } else {
            slab_free(&mm->region_slab, region);
            return err_push(err, MM_ERR_SLOT_ALLOC_FAIL);
        }
    }

    return SYS_ERR_OK;
}