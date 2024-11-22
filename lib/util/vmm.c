#include <util/vmm.h>
#include <util/page_table.h>
#include <util/bitmap.h>
#include <aos/paging.h>
#include <aos/slab.h>

// Function prototype for helpers:
static struct virtual_region* init_virtual_region(struct paging_state *state, uint8_t* bitmap, lvaddr_t start_vaddr, size_t size);
static errval_t allocate_bitmap(struct paging_state *state, struct virtual_region *vr);
static errval_t init_region_slab(struct paging_state *state, lvaddr_t *current_vaddr);
static errval_t init_first_region(struct paging_state *state, lvaddr_t init_vaddr, lvaddr_t current_vaddr);

errval_t init_vmm(struct paging_state *state, lvaddr_t init_vaddr, lvaddr_t current_vaddr) {
    
    // Assume everything before current_vaddr is already allocated

    // 2. slab init
    // 2.1. slab for paging regions

    // struct vmm *vmm = &state->virtual_mm;

    lvaddr_t vaddr = current_vaddr;

    DEBUG_PRINTF("(before init region_slab) current_vaddr:%lx\n", vaddr);

    errval_t err =  init_region_slab(state, &vaddr);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Error in region_slab\n");
        user_panic_fn("vmm.c", "init_vmm", 107, "Something went wrong initializing region_slab\n");
    }

    DEBUG_PRINTF("(after init region_slab) current_vaddr:%lx\n", vaddr);

    init_first_region(state, init_vaddr, vaddr);

    return SYS_ERR_OK;
    
}


void print_paging_region(struct vmm *st) {
    DEBUG_PRINTF("print_paging_region:\n");
    for(struct virtual_region *region = st->virtual_regions; region != NULL; region = region->next) {
        DEBUG_PRINTF("\tbase_addr: %lx, bitmap_size_aligned: %zu, region: %p\n", region->base_addr, region->bitmap_size_aligned, region);
        // for (size_t i = 0; i < region->bitmap_size_aligned; i++) {
        //     for (size_t j = 0; j < region->bitmap_size_aligned; j++) {
        //         printf("%d ", (region->bitmap[i] >> j) & 1);
        //     }
        //     printf("\n");
        // }
        // printf("\n");  
    }
}



/**
 * @brief Add a new region to the paging state with an automatically allocated and mapped bitmap.
 * 
 * This function allocates a new paging region, assigns a bitmap to track page allocations, and updates the paging state's 
 * linked list of regions. The bitmap is dynamically allocated based on the number of pages to manage and is aligned to 
 * `BASE_PAGE_SIZE`. After allocation, the bitmap is mapped into virtual memory.
 * 
 * @param[in]  st          A pointer to the paging state to allocate from.
 * @param[in]  base_addr   The base virtual address for the new region.
 * @param[in]  num_pages   The number of pages to allocate for the region.
 * @param[out] new_region  A pointer to store the newly created region.
 * 
 * @return SYS_ERR_OK if the operation succeeded or an error code indicating what went wrong otherwise.
 */
errval_t add_new_region(struct paging_state *state, lvaddr_t base_addr, size_t num_pages, struct virtual_region **new_region) {
    DEBUG_PRINTF("add_new_region called with base_addr: %lx, num_pages: %zu\n", base_addr, num_pages);
    
    struct vmm* vmm = &state->virtual_mm;

    // 1. Allocate a new paging region
    struct virtual_region *region = slab_alloc(&vmm->region_slab); // TODO Foreign: this will get a pointer in the parent vspace
    if (region == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }
    // 2. Assign the base address for the new region
    region->base_addr = base_addr;
    // 3. Calculate the number of pages needed to store the bitmap
    //    ====  NOTE: 1 page (4096 bytes) has 8 * 4096 bits, so 1 page can manage 8 * 4096 pages.
    size_t number_of_bitmaps = ROUND_UP(num_pages, BASE_PAGE_SIZE * 8);
    region->bitmap_size_aligned = number_of_bitmaps;

    errval_t err = allocate_bitmap(state, region);
    if (err_is_fail(err)) {
        slab_free(&vmm->region_slab, region);
        return err;
    }
    
    for (size_t i = 0; i < num_pages; i++) {
        bitmap_set_bit(region->bitmap, i);
    }
    // 8. Link the new region to the paging state's list of regions
    vmm->tail->next = region;
    vmm->tail = region;
    region->next = NULL;
    // 9. Return the newly created region via the output parameter
    *new_region = region;
    DEBUG_PRINTF("add_new_region: New region added: base_addr = %lx, bitmap_size_aligned = %zu\n", region->base_addr, region->bitmap_size_aligned);
    assert(is_all_vaddr_reserved(vmm, base_addr, num_pages));
    return SYS_ERR_OK;
}


// TODO: look through and refactor function
errval_t vmm_alloc(struct paging_state *state, void** buf, size_t bytes, size_t alignment) {

    struct vmm *vmm = &state->virtual_mm;

    // 1. Calculate the number of pages required for the allocation
    size_t num_pages = (bytes + BASE_PAGE_SIZE - 1) / BASE_PAGE_SIZE;
    lpaddr_t max_seen_region = 0;
    // 2. Traverse the existing regions to check for overlap or allocation within a region
    DEBUG_PRINTF("\tpaging_alloc: Trying to allocate %d bytes (%d pages) with alignment %d\n", bytes, num_pages, alignment);
    
    
    for(struct virtual_region *region = vmm->virtual_regions; region != NULL; region = region->next) {

        DEBUG_PRINTF("%d\n", region->bitmap_size_aligned);

        max_seen_region = MAX(max_seen_region, region_end_vaddr(region));
        size_t bitmap_size = region->bitmap_size_aligned;
        uint8_t *bitmap = region->bitmap;
        size_t start_index; // Variable to hold the start index of the allocated pages
        errval_t err = bitmap_alloc_first_fit(bitmap, bitmap_size, num_pages, 1, &start_index);
        if (err_is_ok(err)) {
            DEBUG_PRINTF("\tAllocated %d pages at index %d\n", num_pages, start_index);
            *buf = (void *)(region->base_addr + start_index * BASE_PAGE_SIZE);
            assert(is_all_vaddr_reserved(vmm, (lvaddr_t)*buf, num_pages));

            return SYS_ERR_OK;
        }
    }

    DEBUG_PRINTF("\tpaging_alloc: No region could be found, trying to add new region\n");
    // No region could be found, add new region
    struct virtual_region *new_region;
    errval_t err = add_new_region(state, max_seen_region + 1, num_pages, &new_region); // TODO: add alignment requirements (should be aligned to 128 MB)
    if (err_is_fail(err)) {
        DEBUG_PRINTF("\tFailed to add new region\n");
        return err;
    }
    DEBUG_PRINTF("\tNew region added at %lx\n", new_region->base_addr);
    *buf = (void *)new_region->base_addr;
    assert(is_all_vaddr_reserved(vmm, (lvaddr_t)*buf, num_pages));

    return SYS_ERR_OK;
}

errval_t vmm_alloc_fixed(struct paging_state *state, lvaddr_t vaddr, size_t bytes, size_t alignment) {

    struct vmm *vmm = &state->virtual_mm;

// 1. Check if the virtual address is properly aligned
    if (vaddr % alignment != 0) {
        DEBUG_PRINTF("paging_alloc_fixed: Error: vaddr is not aligned\n");
        return LIB_ERR_VREGION_BAD_ALIGNMENT;
    }
    // 2. Calculate the number of pages required for the allocation
    size_t num_pages = (bytes + BASE_PAGE_SIZE - 1) / BASE_PAGE_SIZE;
    // 3. Traverse the existing regions to check for overlap or allocation within a region
    for (struct virtual_region *region = vmm->virtual_regions; region != NULL; region = region->next) {
        // Check if the requested vaddr falls within an existing region
        if (vaddr >= region->base_addr && (vaddr + bytes) <= region_end_vaddr(region)) {
            if (is_any_vaddr_reserved(vmm, vaddr, num_pages)) {
                DEBUG_PRINTF("paging_alloc_fixed: Error: Address region overlap detected\n");
                return LIB_ERR_VSPACE_REGION_OVERLAP;
            }
            // 4. Calculate the bitmap offset and reserve the requested pages in the bitmap
            size_t offset = (vaddr - region->base_addr) / BASE_PAGE_SIZE;
            for (size_t i = 0; i < num_pages; i++) {
                bitmap_set_bit(region->bitmap, offset + i);
            }
            DEBUG_PRINTF("paging_alloc_fixed: Allocated %zu pages starting at vaddr: %lx\n", num_pages, vaddr);
            return SYS_ERR_OK;
        }
        // TODO: Handle allocation between two regions, if needed.
    }
    // 5. If no existing region can accommodate the allocation, create a new region
    struct virtual_region *new_region;
    errval_t err = add_new_region(state, vaddr, num_pages, &new_region);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("paging_alloc_fixed: Error: Failed to add new region\n");
        return err;
    }
    DEBUG_PRINTF("paging_alloc_fixed: New region created and allocated %zu pages starting at vaddr: %lx\n", num_pages, vaddr);
    return SYS_ERR_OK;
}

/**
 * @brief Checks if the entire virtual address range is already mapped
 *
 * This function checks the specified virtual address range in the paging state.
 * If every part of the range is already reserved (mapped), the function returns true.
 * If any part of the range is not reserved, it returns false.
 *
 * @param[in] st     the paging state to check in
 * @param[in] vaddr  the starting virtual address to check
 * @param[in] num_pages  the number of pages to check
 *
 * @return true if the entire address range is already mapped, false otherwise
 */
bool is_all_vaddr_reserved(struct vmm *vmm, lvaddr_t vaddr, size_t num_pages)
{
    DEBUG_PRINTF("is_all_vaddr_reserved called at: %lx for %lx pages\n", vaddr, num_pages);
    for (struct virtual_region *region = vmm->virtual_regions; region != NULL; region = region->next) {
        if (region->base_addr <= vaddr && vaddr <= region_end_vaddr(region)) {
            // Check if all bits are set in the bitmap
            size_t offset = (vaddr - region->base_addr) / BASE_PAGE_SIZE;
            for (size_t i = 0; i < num_pages; i++) {
                if (!bitmap_is_set(region->bitmap, offset + i)) {
                    return false;  // Return false if any bit is not set
                }
            }
            return true;  // Return true if all bits are set
        }
    }
    return false;  // Return false if no matching region is found
}


bool is_any_vaddr_reserved(struct vmm *st, lvaddr_t vaddr, size_t num_pages) {
    DEBUG_PRINTF("is_any_vaddr_reserved called\n");
    for (struct virtual_region *region = st->virtual_regions; region != NULL; region = region->next) {
        if (region->base_addr <= vaddr && vaddr <= region_end_vaddr(region)) {
            // Check if all bits are set in the bitmap
            size_t offset = (vaddr - region->base_addr) / BASE_PAGE_SIZE;
            for (size_t i = 0; i < num_pages; i++) {
                if (bitmap_is_set(region->bitmap, offset + i)) {
                    return true;  // Return true if any bit is not set
                }
            }
            return false;  // Return false if no bits are set
        }
    }
    return false;  // Return false if no matching region is found
}



/**
 * @brief Checks if a virtual address is already mapped
 *
 * @param[in] st     the paging state to check in
 * @param[in] vaddr  the virtual address to check
 *
 * @return true if the address is already mapped, false otherwise
 */
lpaddr_t region_end_vaddr(struct virtual_region *region)
{
    DEBUG_PRINTF("region_end_vaddr called\n");
    return region->base_addr + (BASE_PAGE_SIZE * region->bitmap_size_aligned * 8) - 1;
}

///////////////
// Helpers:  //
///////////////

// Initialization Helpers
static errval_t init_region_slab(struct paging_state *state, lvaddr_t *current_vaddr) {
    DEBUG_PRINTF("Initializing region_slab\n");

    struct vmm *vmm = &state->virtual_mm;
    errval_t err;

    struct capref frame;
    err = state->slot_alloc->alloc(state->slot_alloc, &frame);

    err = frame_create(frame, BASE_PAGE_SIZE, NULL);
    if (err_is_fail(err)) {
        state->slot_alloc->free(state->slot_alloc, frame);
        return err;
    }

    if (get_current_paging_state() != state) {
        err = paging_map_fixed(get_current_paging_state(), *current_vaddr + CHILD_VADDR_OFFSET, frame, BASE_PAGE_SIZE);

        if (err_is_fail(err)) {
            cap_destroy(frame);
            return err;
        }
    }
    err = map_frame(state, frame, *current_vaddr, BASE_PAGE_SIZE, 0, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) return err;

    DEBUG_PRINTF("Current vaddr: %lx\n", *current_vaddr);

    void *slab_buf = (void *) *current_vaddr;

    if (state != get_current_paging_state()) {
        slab_buf = (slab_buf + CHILD_VADDR_OFFSET);
    }

    *current_vaddr += BASE_PAGE_SIZE;

    DEBUG_PRINTF("Current vaddr: %lx\n", *current_vaddr);

    slab_init(&vmm->region_slab, sizeof(struct virtual_region), NULL);
    slab_grow(&vmm->region_slab, slab_buf, BASE_PAGE_SIZE);

    return SYS_ERR_OK;
}

static errval_t init_first_region(struct paging_state *state, lvaddr_t init_vaddr, lvaddr_t current_vaddr) {
    
    DEBUG_PRINTF("Initializing first region\n");

    struct vmm *vmm = &state->virtual_mm;

    struct capref frame;
    errval_t err = state->slot_alloc->alloc(state->slot_alloc, &frame);

    err = frame_create(frame, BASE_PAGE_SIZE, NULL);
    if (err_is_fail(err)) {
        state->slot_alloc->free(state->slot_alloc, frame);
        return err;
    }

    if (get_current_paging_state() != state) {
        err = paging_map_fixed(get_current_paging_state(), current_vaddr + CHILD_VADDR_OFFSET, frame, BASE_PAGE_SIZE);

        if (err_is_fail(err)) {
            cap_destroy(frame);
            return err;
        }
    }
    err = map_frame(state, frame, current_vaddr, BASE_PAGE_SIZE, 0, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) return err;

    uint8_t* bitmap = (uint8_t*) current_vaddr;
    if (state != get_current_paging_state()) {

        bitmap = (bitmap + CHILD_VADDR_OFFSET);
    }
    current_vaddr += BASE_PAGE_SIZE;

    struct virtual_region *vr = init_virtual_region(state, bitmap, init_vaddr, BASE_PAGE_SIZE);

    memset(vr->bitmap, 0, vr->bitmap_size_aligned);
    // 5. Mark the first `num_pages` as allocated by setting the corresponding bits in the bitmap
    DEBUG_PRINTF("Num pages = %ld\n", DIVIDE_ROUND_UP(current_vaddr - init_vaddr, BASE_PAGE_SIZE));
    for (size_t i = 0; i < DIVIDE_ROUND_UP(current_vaddr - init_vaddr, BASE_PAGE_SIZE); i++) {
        bitmap_set_bit(vr->bitmap, i);
    }

    // 6. Link the new region to the head of the paging state's region list
    vmm->virtual_regions = vr;
    vmm->tail = vr;
    vr->next = NULL;
    DEBUG_PRINTF("add_new_region_with_bitmap: New region added: base_addr = %lx, bitmap_size_aligned = %zu\n", vr->base_addr, vr->bitmap_size_aligned);
    assert(is_all_vaddr_reserved(vmm, init_vaddr, DIVIDE_ROUND_UP(current_vaddr - init_vaddr, BASE_PAGE_SIZE)));
    
    return SYS_ERR_OK;
}

static struct virtual_region* init_virtual_region(struct paging_state *state, uint8_t* bitmap, lvaddr_t start_vaddr, size_t size) {

    struct vmm* vmm = &state->virtual_mm;

    struct virtual_region* vr = slab_alloc(&vmm->region_slab);
    vr->base_addr = start_vaddr;
    vr->bitmap = bitmap;
    vr->bitmap_size_aligned = size;
    vr->next = NULL;

    return vr;
}


// Allocation helpers
static errval_t allocate_bitmap(struct paging_state *state, struct virtual_region *vr) {
    // 4. Allocate a frame for the bitmap to manage the page allocations
    struct capref bitmap_frame;

    errval_t err = frame_alloc(&bitmap_frame, vr->bitmap_size_aligned, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to allocate frame for bitmap\n");
        return err;
    }
    // 5. Map the frame to the virtual address space for use as the bitmap
    void *vaddr;
    err = paging_map_frame(state, &vaddr, vr->bitmap_size_aligned,
                                bitmap_frame);
    if (err_is_fail(err)) {
        cap_destroy(bitmap_frame);
        slot_free(bitmap_frame);
        DEBUG_ERR(err, "Failed to map frame to virtual address\n");
        return err;
    }

    if (state != get_current_paging_state()) {
        err = paging_map_fixed(get_current_paging_state(), vaddr + CHILD_VADDR_OFFSET, bitmap_frame, vr->bitmap_size_aligned);
        vaddr += CHILD_VADDR_OFFSET;
    }

    vr->bitmap = vaddr;

    memset(vr->bitmap, 0, vr->bitmap_size_aligned);

    return SYS_ERR_OK;
}