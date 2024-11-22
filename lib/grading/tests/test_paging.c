#include <stdio.h>
#include <stdlib.h>
#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/capabilities.h>
#include <aos/slab.h>
#include <aos/solution.h>
#include <aos/threads.h>
#include <grading/grading.h>
#include <hashtable/hashtable.h>
#include <proc_mgmt/proc_mgmt.h>

#include <grading/io.h>
#include <grading/options.h>
#include <grading/state.h>
#include <grading/tests.h>
#include "../include/grading/options_internal.h"

/* Function prototypes for the tests */
static void test_fixed_address_mapping(void);
static void test_heap_allocation(void);
static void test_large_frame_mapping(void);
static void test_sparse_memory_access(void);
static void test_multi_l3_mapping(void);
static void test_misaligned_mapping(void);
static void test_map_then_unmap_indefinitely(void);
static lvaddr_t generate_vaddr(size_t l0_index, size_t l1_index, size_t l2_index, size_t l3_index){
    if (l0_index >= 512 || l1_index >= 512 || l2_index >= 512 || l3_index >= 512) {
        grading_test_fail("Virtual Address Generation", "Invalid index.");
        return 0;
    }
    return (l0_index << 39) | (l1_index << 30) | (l2_index << 21) | (l3_index << 12);
}

/**
 * @brief Test mapping a large frame at a fixed virtual address.
 */
static void test_fixed_address_mapping(void) {
    grading_printf("Running test_fixed_address_mapping()\n");
    errval_t err;

    // Allocate a large frame
    size_t frame_size = 256 * 1024 * 1024; // 256 MB
    struct capref frame_cap;
    err = frame_alloc(&frame_cap, frame_size, NULL);
    if (err_is_fail(err)) {
        grading_test_fail("Fixed Address Mapping", "Failed to allocate frame.");
        return;
    }

    // Choose random L0 to L3 indices
    lvaddr_t fixed_vaddr = generate_vaddr(123,234,345,456);
    grading_printf("Mapping frame at fixed virtual address: 0x%lx\n", fixed_vaddr);

    struct paging_state* current = get_current_paging_state();

    // Map the frame at the fixed virtual address
    err = paging_map_fixed_attr(current, fixed_vaddr, frame_cap, frame_size, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        grading_test_fail("Fixed Address Mapping", "Failed to map frame at fixed address.");
        return;
    }

    // Access the memory to verify the mapping
    uint8_t *buf = (uint8_t *)fixed_vaddr;
    buf[0] = 0x11; // test first
    buf[frame_size / 2] = 0x22; // test middle
    buf[frame_size - 1] = 0x33; // test last
    if (buf[0] != 0x11 || buf[frame_size / 2] != 0x22 || buf[frame_size - 1] != 0x33) {
        grading_test_fail("Fixed Address Mapping", "Memory access verification failed.");
        return;
    }

    grading_test_pass("Fixed Address Mapping", "Successfully mapped and accessed memory at fixed address.");
}

/**
 * @brief Test heap allocation using malloc() and free().
 */
static void test_heap_allocation(void) {
    grading_printf("Running test_heap_allocation()\n");

    // Allocate a large amount of memory using malloc()
    size_t alloc_size = 64 * 1024 * 1024; // 64 MB
    uint8_t *buf = malloc(alloc_size);
    if (buf == NULL) {
        grading_test_fail("Heap Allocation", "Failed to allocate heap memory.");
        return;
    }

    grading_printf("Allocated %zu bytes of heap memory.\n", alloc_size);

    // Access some bytes in the allocated memory
    buf[0] = 0x11; // test first
    buf[alloc_size / 2] = 0x22; // test middle
    buf[alloc_size - 1] = 0x33; // test last
    if (buf[0] != 0x11 || buf[alloc_size / 2] != 0x22 || buf[alloc_size - 1] != 0x33) {
        grading_test_fail("Heap Allocation", "Memory access verification failed.");
        free(buf);
        return;
    }

    // Free the allocated memory
    free(buf);

    grading_test_pass("Heap Allocation", "Successfully allocated and accessed heap memory.");
}

/**
 * @brief Test mapping a very large frame to ensure the paging system can handle large mappings.
 */
static void test_large_frame_mapping(void) {
    grading_printf("Running test_large_frame_mapping()\n");
    errval_t err;

    // Allocate a very large frame
    size_t frame_size = 256 * 1024 * 1024; // 256 MB
    struct capref frame_cap;
    err = frame_alloc(&frame_cap, frame_size, NULL);
    if (err_is_fail(err)) {
        grading_test_fail("Large Frame Mapping", "Failed to allocate large frame.");
        return;
    }

    // Map the frame using paging_map_frame_attr()
    void *buf;
    struct paging_state* current = get_current_paging_state();
    err = paging_map_frame_attr(current, &buf, frame_size, frame_cap, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        grading_test_fail("Large Frame Mapping", "Failed to map large frame.");
        return;
    }

    grading_printf("Mapped large frame at virtual address: %p\n", buf);

    // Access some bytes in the mapped memory
    uint8_t *ptr = (uint8_t *)buf;
    ptr[0] = 0x55;
    ptr[frame_size - 1] = 0x66;
    if (ptr[0] != 0x55 || ptr[frame_size - 1] != 0x66) {
        grading_test_fail("Large Frame Mapping", "Memory access verification failed.");
        return;
    }

    grading_test_pass("Large Frame Mapping", "Successfully mapped and accessed large frame.");
}

/**
 * @brief Test allocating a large block of memory but only accessing a few bytes.
 */
static void test_sparse_memory_access(void) {
    grading_printf("Running test_sparse_memory_access()\n");

    // Allocate 100 MB using malloc()
    size_t alloc_size = 100 * 1024 * 1024; // 100 MB
    uint8_t *buf = malloc(alloc_size);
    if (buf == NULL) {
        grading_test_fail("Sparse Memory Access", "Failed to allocate memory.");
        return;
    }

    grading_printf("Allocated %zu bytes of memory.\n", alloc_size);

    // Access a few bytes in the middle
    buf[alloc_size / 2] = 0x77;
    if (buf[alloc_size / 2] != 0x77) {
        grading_test_fail("Sparse Memory Access", "Memory access verification failed.");
        free(buf);
        return;
    }

    grading_test_pass("Sparse Memory Access", "Successfully allocated and accessed sparse memory.");

    // Free the allocated memory
    free(buf);
}

/**
 * @brief Test mapping a frame that spans multiple L3 page tables.
 */
static void test_multi_l3_mapping(void) {
    grading_printf("Running test_multi_l3_mapping()\n");
    errval_t err;

    // Each L3 page table covers 2MB (512 entries * 4KB pages) so map more than that
    size_t frame_size = 8 * 1024 * 1024; // 8 MB

    // Allocate a frame larger than 2MB
    struct capref frame_cap;
    err = frame_alloc(&frame_cap, frame_size, NULL);
    if (err_is_fail(err)) {
        grading_test_fail("Multi-L3 Mapping", "Failed to allocate frame.");
        return;
    }

    // Map the frame
    void *buf;
    struct paging_state* current = get_current_paging_state();
    err = paging_map_frame_attr(current, &buf, frame_size, frame_cap, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        grading_test_fail("Multi-L3 Mapping", "Failed to map frame spanning multiple L3 tables.");
        return;
    }

    grading_printf("Mapped frame spanning multiple L3 tables at virtual address: %p\n", buf);

    // Access memory to verify mapping
    uint8_t *ptr = (uint8_t *)buf;
    ptr[0] = 0x88;
    ptr[frame_size - 1] = 0x99;
    if (ptr[0] != 0x88 || ptr[frame_size - 1] != 0x99) {
        grading_test_fail("Multi-L3 Mapping", "Memory access verification failed.");
        return;
    }

    grading_test_pass("Multi-L3 Mapping", "Successfully mapped frame spanning multiple L3 tables.");
}

/**
 * @brief Test handling of misaligned virtual addresses and sizes.
 */
static void test_misaligned_mapping(void) {
    grading_printf("Running test_misaligned_mapping()\n");
    errval_t err;

    // Attempt to map a frame at a misaligned virtual address
    size_t frame_size = BASE_PAGE_SIZE; // 4KB
    struct capref frame_cap;
    err = frame_alloc(&frame_cap, frame_size, NULL);
    if (err_is_fail(err)) {
        grading_test_fail("Misaligned Mapping", "Failed to allocate frame.");
        return;
    }

    // Choose a misaligned virtual address
    lvaddr_t misaligned_vaddr = VADDR_OFFSET + 1; // This SHOULD NOT BE ALIGNED TO VIRTUAL ADDRESS
    grading_printf("Attempting to map frame at misaligned virtual address: 0x%lx\n", misaligned_vaddr);

    struct paging_state* current = get_current_paging_state();

    err = paging_map_fixed_attr(current, misaligned_vaddr, frame_cap, frame_size, VREGION_FLAGS_READ_WRITE);
    if (err_is_ok(err)) {
        grading_test_fail("Misaligned Mapping", "Mapping succeeded at misaligned address (expected failure).");
        return;
    } else {
        grading_test_pass("Misaligned Mapping", "Correctly failed to map at misaligned address.");
    }

    // Attempt to map a frame with a misaligned size
    size_t misaligned_size = BASE_PAGE_SIZE - 1; // Not a multiple of page size
    grading_printf("Attempting to map frame with misaligned size: %zu bytes\n", misaligned_size);

    void *buf;
    err = paging_map_frame_attr(current, &buf, misaligned_size, frame_cap, VREGION_FLAGS_READ_WRITE);
    if (err_is_ok(err)) {
        grading_test_fail("Misaligned Size Mapping", "Mapping succeeded with misaligned size (expected failure).");
        return;
    } else {
        grading_test_pass("Misaligned Size Mapping", "Correctly failed to map with misaligned size.");
    }
}

/**
 * @brief Test mapping 13 MB and unmapping it indefinitely.
 */
static void test_map_then_unmap_indefinitely(void) {
    grading_printf("Running test_map_then_unmap_indefinitely()\n");
    errval_t err;

    // Define the size to map
    size_t map_size = 13 * 1024 * 1024; // 13 MB

    // Choose virtual address
    lvaddr_t vaddr = generate_vaddr(444,333,222,111);

    struct paging_state* current = get_current_paging_state();

    // Loop to map and unmap the memory multiple times
    int iterations = 10; 
    for (int i = 0; i < iterations; i++) {
        grading_printf("Iteration %d: Mapping memory at address: 0x%lx\n", i + 1, vaddr);

        // Allocate a frame of 13 MB
        struct capref frame_cap;
        err = frame_alloc(&frame_cap, map_size, NULL);
        if (err_is_fail(err)) {
            grading_test_fail("Map and Unmap Indefinitely", "Failed to allocate frame.");
            return;
        }

        // Map the frame
        err = paging_map_fixed_attr(current, vaddr, frame_cap, map_size, VREGION_FLAGS_READ_WRITE);
        if (err_is_fail(err)) {
            grading_test_fail("Map and Unmap Indefinitely", "Failed to map frame at address.");
            return;
        }

        grading_printf("Mapped 13 MB frame at virtual address: 0x%lx\n", vaddr);

        // Access some bytes to verify mapping
        uint8_t *buf = (uint8_t *)vaddr;
        buf[0] = 0x11;              // Test first byte
        buf[map_size / 2] = 0x22;   // Test middle byte
        buf[map_size - 1] = 0x33;   // Test last byte

        if (buf[0] != 0x11 || buf[map_size / 2] != 0x22 || buf[map_size - 1] != 0x33) {
            grading_test_fail("Map and Unmap Indefinitely", "Memory access verification failed.");
            return;
        }

        grading_printf("Accessed memory successfully.\n");

        grading_printf("Iteration %d: Unmapping memory at address: 0x%lx\n", i + 1, vaddr);

        // Unmap the memory
        err = paging_unmap(current, buf);
        if (err_is_fail(err)) {
            grading_test_fail("Map and Unmap Indefinitely", "Failed to unmap frame.");
            return;
        }

        grading_printf("Unmapped memory at address: 0x%lx\n", vaddr);
    }

    grading_test_pass("Map and Unmap Indefinitely", "Successfully mapped and unmapped memory.");
}

struct map_thread_args {
    void* buf;
    int thread_num;
    size_t num_ints;
    int iteration_size;
};

static int test_map_thread(void* input_args) {

    grading_printf("Running thread code\n");

    struct map_thread_args* args = input_args;

    grading_printf("Thread %d is running\n", args->thread_num);

    int *intbuf = (int*) args->buf;
    int num_ints = args->num_ints;
    int thread_num = (int) args->thread_num;

    for (int i = 0; i + thread_num < num_ints; i += args->iteration_size) {
        intbuf[i + thread_num] = thread_num; 
    }

    grading_printf("Thread %d has finished running\n", thread_num);

    return 0;
}

static void test_multiple_threads(void) {
    grading_printf("Running test_multiple_threads()\n");
    size_t num_runs = 100;

    for (size_t i = 0; i < num_runs; i++) {// Allocate a very large frame
        grading_printf("Run number: %d", i);

        void *buf;
        size_t num_ints = 1 * 1024 * 1024; // 1 MB
        buf = malloc(sizeof(int) * num_ints);
        if (buf == NULL) {
            grading_test_fail("Multiple Threads", "Failed to allocate large frame.");
            return;
        }

        grading_printf("Allocated large frame at virtual address: %p\n", buf);

        // Access some bytes in the mapped memory
        size_t num_threads = 16;
        struct thread *t[num_threads];

        struct map_thread_args args[num_threads];

        int iteration_size = 64; // 2^6 * sizeof(int) = 2^9 (so only the third hex number will change per iteration)

        for (size_t j = 0; j < num_threads; j++) {
            grading_printf("Creating thread %d\n", j);
            args[j].buf = buf;
            args[j].thread_num = j + 1;
            args[j].num_ints = num_ints;
            args[j].iteration_size = iteration_size;
            t[j] = thread_create(test_map_thread, &args[j]);
            grading_printf("Thread %d is running\n", j);
        }

        for (size_t j = 0; j < num_threads; j++) {
            thread_join(t[j], NULL);
            for (size_t k = 0; k + j + 1 < num_ints; k += iteration_size) {
                if (((int*) buf)[k + j + 1] != (int) j + 1) {
                    grading_test_fail("Multiple Threads", "Failed to put correct value in buf. Got %d, expected %d at address %p. Thread number: %x\n", ((int*) buf)[k + j + 1] != (int) j + 1, j + 1, k + j, j + 1);
                
                }
            }
        }

        free(buf);
    }

    grading_test_pass("Multiple Threads", "Successfully mapped and accessed large frame.");
}

/* Main function to run the paging tests */
errval_t grading_run_tests_paging(void) {
    if (grading_options.paging_subtest_run == 0) {
        return SYS_ERR_OK;
    }

    // Run tests on core 0 only
    if (disp_get_core_id() != 0) {
        return SYS_ERR_OK;
    }

    grading_printf("#################################################\n");
    grading_printf("# TESTS: Paging System Tests \n");
    grading_printf("#################################################\n");

    // tests
    test_fixed_address_mapping();
    test_heap_allocation();
    test_large_frame_mapping();
    test_sparse_memory_access();
    test_multi_l3_mapping();
    test_misaligned_mapping();
    test_map_then_unmap_indefinitely();
    test_multiple_threads();

    grading_printf("#################################################\n");
    grading_printf("# DONE:  Paging System Tests \n");
    grading_printf("#################################################\n");

    return SYS_ERR_OK;
}

bool grading_opts_handle_paging_tests(struct grading_options *opts, const char *arg) {
    (void)arg;

    // Enable the paging tests
    opts->paging_subtest_run = 0x1;

    // TODO(optional): parsing options to selectively enable tests or configure them at runtime.

    return true;
}