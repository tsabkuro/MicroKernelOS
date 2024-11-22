/**
 * \file
 * \brief Bitmap operations for memory management
 */

#include <string.h>
#include <aos/domain.h>
#include <aos/types.h>
#include <util/bitmap.h>

/**
 * @brief helper function that checks if a bit is set in the bitmap
 */
bool bitmap_is_set(uint8_t *bitmap, size_t bit_index) {
    size_t byte_index = bit_index / 8;
    size_t bit_offset = bit_index % 8;
    return (bitmap[byte_index] >> bit_offset) & 1;
}

/**
 * @brief helper function to set a bit in the bitmap
 */
void bitmap_set_bit(uint8_t *bitmap, size_t bit_index) {
    size_t byte_index = bit_index / 8;
    size_t bit_offset = bit_index % 8;
    bitmap[byte_index] |= (1 << bit_offset);
}

/**
 * @brief helper function to clear a bit in the bitmap
 */
void bitmap_clear_bit(uint8_t *bitmap, size_t bit_index) {
    size_t byte_index = bit_index / 8;
    size_t bit_offset = bit_index % 8;
    bitmap[byte_index] &= ~(1 << bit_offset);
}

void bitmap_clear_bits(uint8_t *bitmap, uint64_t offset, size_t num_bits) {
    for (size_t i = 0; i < num_bits; i++) {
        bitmap_clear_bit(bitmap, offset + i);
    }
}

/**
 * @brief helper function to count free pages in bitmap to a certain limit
 * @param[in] max_count     the max limit to count to. Suggested is num_pages * 2
 */
size_t count_forward_pages(uint8_t *bitmap, size_t start_index, size_t max_count, size_t bitmap_size) {
    size_t free_count = 0;
    for (size_t k = 0; k < max_count && (start_index + k) < bitmap_size; k++) {
        if (bitmap_is_set(bitmap, start_index + k)) {
            break; // Encountered allocated page; stop counting
        }
        free_count++;
    }
    return free_count;
}

/**
 * @brief Helper function to count free pages backwards from a given index in bitmap up to a certain limit
 *
 * @param[in]  bitmap                  Pointer to the bitmap
 * @param[in]  start_index             Index from which to start counting backward
 * @param[in]  max_count               Maximum number of pages to count backward
 * @return     Number of consecutive free pages backward from start_index
 */
size_t free_backward_pages(uint8_t *bitmap, size_t start_index, size_t max_count) {
    size_t closest_allocated_after = 0;
    if (start_index == 0) { 
        return 0;
    }
    for (size_t k = 0; k < max_count; k++) {
        size_t index = start_index - k;
        if (bitmap_is_set(bitmap, index)) {
            break; // Encountered allocated page; stop counting
        }
        closest_allocated_after++;
        if (index == 0) { // Prevent underflow
            break;
        }
    }
    return closest_allocated_after;
}

/**
 * @brief first-fit allocation from a bitmap.
 *
 * @param[in] bitmap              Pointer to the bitmap.
 * @param[in] bitmap_size         Size of the bitmap in bits.
 * @param[in] num_pages           Number of pages to allocate.
 * @param[in] alignment_factor    Alignment factor for the allocation.
 * @param[out] start_index        Returns the starting index of the allocated pages.
 *
 * @return SYS_ERR_OK on success, or an error code on failure.
 */
errval_t bitmap_alloc_first_fit(uint8_t *bitmap, size_t bitmap_size, size_t num_pages, size_t alignment_factor, size_t *start_index) {
    for (size_t i = 0; i < bitmap_size; i += alignment_factor) { // we skip because of alignment
        if (bitmap_is_set(bitmap, i)) {
            continue; // if the first bit within the alignment is set, go next
        }
        
        size_t free_count = 0;
        for (size_t k = 0; k < num_pages; k++) {
            if (i + k >= bitmap_size || bitmap_is_set(bitmap, i + k)) {
                break;  // Not enough consecutive free pages
            }
            free_count++;
        }

        // If we've found enough free consecutive pages
        if (free_count == num_pages) {
            for (size_t k = 0; k < num_pages; k++) { // mark pages allocated
                bitmap_set_bit(bitmap, i + k);
            }
            *start_index = i; // Set the starting index
            return SYS_ERR_OK; // Allocation successful
        }
    }
    
    return MM_ERR_OUT_OF_MEMORY; // Not enough free pages found
}