# MicroKernel OS

This repository contains a microkernel-based operating system developed as part of an academic systems project. The project was completed collaboratively by a team of four. Due to university licensing and policy restrictions, portions of the codebase are encrypted and not publicly available. The unencrypted files included here represent my original contributions and are provided for demonstration purposes.

## Repository Overview

The repository contains a subset of the full system. All publicly visible source files are written by me and focus primarily on memory management and core runtime utilities.

### Public Source Files

- `lib/mm/mm.c`  
  Implements the kernel memory management subsystem, including low-level allocation primitives and internal data structures.

- `lib/aos/paging.c`  
  Implements virtual memory and paging functionality, including page table management and fault handling support.

- `lib/grading/tests/test_paging.c`  
  Test suite used to validate correctness and robustness of the paging subsystem.

- `lib/hashtable/hashtable.c`  
  Custom hashtable implementation used across the system for efficient key-value storage.

- `lib/util/`  
  General utility code shared across kernel components.

### Encrypted Files

All remaining files in the repository are encrypted to comply with academic licensing policies. These files are part of the full operating system but cannot be distributed publicly.

If you are authorized to view the full codebase, feel free to contact me directly for more details.

## Key Components

### Memory Management

The memory management subsystem provides low-level allocation mechanisms required by the kernel. This includes support for paging-related operations and internal allocators designed for constrained environments.

### Virtual Memory and Paging

The paging subsystem handles address space management and virtual-to-physical memory translation. The implementation focuses on correctness, safety, and reliability under constrained kernel conditions.

### Testing

Paging functionality is validated using a dedicated test suite to ensure correct behavior and catch edge cases early during development.

## Notes

This project was designed to closely mirror real operating system concepts such as memory protection, address translation, and kernel-level resource management. While not all source files can be shared publicly, the code provided reflects the core systems work completed as part of the project.
