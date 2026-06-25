#include <stddef.h>
#include <sys/mman.h>

#ifndef MAP_UNINITIALIZED
#    define MAP_UNINITIALIZED 0x4000000
#endif

// Demonstrates CPU taint propagation: an uninitialized byte is loaded into a
// register, then used to decide a conditional branch. The emulator should report
// both the uninitialized read and that a branch depended on uninitialized data,
// and keep running (the report is non-fatal).
int main(void)
{
    volatile char* mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_UNINITIALIZED, -1, 0);
    if (mapping == MAP_FAILED)
        return 1;

    if (mapping[7])
        return 2;
    return 0;
}
