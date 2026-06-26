#include <stdlib.h>
#include <unistd.h>

// Exercises the MallocTracer read audit: reading never-written heap memory
// (uninitialized heap read) and reading memory after it has been freed
// (use-after-free read). Both are non-fatal reports; the guest keeps running.

int main(void)
{
    // Uninitialized heap read: malloc returns untouched storage, so reading a
    // byte the guest never wrote should be reported.
    volatile char* a = malloc(8);
    if (!a)
        return 1;
    volatile char uninitialized = a[3];
    (void)uninitialized;

    // Use-after-free read: free a block, then read from it.
    char* b = malloc(8);
    if (!b)
        return 2;
    b[0] = 'x';
    free(b);
    volatile char after_free = b[0];
    (void)after_free;

    write(1, "malloc audit guest done\n", 24);
    return 0;
}
