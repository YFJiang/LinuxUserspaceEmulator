#include <stddef.h>
#include <sys/mman.h>

#ifndef MAP_UNINITIALIZED
#    define MAP_UNINITIALIZED 0x4000000
#endif

int main(void)
{
    char* mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_UNINITIALIZED, -1, 0);
    if (mapping == MAP_FAILED)
        return 1;

    mapping[0] = 'x';
    volatile char value = mapping[1];
    (void)value;
    return 0;
}
