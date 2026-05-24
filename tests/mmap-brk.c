#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void)
{
    char* heap = malloc(32);
    if (!heap)
        return 1;
    strcpy(heap, "heap ok\n");
    write(1, heap, strlen(heap));

    char* mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 2;
    strcpy(mapping, "mmap ok\n");
    write(1, mapping, strlen(mapping));
    if (mprotect(mapping, 4096, PROT_READ) != 0)
        return 3;
    if (munmap(mapping, 4096) != 0)
        return 4;
    free(heap);
    return 0;
}
