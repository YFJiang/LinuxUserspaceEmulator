#include <stddef.h>
#include <sys/mman.h>

int main(void)
{
    char* mapping = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 1;
    if (mprotect(mapping + 4096, 4096, PROT_READ) != 0)
        return 2;

    mapping[0] = 'a';
    mapping[4096] = 'b';
    return 0;
}
