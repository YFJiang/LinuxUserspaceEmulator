#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void)
{
    char* mapping = mmap(NULL, 12288, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 1;

    strcpy(mapping, "left");
    strcpy(mapping + 4096, "middle");
    strcpy(mapping + 8192, "right");

    if (mprotect(mapping + 4096, 4096, PROT_READ) != 0)
        return 2;

    mapping[0] = 'L';
    mapping[8192] = 'R';

    if (strcmp(mapping, "Left") != 0)
        return 3;
    if (strcmp(mapping + 4096, "middle") != 0)
        return 4;
    if (strcmp(mapping + 8192, "Right") != 0)
        return 5;

    if (munmap(mapping + 4096, 4096) != 0)
        return 6;

    mapping[1] = 'E';
    mapping[8193] = 'I';

    if (write(1, mapping, 4) != 4)
        return 7;
    if (write(1, "\n", 1) != 1)
        return 8;
    if (write(1, mapping + 8192, 5) != 5)
        return 9;
    if (write(1, "\n", 1) != 1)
        return 10;

    if (munmap(mapping, 4096) != 0)
        return 11;
    if (munmap(mapping + 8192, 4096) != 0)
        return 12;

    return 0;
}
