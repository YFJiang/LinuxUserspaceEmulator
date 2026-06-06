#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    char* leaked = malloc(13);
    if (!leaked)
        return 1;
    leaked[0] = 'L';

    char* overflow = malloc(1);
    if (!overflow)
        return 2;
    overflow[16] = '!';

    char* freed = malloc(8);
    if (!freed)
        return 3;
    free(freed);
    freed[0] = '?';

    write(1, "malloc tracer guest done\n", 25);
    return 0;
}
