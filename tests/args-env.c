#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
    printf("argc=%d\n", argc);
    for (int i = 0; i < argc; ++i)
        printf("argv[%d]=%s\n", i, argv[i]);
    const char* value = getenv("LUE_TEST_VALUE");
    printf("LUE_TEST_VALUE=%s\n", value ? value : "(null)");
    return 0;
}
