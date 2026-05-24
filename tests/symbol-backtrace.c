#include <unistd.h>

__attribute__((noinline)) void boom(void)
{
    __asm__ volatile(".byte 0x0f, 0x0b");
}

int main(void)
{
    static const char message[] = "before trap\n";
    write(1, message, sizeof(message) - 1);
    boom();
    return 0;
}
