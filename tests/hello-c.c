#include <unistd.h>

int main(void)
{
    static const char message[] = "hello from C guest\n";
    write(1, message, sizeof(message) - 1);
    return 0;
}
