#include <signal.h>
#include <unistd.h>

static void handler(int signum)
{
    (void)signum;
    static const char message[] = "handled\n";
    write(1, message, sizeof(message) - 1);
}

int main(void)
{
    signal(SIGUSR1, handler);

    static const char before[] = "before\n";
    write(1, before, sizeof(before) - 1);

    raise(SIGUSR1);

    static const char after[] = "after\n";
    write(1, after, sizeof(after) - 1);
    return 0;
}
