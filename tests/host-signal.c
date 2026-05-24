#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

static void handler(int signum)
{
    (void)signum;
    static const char message[] = "handled\n";
    write(1, message, sizeof(message) - 1);
    exit(0);
}

int main(void)
{
    signal(SIGINT, handler);

    static const char ready[] = "ready\n";
    write(1, ready, sizeof(ready) - 1);

    for (;;)
        ;
}
