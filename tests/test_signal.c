#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

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
    printf("register singal done.\r\n");
    while(1){
	    ;
    }
    return 0;
}
