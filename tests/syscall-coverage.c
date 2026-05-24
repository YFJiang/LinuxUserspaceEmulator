#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fail(const char* message)
{
    printf("FAIL %s errno=%d\n", message, errno);
    return 1;
}

int main(void)
{
    int pipe_fds[2];
    if (pipe(pipe_fds) < 0)
        return fail("pipe");
    if (write(pipe_fds[1], "x", 1) != 1)
        return fail("pipe write");

    struct pollfd pfd = { .fd = pipe_fds[0], .events = POLLIN };
    if (poll(&pfd, 1, 0) != 1 || !(pfd.revents & POLLIN))
        return fail("poll");

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(pipe_fds[0], &readfds);
    struct timeval zero = { 0, 0 };
    if (select(pipe_fds[0] + 1, &readfds, NULL, NULL, &zero) != 1 || !FD_ISSET(pipe_fds[0], &readfds))
        return fail("select");

    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0)
        return fail("socketpair");
    if (write(sockets[0], "y", 1) != 1)
        return fail("socket write");

    int epfd = epoll_create1(0);
    if (epfd < 0)
        return fail("epoll_create1");
    struct epoll_event event = { .events = EPOLLIN, .data.fd = sockets[1] };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockets[1], &event) < 0)
        return fail("epoll_ctl");
    struct epoll_event out_event;
    if (epoll_wait(epfd, &out_event, 1, 0) != 1 || out_event.data.fd != sockets[1])
        return fail("epoll_wait");

    struct timeval tv;
    if (gettimeofday(&tv, NULL) < 0 || tv.tv_sec <= 0)
        return fail("gettimeofday");
    struct timespec tiny = { 0, 1000 };
    if (nanosleep(&tiny, NULL) < 0)
        return fail("nanosleep");

    errno = 0;
    if (wait4(-1, NULL, WNOHANG, NULL) != -1 || errno != ECHILD)
        return fail("wait4");

#ifdef MAP_FIXED_NOREPLACE
    void* first = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (first == MAP_FAILED)
        return fail("mmap");
    errno = 0;
    void* second = mmap(first, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (second != MAP_FAILED || errno != EEXIST)
        return fail("mmap fixed noreplace");
    munmap(first, 4096);
#endif

    printf("syscall coverage ok\n");
    return 0;
}
