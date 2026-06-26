#include <stdlib.h>
#include <unistd.h>

// Exercises the leak reachability graph: one allocation stays reachable through
// a global pointer (still reachable), while another has its only reference
// dropped (definitely lost). The leak report should classify them separately.

static void* g_kept; // global root keeps its allocation reachable

static void make_lost_leak(void)
{
    // The only pointer to this block lives in a local that dies with the frame.
    char* lost = malloc(48);
    if (lost)
        lost[0] = 'x';
}

static void scrub_stack(void)
{
    // Overwrite the abandoned frame (and any lingering pointer copy) so the
    // dropped allocation is genuinely unreachable from the stack.
    volatile char buf[512];
    for (unsigned i = 0; i < sizeof(buf); ++i)
        buf[i] = 0;
}

int main(void)
{
    g_kept = malloc(32);
    if (!g_kept)
        return 1;
    ((char*)g_kept)[0] = 'k';

    make_lost_leak();
    scrub_stack();

    write(1, "leak reachability guest done\n", 29);
    return 0;
}
