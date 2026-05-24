#include <fcntl.h>
#include <unistd.h>

int main(int argc, char** argv)
{
    int fd = 0;
    if (argc > 1) {
        fd = open(argv[1], O_RDONLY);
        if (fd < 0)
            return 1;
    }

    char buffer[128];
    for (;;) {
        ssize_t nread = read(fd, buffer, sizeof(buffer));
        if (nread < 0)
            return 2;
        if (nread == 0)
            break;
        char* out = buffer;
        while (nread > 0) {
            ssize_t nwritten = write(1, out, nread);
            if (nwritten < 0)
                return 3;
            out += nwritten;
            nread -= nwritten;
        }
    }

    if (fd != 0)
        close(fd);
    return 0;
}
