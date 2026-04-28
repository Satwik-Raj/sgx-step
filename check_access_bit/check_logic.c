#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/mman.h>

#define IOCTL_CHECK  _IOWR('a', 'a', struct query)
#define IOCTL_CLEAR  _IOW('a', 'b', struct query)

struct query {
    int pid;
    unsigned long addr;
    int accessed;
};

int main()
{
    int fd = open("/dev/abit_probe", O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    size_t page_size = getpagesize();

    char *page = mmap(NULL, page_size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1, 0);

    if (page == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    struct query q;
    q.pid = getpid();
    q.addr = (unsigned long)page;

    /* Step 1: clear accessed bit */
    ioctl(fd, IOCTL_CLEAR, &q);

    // 

    printf("After clear:\n");
    ioctl(fd, IOCTL_CHECK, &q);
    printf("Accessed bit = %d\n", q.accessed);

    /* Step 2: access page */
    page[0] = 42; // write
    printf("%d \n", page[1020]); //read. you can do either way

    printf("After access:\n");
    ioctl(fd, IOCTL_CHECK, &q);
    printf("Accessed bit = %d\n", q.accessed);

    close(fd);
    return 0;
}
