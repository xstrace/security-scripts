#define _GNU_SOURCE

#include <unistd.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <string.h>

#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif

#define FAKE_EXE_LENGTH 0x10

extern int errno;

int dprint(const char *fmt, ...)
{
    va_list args;
    int n;
    FILE *log = stdout;
    va_start(args, fmt);
    n = vfprintf(log, fmt, args);
    va_end(args);
    fflush(log);
    return n;
}

int prctl_proc_name(char *name)
{
    int ret = prctl(PR_SET_NAME, name);
    if (ret < 0)
    {
        perror("prctl");
    }
    return 0;
}

int remap(const char *path)
{
    char line_buf[512] = {};
    struct stat dl_stat;
    int remapped = -1;

    if (!path || path[0] == '\0')
    {
        return -1;
    }

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps)
    {
        return -1;
    }

    if (stat(path, &dl_stat) < 0)
    {
        dprint("Remap %s - failed, stat() failed: %m\n", path);
        goto lbExit;
    }

    if (dl_stat.st_ino == 0)
    {
        dprint("Remap %s - failed, stat() failed: st_ino == 0\n", path);
        goto lbExit;
    }

    while (fgets(line_buf, sizeof(line_buf), maps))
    {
        unsigned long long addr_start, addr_end, inode;
        unsigned long long l_size = 0;
        unsigned int file_offset, dev_major, dev_minor;
        char perm[4];
        char _path[256] = {0};
        unsigned short s_dev = 0;

        sscanf(line_buf, "%Lx-%Lx %4c %x %02x:%02x %Lu %s", &addr_start, &addr_end, perm, &file_offset, &dev_major, &dev_minor, &inode, _path);

        s_dev = (unsigned short)((dev_major << 8 | dev_minor) & 0xFFFF);
        if (!(s_dev == dl_stat.st_dev && inode == dl_stat.st_ino))
        {
            continue;
        }
        dprint(line_buf);

        l_size = addr_end - addr_start;

        int flags = 0;
        if (perm[0] == 'r')
            flags |= PROT_READ;
        if (perm[1] == 'w')
            flags |= PROT_WRITE;
        if (perm[2] == 'x')
            flags |= PROT_EXEC;

        void *new_map = MAP_FAILED;
        if (flags)
        {
            new_map = mmap(NULL, l_size,
                           PROT_WRITE | PROT_READ,
                           MAP_PRIVATE | MAP_ANONYMOUS,
                           -1, 0);
            if (new_map == MAP_FAILED)
            {
                dprint("Remap %s - %p - %p (%s) - failed, new mmap: %m\n",
                       path, addr_start, addr_end, perm);
                continue;
            }
            memcpy(new_map, (void *)addr_start, l_size);

            if (flags != (PROT_READ | PROT_WRITE))
            {
                if (mprotect(new_map, l_size, flags) != 0)
                {
                    dprint("Remap %s - %p - %p (%s) - failed, mprotect: %m\n",
                           path, addr_start, addr_end, perm);
                    munmap(new_map, l_size);
                    remapped = 0;
                    continue;
                }
            }

            if (mremap(new_map, l_size, l_size,
                       MREMAP_FIXED | MREMAP_MAYMOVE,
                       (void *)addr_start) == MAP_FAILED)
            {
                dprint("Remap %s - %p - %p (%s) - failed, remap: %m\n",
                       path, addr_start, addr_end, perm);
                munmap(new_map, l_size);
                remapped = -1;
            }
        }
    }

lbExit:
    fclose(maps);

    return remapped;
}

void main(int argc, char *argv[])
{
    printf("start pid: %d\n", getpid());

    // modify cmdline
    memset((void *)argv[0], '\0', strlen(argv[0]));
    strcpy(argv[0], "-bash");

    pid_t pid = fork();
    if (pid > 0)
    {
        printf("new pid: %d\n", pid);
        return;
    }

    prctl_proc_name("bash");

    const char *fake = "/bin/bash";
    int fd = open(fake, O_RDONLY);
    remap("/proc/self/exe");
    int ret = prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0, 0);

    sleep(600);
}
