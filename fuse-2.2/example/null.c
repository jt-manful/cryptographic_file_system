/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include <fuse.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#define UNUSED(x) x __attribute__((unused))

static int null_getattr(const char *path, struct stat *stbuf)
{
    if(strcmp(path, "/") != 0)
        return -ENOENT;

    stbuf->st_mode = S_IFREG | 0644;
    stbuf->st_nlink = 1;
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();
    stbuf->st_size = (1ULL << 32); /* 4G */
    stbuf->st_blocks = 0;
    stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = time(NULL);

    return 0;
}

static int null_truncate(const char *path, off_t UNUSED(size))
{
    if(strcmp(path, "/") != 0)
        return -ENOENT;

    return 0;
}

static int null_open(const char *path, struct fuse_file_info *UNUSED(fi))
{
    if(strcmp(path, "/") != 0)
        return -ENOENT;

    return 0;
}

static int null_read(const char *path, char *UNUSED(buf), size_t size,
                     off_t UNUSED(offset), struct fuse_file_info *UNUSED(fi))
{
    if(strcmp(path, "/") != 0)
        return -ENOENT;

    return size;
}

static int null_write(const char *path, const char *UNUSED(buf), size_t size,
                     off_t UNUSED(offset), struct fuse_file_info *UNUSED(fi))
{
    if(strcmp(path, "/") != 0)
        return -ENOENT;

    return size;
}

static struct fuse_operations null_oper = {
    .getattr	= null_getattr,
    .truncate	= null_truncate,
    .open	= null_open,
    .read	= null_read,
    .write	= null_write,
};

int main(int argc, char *argv[])
{
    return fuse_main(argc, argv, &null_oper);
}
