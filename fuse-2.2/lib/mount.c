/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "fuse.h"
#include "fuse_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#define FUSERMOUNT_PROG         "fusermount"
#define FUSE_COMMFD_ENV         "_FUSE_COMMFD"


/* return value:
 * >= 0  => fd
 * -1    => error
 */
static int receive_fd(int fd)
{
    struct msghdr msg;
    struct iovec iov;
    char buf[1];
    int rv;
    int connfd = -1;
    char ccmsg[CMSG_SPACE(sizeof(connfd))];
    struct cmsghdr *cmsg;

    iov.iov_base = buf;
    iov.iov_len = 1;

    msg.msg_name = 0;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    /* old BSD implementations should use msg_accrights instead of
     * msg_control; the interface is different. */
    msg.msg_control = ccmsg;
    msg.msg_controllen = sizeof(ccmsg);

    while(((rv = recvmsg(fd, &msg, 0)) == -1) && errno == EINTR);
    if (rv == -1) {
        perror("recvmsg");
        return -1;
    }
    if(!rv) {
        /* EOF */
        return -1;
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg->cmsg_type == SCM_RIGHTS) {
        fprintf(stderr, "got control message of unknown type %d\n",
                cmsg->cmsg_type);
        return -1;
    }
    return *(int*)CMSG_DATA(cmsg);
}

void fuse_unmount(const char *mountpoint)
{
    const char *mountprog = FUSERMOUNT_PROG;
    char umount_cmd[1024];

    snprintf(umount_cmd, sizeof(umount_cmd) - 1, "%s -u -q -z %s", mountprog,
             mountpoint);

    umount_cmd[sizeof(umount_cmd) - 1] = '\0';
    system(umount_cmd);
}

int fuse_mount(const char *mountpoint, const char *opts)
{
    const char *mountprog = FUSERMOUNT_PROG;
    int fds[2], pid;
    int res;
    int rv;

    res = socketpair(PF_UNIX, SOCK_STREAM, 0, fds);
    if(res == -1) {
        perror("fuse: socketpair() failed");
        return -1;
    }

#ifndef USE_UCLIBC
    pid = fork();
#else
    pid = vfork();
#endif
    if(pid == -1) {
        perror("fuse: fork() failed");
        close(fds[0]);
        close(fds[1]);
        return -1;
    }

    if(pid == 0) {
        char env[10];
        const char *argv[] = {mountprog, opts ? "-o" : mountpoint, opts,
                              mountpoint, NULL};

        close(fds[1]);
        fcntl(fds[0], F_SETFD, 0);
        snprintf(env, sizeof(env), "%i", fds[0]);
        setenv(FUSE_COMMFD_ENV, env, 1);
        execvp(mountprog, (char **) argv);
        perror("fuse: failed to exec fusermount");
        exit(1);
    }

    close(fds[0]);
    rv = receive_fd(fds[1]);
    close(fds[1]);
    waitpid(pid, NULL, 0); /* bury zombie */

    return rv;
}

int fuse_mount_compat1(const char *mountpoint, const char *args[])
{
    /* just ignore mount args for now */
    (void) args;
    return fuse_mount(mountpoint, NULL);
}
