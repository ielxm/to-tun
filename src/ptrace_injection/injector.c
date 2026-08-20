#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sched.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define SOCKET_PATH "/tmp/socksocksock_scm.sock"
#define T_NETNS_PATH "/run/netns/T"

int send_fd(int sk, int fd_t_s)
{
    struct msghdr msg = {0};

    struct iovec iov[1];
    char dummy_byte = 'F';
    iov[0].iov_base = &dummy_byte;
    iov[0].iov_len = sizeof(dummy_byte);

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));

    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));

    memcpy(CMSG_DATA(cmsg), &fd_t_s, sizeof(int));

    if (sendmsg(sk, &msg, 0) < 0)
    {
        perror("sendmsg");
        return -1;
    }
    return 0;
}

static long make_syscall(pid_t pid, long nr, long arg1, long arg2, long arg3)
{
    struct user_regs_struct r, save;
    int st;
    ptrace(PTRACE_ATTACH, pid, 0, 0);

    waitpid(pid, &st, 0);
    
    ptrace (PTRACE_GETREGS, pid, 0, &r);
    
    save = r;

    long word = ptrace(PTRACE_PEEKTEXT, pid, r.rip, 0);
    if (word == -1 && errno !=0 )
    {
        perror("PTRACE_PEEKTEXT");
        return 1;
    }

    ptrace(
        PTRACE_POKETEXT,
        pid,
        r.rip,
        (word & ~0xffff) | 0x050f //syscall
    );

    r.rax = nr; // __NR_setns
    r.rdi = arg1; // fd
    r.rsi = arg2; // CLONE_NEWNET
    r.rdx = arg3; // not used

    ptrace(PTRACE_SETREGS, pid, 0, &r);

    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);

    waitpid(pid, &st, 0);

    ptrace(PTRACE_GETREGS, pid, 0, &r);

    long ret = r.rax;

    ptrace(PTRACE_POKETEXT, pid, save.rip, word);

    ptrace(PTRACE_SETREGS, pid, 0, &save);

    ptrace(PTRACE_DETACH, pid, 0, 0);

    return ret;
}
int main()
{
    int nsfd = open(T_NETNS_PATH, O_RDONLY);
    if (nsfd < 0)
    {
        perror("nsfd can't open error");
        exit(EXIT_FAILURE);
    }

    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0)
    {
        perror("socket error");
        close(nsfd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("can't connect to socket it's probably not running");
        close(sock_fd);
        close(nsfd);
        exit(EXIT_FAILURE);
    }

    // getting pid
    struct ucred creds;
    socklen_t len = sizeof(creds);
    if (getsockopt(sock_fd, SOL_SOCKET, SO_PEERCRED, &creds, &len) < 0)
    {
        perror("getsockopt SO_PEERCRED");
        close(sock_fd);
        close(nsfd);
        exit(EXIT_FAILURE);
    }
    pid_t t_pid = creds.pid;

    // sending fd
    if (send_fd(sock_fd, nsfd) < 0)
    {
        fprintf(stderr, "can't send fd");
    } else
    {
        printf("success\n");
    }

    // getting nsfd, it's version from receiver
    int t_fd;
    if (read(sock_fd, &t_fd, sizeof(int)) <= 0)
    {
        perror("read t_fd");
        exit(EXIT_FAILURE);
    }


    long ret = make_syscall(t_pid, __NR_setns, t_fd, CLONE_NEWNET, 0);
    //printf("%ld\n", ret);
    write(sock_fd, "K", 1);
    close(nsfd);
    close(sock_fd);
    return EXIT_SUCCESS;
}