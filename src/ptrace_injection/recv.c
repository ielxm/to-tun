#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>

#define C_PROC_NS_PATH "/proc/self/ns/net"
#define BUF_SIZE 256

#define SOCKET_PATH "/tmp/socksocksock_scm.sock"

int recv_fd(int sk)
{
    struct msghdr msg = {0};

    struct iovec iov[1];
    char dummy_byte;
    iov[0].iov_base = &dummy_byte;
    iov[0].iov_len = sizeof(dummy_byte);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));

    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    if (recvmsg(sk, &msg, 0) <= 0)
    {
        perror("recvmsg");
        return -1;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg != NULL &&
        cmsg->cmsg_level == SOL_SOCKET &&
        cmsg->cmsg_type == SCM_RIGHTS)
        {
            int received_fd;
            memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int));
            return received_fd;
        }
        return -1;
}

static unsigned long get_netns()
{
    /*char buf[BUF_SIZE];
    size_t buf_size = sizeof(buf);
    size_t len = readlink(C_PROC_NS_PATH, buf, buf_size - 1);

    if (len == -1) 
    {
        perror("readlink");
        return -1;
    }
    
    buf[len] = '\0';

    //printf("%s\n", buf);
    return EXIT_SUCCESS;*/

    struct stat st;
    if (stat(C_PROC_NS_PATH, &st) < 0)
    {
        perror("stat ns");
        return 0;
    }
    return st.st_ino;
}
int main(int argc, char *argv[])
{
    unlink(SOCKET_PATH);
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 1) < 0 )
    {
        perror("listen");
        close(server_fd);
        unlink(SOCKET_PATH);
        exit(EXIT_FAILURE);
    }

    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0)
    {
        perror("accept");
        close(server_fd);
        unlink(SOCKET_PATH);
        exit(EXIT_FAILURE);
    }

    int nsfd = recv_fd(client_fd);
    if (nsfd < 0)
    {
        fprintf(stderr, "Can't receive fd\n");
    }
    printf("fd received\n");    
    write(client_fd, &nsfd, sizeof(int));

    printf("waiting for sender to perform injection\n");
    char sync_byte;
    read(client_fd, &sync_byte, 1);

    close(nsfd);
    close(client_fd);
    close(server_fd);
    unlink(SOCKET_PATH);

    unsigned long initial_ns = get_netns();

    while (1)
    {
        unsigned long current_ns = get_netns();
        if (initial_ns != current_ns)
        {
            puts("ns has changed");
        }
        sleep(1); //1sec
    }

    return EXIT_SUCCESS;
}