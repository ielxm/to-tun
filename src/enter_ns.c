// All credits goes to ielxm
// LICENCE: MIT
//
// Please, keep in mind that you're about to run some code from an unknown person with questionable knowledge level about C and Linux
// It is even more risky because this code requires SUID to work properly

#define _GNU_SOURCE

#include <sys/prctl.h>
#include <stdio.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <grp.h>

#define NETNS_PATH "/run/netns/T"
#define CGROUP_ROOT "/sys/fs/cgroup/user.slice"
#define SLICE_NAME "T.slice"
#define ALLOWED_UID 1000
#define ALLOWED_GID 1000

static void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static void jcgroup(uid_t uid)
{
    char cgroupp[512];
    int n = snprintf(cgroupp, sizeof(cgroupp), CGROUP_ROOT "/user-%u.slice/user@%u.service/" SLICE_NAME "/cgroup.procs", uid,uid);
    if (n<0||n>=sizeof(cgroupp)) die("snprintf");
    int fd = open(cgroupp, O_WRONLY | O_CLOEXEC);
    if (fd<0) die("open cgroup");
    if (dprintf(fd,"%d\n",getpid())<0) die("write cgroup");
    if (close(fd)<0) die("close cgroup");
}

int main(int argc, char **argv)
{
    if (geteuid() != 0) {
        fprintf(stderr,"must be suid root\n");
        return 1;
    }

    uid_t uid = getuid();
    gid_t gid = getgid();

    if (uid!=ALLOWED_UID || gid!=ALLOWED_GID) {
        fprintf(stderr,"user is not allowed to use this program\n");
        return 1;
    }

    if (argc<2) {
        fprintf(stderr,"usage: %s <program> [args...]\n",argv[0]);
        return 1;
    }

    int fd = open(NETNS_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd<0) return 1;

    if (setgroups(0,NULL) < 0) die("setgroups");

    if (setns(fd, CLONE_NEWNET) < 0) die("setns");
    
    if (close (fd)<0) die("close");
    
    if (setresgid(gid,gid,gid)<0) die("setresgid");
    if (setresuid(uid,uid,uid)<0) die("setresuid");

    if (getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid) {
        fprintf(stderr,"privilege drop failed\n");
        return 1;
    }

    jcgroup(uid);

    if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)<0) die("no_new_privs");

    execv(argv[1], &argv[1]);
    die("exec sh");
}