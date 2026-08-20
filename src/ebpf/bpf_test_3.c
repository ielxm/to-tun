#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

SEC("cgroup/sock")
int mark_socket(struct bpf_sock *sk) 
{
    sk->mark = 0x42;
    return 1;
}
char LICENSE[] SEC("license")="GPL";

//clang -O2 -g -target bpf -c src/bpf_test_3.c -o mark.o
//sudo bpftool prog load mark.o /sys/fs/bpf/t_slice_mark
//sudo bpftool cgroup attach /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/T.slice sock pinned /sys/fs/bpf/t_slice_mark

//ip rule add fwmark 0x42 lookup 100
//ip route add default via 172.19.100.1 dev tun0 table 100