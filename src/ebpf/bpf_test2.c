#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("cgroup_skb/egress")
int mark_egress(struct __sk_buff *skb) 
{
    skb->mark = 0x42;
    return 1;
}
char LICENSE[] SEC("license")="GPL";