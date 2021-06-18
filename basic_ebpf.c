#define KBUILD_MODNAME "tc"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/filter.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/sched.h>



#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif
#define htons(x) ((__be16)___constant_swab16((x)))

// #define TASK_COMM_LEN	16

// static inline int check_process(void)
// {
// 	const char name[] = "telnet";
// 	char task_name[TASK_COMM_LEN] = { 0 };
// 	const struct task_struct *t;

// 	t = (struct task_struct *) bpf_get_current_task();

// 		bpf_get_current_comm(&task_name, sizeof(task_name));

// 	for (int i = 0; i < sizeof(name); ++i) {
// 		if (task_name[i] != name[i])
// 			return 0;
// 	}
	
// 	return 1;
// }

static inline int drop_pkt(struct __sk_buff *skb)
{
    int eth_off = 0;
    int iphdr_off = 0;
            
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    eth_off = sizeof(*eth);

    struct iphdr *ip = (data + eth_off);
    iphdr_off = sizeof(*ip);

    struct tcphdr *tcph = (data + eth_off + iphdr_off);

    if (data + eth_off + iphdr_off + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
                //return XDP_DROP;
    if (ip->protocol == IPPROTO_TCP && (tcph->dest == htons(80) || tcph->source == htons(80)) ) {
        return XDP_PASS;
        }
    else {
       return XDP_DROP;
    }
}
__section("classifier")
int xdp_drop(struct __sk_buff *skb)
{
    // if (check_process())
    // {
         return drop_pkt(skb);
    // }
    // else
    //     return XDP_DROP;        
}

char __license[] __section("license") = "GPL";

/* Loading the eBPF program into kernel space
sudo tc qdisc add dev ens33 clsact
sudo tc filter add dev ens33 egress bpf direct-action obj basic_ebpf.o sec classifier
tc filter show dev ens33 egress

*** Unloading
sudo tc filter del dev ens33 egress
*/