#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <linux/filter.h>
#include "bpf_legacy.h"


#ifndef __section
#define __section(x)	__attribute__((section((x)), used))
#endif

#ifndef offsetof
#define offsetof(x, y)	__builtin_offsetof(x, y)
#endif

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)
#define TASK_COMM_LEN	16

#define BPF_MAP_ID_STATS	1
#define PIN_GLOBAL_NS		2


// static inline int getProgram(void)
// {
// 	const char name[] = "telnet";
// 	char task_name[TASK_COMM_LEN] = { 0 };
	
// 	bpf_get_current_comm(&task_name, sizeof(task_name));
    
//     /* Test if the process name is the one expected */
// 	for (int i = 0; i < sizeof(name); ++i) {
// 	    if (task_name[i] != name[i])
// 	 		return 1;
// 	 }
	
//     /* In case of success, return 0 */
// 	return 0;
// }

static inline int tcp_port_egress_block(struct __sk_buff *skb, __u16 blk_port)
{
	__u8 ip_proto, ip_vl;
	__u16 dport;
	int nh_off = BPF_LL_OFF + ETH_HLEN;
	
	if (skb->protocol != __constant_htons(ETH_P_IP))
		return TC_ACT_OK;
	
	ip_proto = load_byte(skb, nh_off + offsetof(struct iphdr, protocol));
	if (ip_proto != IPPROTO_TCP)
		return TC_ACT_OK;

	ip_vl = load_byte(skb, nh_off);
	if (ip_vl == 0x45)
		nh_off += sizeof(struct iphdr);
	else
		nh_off += (ip_vl & 0xF) << 2;

	dport = load_half(skb, nh_off + offsetof(struct tcphdr, dest));
	if (dport != blk_port ) {
		return TC_ACT_SHOT;
	}
	return TC_ACT_OK;
}

static inline int tcp_port_ingress_block(struct __sk_buff *skb, __u16 blk_port)
{
	__u8 ip_proto, ip_vl;
	__u16 sport;
	int nh_off = BPF_LL_OFF + ETH_HLEN;
	
	if (skb->protocol != __constant_htons(ETH_P_IP))
		return TC_ACT_OK;
	
	ip_proto = load_byte(skb, nh_off + offsetof(struct iphdr, protocol));
	if (ip_proto != IPPROTO_TCP)
		return TC_ACT_OK;

	ip_vl = load_byte(skb, nh_off);
	if (ip_vl == 0x45)
		nh_off += sizeof(struct iphdr);
	else
		nh_off += (ip_vl & 0xF) << 2;

	sport = load_half(skb, nh_off + offsetof(struct tcphdr, source));
	if (sport != blk_port ) {
		return TC_ACT_SHOT;
	}
	return TC_ACT_OK;
}

/* Ingress hook - handle incoming packets */
__section("cgroup_skb/ingress")
int ingress(struct __sk_buff *skb) {
    int ret = 0;
    __u16 port = 4040;
    // ret = getProgram();
    // if (!ret)
    //     return 1;
    ret = tcp_port_ingress_block(skb, port);
    if (!ret)
        return 1;
    return 0;
}

/* Egress hook - handle outgoing packets */
__section("cgroup_skb/egress")
int egress(struct __sk_buff *skb) {
    
    int ret = 0;
    __u16 port = 4040;
    // ret = getProgram();
    // if (!ret)
    //     return 1;
    ret = tcp_port_egress_block(skb, port);
    if (!ret)
        return 1;
    return 0;

}

char __license[] __section("license") = "GPL";