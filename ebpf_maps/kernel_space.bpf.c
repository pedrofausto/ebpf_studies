#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/filter.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <bpf/bpf_tracing.h>
#include "vmlinux.h"

#ifndef __section
# define __section(NAME) __attribute__((section(NAME), used))
#endif
#define htons(x) ((__be16)___constant_swab16((x)))

 #define TASK_COMM_LEN	16
 #define MAX_FILES	65535

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, MAX_FILES);
} file_map SEC(".maps");


SEC("cgroup/connect4")
int check_packet(struct bpf_sock_addr *ctx)
{
    __u32 *value = 0;
    int init_key = 1;
    int ret_map = 0;
	
	const char map_error[] = "Error creating map";
    const char number_packets[] = "Number of captured TCP packets: %d";
    
	
	if (ctx->protocol == IPPROTO_TCP)
    {
        
        value = bpf_map_lookup_elem(&file_map, &init_key);
        ret_map = bpf_map_update_elem(&file_map, &init_key, &value, BPF_ANY);
        
        if (!ret_map)
        {
            bpf_trace_printk(number_packets, sizeof(number_packets), value);
        }
            
        else
            bpf_trace_printk(map_error, sizeof(map_error));
    // }
    // else {
      // return XDP_DROP;
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";