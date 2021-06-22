// #define KBUILD_MODNAME "tc"

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

 #define TASK_COMM_LEN	16

static inline int check_process(void)
{
	const char name[] = "telnet";
	char task_name[TASK_COMM_LEN] = { 0 };

	bpf_get_current_comm(&task_name, sizeof(task_name));

	for (int i = 0; i < sizeof(name); ++i) {
		if (task_name[i] != name[i])
			return 0;
	}

	return 1;
}

static inline int check_port_match(struct bpf_sock_addr *ctx)
{

    if (ctx->user_port == htons(80)) {
        return 1;
    }
    else {
       return 0;
    }
}
__section("cgroup/connect4")
int drop_packet(struct bpf_sock_addr *ctx)
{
    if (check_process())
    {
         return check_port_match(ctx);
    }
    else
        return 0;
}

char __license[] __section("license") = "GPL";

/* Loading the eBPF program into kernel space
sudo tc qdisc add dev ens33 clsact
sudo tc filter add dev ens33 egress bpf direct-action obj basic_ebpf.o sec classifier
tc filter show dev ens33 egress

*** Unloading
sudo tc filter del dev ens33 egress
*/

/*
sudo bpftool prog load basic_ebpf.o /sys/fs/bpf/basic_ebpf
sudo bpftool prog show pinned /sys/fs/bpf/basic_ebpf
sudo bpftool cgroup attach /sys/fs/cgroup/ connect4 pinned /sys/fs/bpf/basic_ebpf
*/
