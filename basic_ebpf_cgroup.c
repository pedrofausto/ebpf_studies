#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/filter.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/sched.h>

/* Loading the eBPF program into kernel space
sudo bpftool prog load basic_ebpf.o /sys/fs/bpf/basic_ebpf
sudo bpftool prog show pinned /sys/fs/bpf/basic_ebpf
sudo bpftool cgroup attach /sys/fs/cgroup/ connect4 pinned /sys/fs/bpf/basic_ebpf


*** Unloading
sudo bpftool cgroup detach /sys/fs/cgroup/ connect4 pinned /sys/fs/bpf/basic_ebpf
sudo rm /sys/fs/bpf/basic_ebpf

*** Testing
telnet 172.217.29.4 443         // You shall NOT PASS!!
telnet 172.217.29.4 80          // You shall pass.
curl -v -k http://172.217.29.4  // You shall pass.
curl -v -k https://172.217.29.4  // You shall NOT PASS.

*/

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif
#define htons(x) ((__be16)___constant_swab16((x)))

 #define TASK_COMM_LEN	16

static inline int check_process(void)
{
	const char name[] = "telnet";
  const char error_msg[] = "Error get the current command";
  const char comm_msg[] = "Command name: %s";

	char comm_name[TASK_COMM_LEN] = { 0 };
  int ret = -1;

	ret = bpf_get_current_comm(comm_name, sizeof(comm_name));
  if (ret < 0)
  {
    bpf_trace_printk(error_msg, sizeof(error_msg));
  }
  bpf_trace_printk(comm_msg, sizeof(comm_msg), comm_name);

	for (int i = 0; i < sizeof(name); ++i) {
		if (comm_name[i] != name[i])
			return 0;
	}

	return 1;
}

static inline int check_port_match(struct bpf_sock_addr *ctx)
{
    const char initial_msg[] = "======New connection=====";
    const char port_number[] = "Port number: %d";
    const char proto_number[] = "Protocol: %d";
    bpf_trace_printk(initial_msg, sizeof(initial_msg));
    bpf_trace_printk(port_number, sizeof(port_number),htons(ctx->user_port));
    bpf_trace_printk(proto_number, sizeof(proto_number),ctx->protocol);

    if (ctx->user_port == htons(4040) && ctx->protocol == IPPROTO_TCP) {
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
