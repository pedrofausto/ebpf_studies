#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "bpf_helpers.h"

#define __section(NAME) \
__attribute__((section(NAME), used))

#define TASK_COMM_LEN	16


static inline int getProgram(void)
{
	const char name[] = "telnet";
	char task_name[TASK_COMM_LEN] = { 0 };
	
    /*const struct task_struct *t; */
	/*const char read_error[] = "read_error:   t->comm - %d\n";
	const char read_suc[] = "read_success: t->comm - %d\n";
	int ret = 0;

    t = (struct task_struct *) bpf_get_current_task();
	ret = bpf_probe_read_kernel(task_name, TASK_COMM_LEN, t->comm);*/
	bpf_get_current_comm(task_name, sizeof(task_name));
    
	/*if (ret < 0) {
		bpf_trace_printk(read_error, sizeof(read_error), ret);
		return 0;
	}

	bpf_trace_printk(read_suc, sizeof(read_suc), ret);
	bpf_trace_printk(name, sizeof(name));*/

    /* Test if the process name is the one expected */
	for (int i = 0; i < sizeof(name); ++i) {
		if (task_name[i] != name[i])
			return 1;
	}
	
    /* In case of success, return 0 */
	return 0;
}

/* Ingress hook - handle incoming packets */
__section("cgroup_skb/ingress")
int ingress(struct __sk_buff *skb) {
    
    return getProgram();
}

/* Egress hook - handle outgoing packets */
__section("cgroup_skb/egress")
int egress(struct __sk_buff *skb) {
    return getProgram();
    return false;
}



char __license[] __section("license") = "GPL";