// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include "vmlinux.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} simple_count SEC(".maps");

int my_pid = 0;
int init = 0;

SEC("tp/syscalls/sys_enter_write")
int handle_syscall(void *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid();
	__u32 *map_value = 0;
	__u32 value = 0;
		
	if (pid != my_pid)
		return 0;

	bpf_printk("BPF triggered. My PID is %d.\n", pid);

	if(init == 0)
	{
		bpf_map_update_elem(&simple_count, &pid, &init, BPF_ANY);
		init = -1;
	}
	else
	{
		map_value = bpf_map_lookup_elem(&simple_count, &pid);
		if (!map_value)
			return 0;
		value = *map_value;
		value++;
		bpf_printk("Value for PID %d is %d.\n", pid, value);
		bpf_map_update_elem(&simple_count, &pid, &value, BPF_ANY);
	}

	return 0;
}
