// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include "vmlinux.h"

/* This example is based on the libbpf-boostrap minimal and boostrap source codes available in
https://github.com/libbpf/libbpf-bootstrap/ by Andrii Nakryiko */

/* Every eBPF program must have an ELF .section called 'license' to define
which licensing is applied to the BPF. If you want to have access to some
kernel features, GPL must be provided. */ 
char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Maps are basically structs with 4 'attributes':
 - Type;
 - Max number of entries;
 - The key used to uniquely identify an item within the map;
 - The value of the element for that key.

Types are defined in bpf.h (hence the #include above).
Also, for each type, some 'helpers' are defined and available to use within the scope of the eBPF program. These helpers are
defined in 'bpf_helpers.h' */

/* So, we create a map of type HASH with only one entry*/
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} simple_count SEC(".maps");

/* Then we create global variables that can be used by wither user or kernel space.
In reality, global variables are generic maps.
In this example I create one variable to store the pid (process ID) of the userspace program
and a generic flag to know if my map is already initialized.
If don't, update it with some information. */


int my_pid = 0;
int init = 0;

/* 
libbpf defines a convention to where eBPF programs should be hooked, as we can see in:
https://github.com/libbpf/libbpf/blob/master/src/libbpf.c#L6260-L6349
As such, we used the basic example from the minimal.bpf.c source code provided and re-use the hook point
to any write syscall. 
*/
SEC("tp/syscalls/sys_enter_write")

/*
Then, for the current section the below function will be 'translated' to BPF bytecodes and to be 'hooked'
accordingly to the previous SEC definition.  
*/
int handle_syscall(void *ctx)
{
	/* Get the current pid (tgid) and initialize some auxiliary variables*/
	__u32 pid = bpf_get_current_pid_tgid();
	__u32 *map_value = 0;
	__u32 value = 0;

	/* To avoid that every write syscall from process other then ourserlves, verify if the process's PID that is trying to write
	is equal to the userspace process's pid */	
	if (pid != my_pid)
		return 0;

	bpf_printk("BPF triggered. My PID is %d.\n", pid);

	/* Testing small logic to 'initialize' our map. There's no need though.
	Then, we can update a map element by using the helper function 'bpf_map_update_elem', which expects
	the address of our 'simple_count' map, the address to our 'key' (in our case is the PID) and a additional flag.
	This flag is defined by the bpf.h as an 'enum' as follow:
	
	BPF_ANY		= 0, // create new element or update existing 
	BPF_NOEXIST	= 1, // create new element if it didn't exist 
	BPF_EXIST	= 2, // update existing element 
	BPF_F_LOCK	= 4, // spin_lock-ed map_lookup/map_update 
	*/
	if(init == 0)
	{
		init++;
		bpf_map_update_elem(&simple_count, &pid, &init, BPF_ANY);
		bpf_printk("Initial value for PID %d is %d.\n", pid, init);
		init = -1;
	}
	else
	{
		/*
		Then:
		1. Get the current pointer address to the value stored in the map for our PID
		2. Check if the pointer isn't NULL. If you do not check this, the verifier will complain about it and the bytecode won't run.
		3. Increment the current value.
		4. Store it's value back in the map using, again, the update element helper.
		*/
		map_value = bpf_map_lookup_elem(&simple_count, &pid);
		if (!map_value)
			return 0;
		value = *map_value;
		value++;
		bpf_map_update_elem(&simple_count, &pid, &value, BPF_ANY);
		bpf_printk("Value for PID %d is %d.\n", pid, value);
	}
	
	return 0;
}
