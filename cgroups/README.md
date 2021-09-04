# eBPF studies
<p align="center">Testing, learning and coding ebpf</p>

Content
=================
<!--ts-->
   * [Requiriments](#Requiriments)
   * [Compiling](#Compiling)
   * [Testing](#Testing)
<!--te-->

## Requirements
See the main [README.md](../README.md) file.

At some you may need the Kernel configuration in your linux tree. Otherwise the compile will show this message:

    ERROR: Kernel configuration is invalid.
         include/generated/autoconf.h or include/config/auto.conf are missing.
         Run 'make oldconfig && make prepare' on kernel src to fix it.

To easy you life and automate the boring stuff, just go to the kernel main directory and do (you need flex & bison):

    yes | make oldconfig && make prepare 
Get a seat. It can take a while.

## Compiling
*The following example is based on the code within the cgroups folder*

Copy the `Makefile` and `basic_ebpf_cgroup.c` to the folder `linux/samples/bpf/`. Make sure to backup the old `Makefile `from the linux samples dir if needed.

You may use the Makefile to compile the source code as simples as running  `make`.

Also, it's possible to compile the code using clang, as follow:

`clang -O2 -Wall -target bpf -c basic_ebpf_cgroup.c -o basic_ebpf_cgroup.o`

In the above example, the ELF object file will be named "basic_ebpf_cgroup.o", created from the eBPF program "basic_ebpf_cgroup.c".
The "target" flag states that clang must create an object with eBPF bytecodes in mind.

If you want to see the `sections` within the ELF object, just type:

    readelf -S basic_ebpf_cgroup.o

## Testing
### without libbpf-bootstrap
After compiling, load the BPF object using:
  
  `make load`

This will load the binary and attach it to a [cgroup](https://www.redhat.com/sysadmin/cgroups-part-one) (considering that CGROUPS are enabled)

To unload the binary just:
  
  `make unload`

This implementation's logic is "hard-coded". It means that will have a "fixed" logic. For exemple: the above example is only allowing egress communicaton to TCP/80 from TELNET. Ergo:

  `telnet DESTINATION 80`

If the destination it's a name, it must be resolved first and will be blocked (Default DNS uses UDP/53). To avoid that, [change](https://github.com/pedrofausto/ebpf_studies/blob/41a077b0e0b838c6360a3d6ea9f3596f3af97400/basic_ebpf_cgroup.c#L69) the code to also allow UDP packages.

Futher examples will be updated and expanded as soon as possible.
