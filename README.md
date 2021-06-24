# eBPF studies
<p align="center">Testing, learning and coding ebpf</p>

Content
=================
<!--ts-->
   * [About](#About)
   * [How to](#"how-to")
      * [Requiriments](#Requiriments)
      * [Compiling](#Compiling)
   * [Testing](#Testing)
   * [Tecnologias](#tecnologias)
<!--te-->

## About
This example shows how to use [eBPF](https://docs.cilium.io/en/v1.9/bpf/) to block a TCP request based on the process name and TCP port.

## How to
To use the code, just copy it to the kernel source tree under linux/samples/bpf/.

## Requiriments
You should have an up-to-date local copy of the Linux Kernel tree:
`git clone https://github.com/torvalds/linux.git`

Also make sure you have bpftools and cgroups in your system:
To run these scripts you will need:

 - Kernel headers (ideally from a 5+ kernel):

        $ sudo apt-get install linux-headers-generic
  
Or it's equivalent to other Linux Distros      

 - Installing clang and other dependencies:

        $ sudo apt install -y clang llvm golang make

 

## Compiling
You may use the Makefile to compile the source code.
Also, it's possible to compile the code usgin clang, as follow:

`clang -O2 -Wall -target bpf -c basic_ebpf_cgroup.c -o basic_ebpf_cgroup.o`
  
## Testing

After compiling, load the BPF object using:
  
  `make load`

This will load the binary and attach it to a [cgroup](https://www.redhat.com/sysadmin/cgroups-part-one) (considering that CGROUPS are enabled)

To unload the binary just:
  
  `make unload`

The current code is "hard-coded". It means that, for now, it's only allowing egress communicaton to TCP/80 from TELNET. Ergo:
  `telnet DESTINATION 80`

If the destination it's a name, it must be resolved first and will be blocked (Default DNS uses UDP/53). To avoid that, [change](https://github.com/pedrofausto/ebpf_studies/blob/41a077b0e0b838c6360a3d6ea9f3596f3af97400/basic_ebpf_cgroup.c#L69) the code to allow UDP packages.

