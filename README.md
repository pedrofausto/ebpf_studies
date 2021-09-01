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
<!--te-->

## About
The examples here shows how to use [eBPF](https://docs.cilium.io/en/v1.9/bpf/) to variety of uses like: block a TCP request based on the process name and TCP port; audit process, files and other stuff; demonstrate the use of BPF maps and so forth.

Some of the code is based on the linux eBPF examples provided in the source tree (linux/samples/bpf/).
Some can be used within the [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap/) tree.

## How to
The details for each source are described under its correspondent subfolder.
Generally speaking, to use the code, just copy it to your local repo, depending on case. It will be faster and easier.

## Requirements
You should have an up-to-date local copy of the Linux Kernel tree:
`git clone https://github.com/torvalds/linux.git`

An up-to-date local copy of the libbpf-bootstrap tree:
`git clone https://github.com/libbpf/libbpf-bootstrap.git`

Also make sure you have bpftools and cgroups in your system:
To run these scripts you will need:

 - Kernel headers (ideally from a 5.7+ kernel):

        $ sudo apt-get install linux-headers-generic
  
Or it's equivalent to other Linux Distros      

 - Installing clang and other dependencies:

        $ sudo apt install -y clang llvm golang make

## Compiling
### without libbpf-bootstrap 
*The following example is based on the code within the cgroups folder*

You may use the Makefile to compile the source code as simples as:
`make`

Also, it's possible to compile the code using clang, as follow:

`clang -O2 -Wall -target bpf -c basic_ebpf_cgroup.c -o basic_ebpf_cgroup.o`

In the above example, the ELF object file will be named "basic_ebpf_cgroup.o", created from the eBPF program "basic_ebpf_cgroup.c".
The "target" flag states that clang must create an object with eBPF bytecodes in mind.

### with libbpf-bootstrap 
*The following example is based on the code within the ebpf_maps folder*
For the code that use libbpf-bootstrap, just compile passing as argument the code do you want to compile:
`make example`
or
`make minimal`
  
## Testing
### without libbpf-bootstrap
After compiling, load the BPF object using:
  
  `make load`

This will load the binary and attach it to a [cgroup](https://www.redhat.com/sysadmin/cgroups-part-one) (considering that CGROUPS are enabled)

To unload the binary just:
  
  `make unload`

Some implementations are "hard-coded". It means that some eBPF programs will have a "fixed" logic. For exemple: the above example from "Compiling" section, is only allowing egress communicaton to TCP/80 from TELNET. Ergo:
  `telnet DESTINATION 80`

If the destination it's a name, it must be resolved first and will be blocked (Default DNS uses UDP/53). To avoid that, [change](https://github.com/pedrofausto/ebpf_studies/blob/41a077b0e0b838c6360a3d6ea9f3596f3af97400/basic_ebpf_cgroup.c#L69) the code to allow UDP packages.

### with libbpf-bootstrap
In this scenario, libbpf-bootstrap uses the userspace code to load the ebpf bytecode. The detailed process can be read [here](https://nakryiko.com/posts/libbpf-bootstrap/)

Futher examples will be updated and expanded as soon as possible.
