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

    git clone https://github.com/torvalds/linux.git

An up-to-date local copy of the libbpf-bootstrap tree and the libbpf itself:

    git clone https://github.com/libbpf/libbpf-bootstrap.git
    git submodule update --init --recursive

Also make sure you have bpftools and cgroups in your system:
To run these scripts you will need:

 - Kernel headers (ideally from a 5.7+ kernel):

        sudo apt-get install linux-headers-generic
  
Or it's equivalent to other Linux Distros      

 - Installing clang and other dependencies:

        sudo apt install -y clang llvm golang make

## Compiling
Each subfolder have it's own compiling instructions
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
Each subfolder have it's own testing instructions