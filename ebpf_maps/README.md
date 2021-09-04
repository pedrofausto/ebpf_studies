# eBPF studies
<p align="center">Testing, learning and coding ebpf</p>

Content
=================
<!--ts-->
   * [Requiriments](#Requiriments)
   * [Compiling](#Compiling)
   * [Testing](#Testing)
   * [References](#References)
<!--te-->


## Requirements
See the main [README.md](../README.md) file.

Also, you may need to generate a "vmlinux.h" (see Andrii Nakryiko's post<sup>[1](https://nakryiko.com/posts/bpf-portability-and-co-re/)</sup>)

A lot of good develeopers provide examples based on libbpf and libbpf-bootstrap. I recommend see the Rafael Tinoco's example<sup>[2](https://github.com/rafaeldtinoco/portablebpf)</sup>)

## Compiling
### with libbpf-bootstrap 
*The following example is based on the code within the ebpf_maps folder*

For the code that use libbpf-bootstrap, just compile passing as argument the code do you want to compile:
`make example`
or
`make minimal`

The `Makefile` will create a ELF binary that have all that is needed. In this case, the userspace (`example.c`) code will load the kernelspace code (`example.ebpf.c`)

## Testing
To test, just run the generated binary:

    sudo ./example

## References
1. [BPF CO-RE (Compile Once – Run Everywhere)](https://nakryiko.com/posts/bpf-portability-and-co-re/)

2. [Portable eBPF](https://github.com/rafaeldtinoco/portablebpf)