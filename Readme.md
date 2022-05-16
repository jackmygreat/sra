# SRA: SRv6 implementation based on AF_XDP

We have developed a SRv6 processing framework based on AF_XDP, which 
is a high-performance and flexible processing framework for SRv6 
behaviours in userspace. You can use this framework to implement 
custom SRv6 behaviors.

# Build
    clang -S \
    -target bpf \
    -D __BPF_TRACING__ \
    -Wall \
    -Wno-unused-value \
    -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types \
    -Werror \
    -O2 -emit-llvm -c -g -o kernel.ll kernel.c

    clang -target bpf -c af_xdp_kern.c  -o af_xdp_kern.o -O2 -llibbpf
    cd build
    cmake -DCMAKE_BUILD_TYPE=Release ..  
