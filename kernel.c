//
// Created by root on 9/14/21.
//



#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>

struct bpf_map_def SEC("maps") xsks_map = {
        .type = BPF_MAP_TYPE_XSKMAP,
        .key_size = sizeof(int),
        .value_size = sizeof(int),
        .max_entries = 64,  /* Assume netdev has no more than 64 queues */
};

//static __always_inline void *find_srh(struct ipv6hdr *ipv6, void *data_end) {
//    if (ipv6 + 1 > data_end) {
//        return NULL;
//    }
//    if (ipv6->nexthdr == IPPROTO_ROUTING)
//        return (struct ipv6_opt_hdr *) (struct ipv6_opt_hdr *) ipv6 + 1;
//    if (ipv6->nexthdr == IPPROTO_NONE)
//        return NULL;
//
//    struct ipv6_opt_hdr *p = (struct ipv6_opt_hdr *) ipv6 + 1;
//
//    while (p + 1 < data_end && p->nexthdr != IPPROTO_ROUTING) {
//
//        if (p->nexthdr == IPPROTO_NONE) {
//            return NULL;
//        } else {
//            if (p + 1 > data_end) {
//                return NULL;
//            }
//            p = (struct ipv6_opt_hdr *) ((void *) p + 1 + p->hdrlen);
//
//        }
//    }
//    return (struct ipv6_opt_hdr *) ((void *) p + 1 + p->hdrlen);
//    return NULL;
//}


SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx) {

    int index = ctx->rx_queue_index;
    void *pkt = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct ethhdr *eth = pkt;
//    struct ipv6hdr *ipv6;
//    struct ipv6_rt_hdr *rt_hdr;
//    struct ipv6_sr_hdr *srh;
    int hdrsize = sizeof(*eth);

    if (pkt + hdrsize > data_end)
        return XDP_PASS;
    if (eth->h_proto == htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    if (eth->h_proto == htons(ETH_P_IPV6)) {
//        ipv6 = (struct ipv6hdr *) (eth + 1);
//        rt_hdr = (struct ipv6_rt_hdr *) find_srh(ipv6, data_end);
//        if (!rt_hdr) {
//            bpf_printk("is ipv6");
//            return XDP_PASS;
//        } else {
//            srh = (struct ipv6_sr_hdr *) rt_hdr;
        /* A set entry here means that the correspnding queue_id
         * has an active AF_XDP socket bound to it. */
        if (bpf_map_lookup_elem(&xsks_map, &index))
            return bpf_redirect_map(&xsks_map, index, 0);

        return XDP_PASS;
//        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
