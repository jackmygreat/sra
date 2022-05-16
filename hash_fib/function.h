//
// Created by root on 9/25/21.
//

#ifndef XDP_SRV6_FUNCTION_H
#define XDP_SRV6_FUNCTION_H

#include <linux/seg6_local.h>
#include "hash_fib.h"

static __always_inline void *find_srh(struct ipv6hdr *ipv6) {
    if (ipv6->nexthdr == IPPROTO_ROUTING)
        return (void *) ipv6 + sizeof(struct ipv6hdr);
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
    return NULL;
}

int end(void *pkt, struct ipv6hdr *iph, struct ipv6_sr_hdr *srh, struct hash_sid6_info *info);

int end_x(void *pkt, struct ipv6hdr *iph, struct ipv6_sr_hdr *srh, struct hash_sid6_info *info);

int end_dx2(void *pkt, uint32_t *pkt_len, struct ipv6hdr *iph, struct ipv6_sr_hdr *srh, struct hash_sid6_info *info);

int end_dx6(void *pkt, uint32_t *pkt_len, struct ipv6hdr *iph, struct ipv6_sr_hdr *srh, struct hash_sid6_info *info);

int encap(void *pkt, uint32_t *pkt_len, struct ipv6hdr *iph, struct hash_sid6_info *info);

int encap_inline(void *pkt, uint32_t *pkt_len, struct ipv6hdr *iph, struct hash_sid6_info *info);


#endif //XDP_SRV6_FUNCTION_H
