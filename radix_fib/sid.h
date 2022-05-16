//
// Created by root on 2021/11/12.
//

#ifndef XSK_SRV6_SID_H
#define XSK_SRV6_SID_H

#include <stdbool.h>
#include <stddef.h>

typedef struct net_addr_ip6 {
    uint8_t type;
    uint8_t pxlen;
    uint16_t length;
    struct in6_addr prefix;
} net_addr_ip6;

struct srh_node {
    uint32_t length;
    struct ipv6_sr_hdr srh;
};

/**
 * struct hash_sid6_info - localsid table entry
 * @sid: SRv6 sid
 * @behavior: SRv6 behavior
 * @nh_ip: IPv4 address of next hop
 * @nh_ip6: IPv6 address of next hop
 * @nh_mac: MAC address of next hop
 * @mc: Flag - indicates that nh_mac is known (no need for ARP or NDISC)
 * @oif: target interface
 * @iif: source interface
 * @good_pkts: counter for good traffic in packets
 * @good_bytes: counter for good traffic in bytes
 * @bad_pkts: counter for bad traffic in packets
 * @bad_bytes: counter for bad traffic in bytes
 * @func: pointer to an SRv6 function
 * @hnode: hlist_node variable
 */
struct radix_sid6_info {
    uint encap_type;
    __u8 behavior;
    bool mc;
    char *oif;
    uint oif_index;
    char *iif;
    uint64_t good_pkts;
    uint64_t good_bytes;
    uint64_t bad_pkts;
    uint64_t bad_bytes;
    char src_mac[6];
    char dst_mac[6];
    struct net_addr_ip6 nh6;
    struct srh_node *srhNode;
};

#endif //XSK_SRV6_SID_H
