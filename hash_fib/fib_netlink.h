//
// Created by zbs on 9/15/21.
//
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
//#include<linux/if.h>
#include <linux/seg6_local.h>
#include <linux/seg6_iptunnel.h>
#include <sys/socket.h>
#include <net/if.h>
#include<errno.h>
#include <stdio.h>
#include <string.h>
#include<stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/ioctl.h>
#include "arp_table.h"

//extern GHashTable *arp_hashtable;

#ifndef __FIB_NETLINK_H
#define __FIB_NETLINK_H


enum lwtunnel_encap_types {
    LWTUNNEL_ENCAP_NONE,
    LWTUNNEL_ENCAP_MPLS,
    LWTUNNEL_ENCAP_IP,
    LWTUNNEL_ENCAP_ILA,
    LWTUNNEL_ENCAP_IP6,
    LWTUNNEL_ENCAP_SEG6,
    LWTUNNEL_ENCAP_BPF,
    LWTUNNEL_ENCAP_SEG6_LOCAL,
    __LWTUNNEL_ENCAP_MAX,
};


static const char *seg6_action_names[SEG6_LOCAL_ACTION_MAX + 1] = {
        [SEG6_LOCAL_ACTION_END]            = "End",
        [SEG6_LOCAL_ACTION_END_X]        = "End.X",
        [SEG6_LOCAL_ACTION_END_T]        = "End.T",
        [SEG6_LOCAL_ACTION_END_DX2]        = "End.DX2",
        [SEG6_LOCAL_ACTION_END_DX6]        = "End.DX6",
        [SEG6_LOCAL_ACTION_END_DX4]        = "End.DX4",
        [SEG6_LOCAL_ACTION_END_DT6]        = "End.DT6",
        [SEG6_LOCAL_ACTION_END_DT4]        = "End.DT4",
        [SEG6_LOCAL_ACTION_END_B6]        = "End.B6",
        [SEG6_LOCAL_ACTION_END_B6_ENCAP]    = "End.B6.Encaps",
        [SEG6_LOCAL_ACTION_END_BM]        = "End.BM",
        [SEG6_LOCAL_ACTION_END_S]        = "End.S",
        [SEG6_LOCAL_ACTION_END_AS]        = "End.AS",
        [SEG6_LOCAL_ACTION_END_AM]        = "End.AM",
        [SEG6_LOCAL_ACTION_END_BPF]        = "End.BPF",
};

static const char *format_action_type(int action) {
    if (action < 0 || action > SEG6_LOCAL_ACTION_MAX)
        return "<invalid>";

    return seg6_action_names[action] ?: "<unknown>";
}

int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
                       int len, unsigned short flags) {
    unsigned short type;

    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        type = rta->rta_type & ~flags;
        if ((type <= max) && (!tb[type]))
            tb[type] = rta;
        rta = RTA_NEXT(rta, len);
    }
    if (len)
        fprintf(stderr, "!!!Deficit %d, rta_len=%d\n",
                len, rta->rta_len);
    return 0;
}

static int recv_msg(struct sockaddr_nl sock_addr, int sock, char *buf, int buflen) {
    struct nlmsghdr *nh;
    int len, nll = 0;
    char *buf_ptr;

    buf_ptr = buf;
    while (1) {
        len = recv(sock, buf_ptr, buflen - nll, 0);
        if (len < 0)
            return len;

        nh = (struct nlmsghdr *) buf_ptr;

        if (nh->nlmsg_type == NLMSG_DONE)
            break;
        buf_ptr += len;
        nll += len;
        if ((sock_addr.nl_groups & RTMGRP_NEIGH) == RTMGRP_NEIGH)
            break;

        if ((sock_addr.nl_groups & RTMGRP_IPV4_ROUTE) == RTMGRP_IPV4_ROUTE)
            break;
    }
    return nll;
}

///* Get the mac address of the interface given interface name */
//static __be64 getmac(char *iface) {
//    struct ifreq ifr;
//    __be64 mac = 0;
//    int fd, i;
//
//    fd = socket(AF_INET, SOCK_DGRAM, 0);
//    ifr.ifr_addr.sa_family = AF_INET;
//    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
//    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
//        printf("ioctl failed leaving....\n");
//        return -1;
//    }
//    for (i = 0; i < 6; i++)
//        *((__u8 *) &mac + i) = (__u8) ifr.ifr_hwaddr.sa_data[i];
//    close(fd);
//    return mac;
//}

static void int_exit(int sig) {
    __u32 prog_id = 0;
    exit(0);
}


void parse_encap_seg6local(struct rtattr *tb[], struct rtattr *encap) {

#define NLA_F_NESTED        (1 << 15)

    struct rtattr *rta = RTA_DATA(encap);
    int len = RTA_PAYLOAD(encap);
    while (RTA_OK(rta, len)) {
        unsigned short type = rta->rta_type & ~NLA_F_NESTED;

        if ((!tb[type]))
            tb[type] = rta;

        rta = RTA_NEXT(rta, len);
    }
}

/* Function to parse the route entry returned by netlink
 * Updates the route entry related map entries
 */
static void read_route(struct nlmsghdr *nh, int nll, struct hash_fib *f) {
    char dsts[24], gws[24], ifs[16], dsts_len[24], metrics[24];
    struct bpf_lpm_trie_key *prefix_key;
    struct rtattr *rt_attr;
    struct rtmsg *rt_msg;
    int rtm_family;
    int rtl;
    int i;

//    printf("Destination\t\tGateway\t\tGenmask\t\tMetric\t\tIface\n");
    for (; NLMSG_OK(nh, nll); nh = NLMSG_NEXT(nh, nll)) {
        rt_msg = (struct rtmsg *) NLMSG_DATA(nh);
        rtm_family = rt_msg->rtm_family;
        if (rtm_family == AF_INET6)
            if (rt_msg->rtm_table != RT_TABLE_MAIN)
                continue;
        rt_attr = (struct rtattr *) RTM_RTA(rt_msg);
        rtl = RTM_PAYLOAD(nh);
        struct rtattr *tb[RTA_MAX + 1];
        memset(tb, 0, sizeof(struct rtattr *) * (RTA_MAX + 1));

        for (; RTA_OK(rt_attr, rtl); rt_attr = RTA_NEXT(rt_attr, rtl)) {
            tb[rt_attr->rta_type] = rt_attr;
        }
        struct hash_sid6_info *sid_node;
        if (tb[RTA_DST]) {
            struct net_addr_ip6 a = {2, rt_msg->rtm_dst_len, sizeof(struct net_addr_ip6),
                                     *(struct in6_addr *) RTA_DATA(tb[RTA_DST])};
            sid_node = fib_find_or_insert(f, &a);
            char ip[50];
            inet_ntop(AF_INET6, &a.prefix, ip, sizeof(ip));
            printf("%s/%d \n", ip, a.pxlen);

        }
        if (tb[RTA_OIF]) {
            sid_node->oif_index = *(__u32 *) RTA_DATA(tb[RTA_OIF]);
            size_t a = 16;
            void *oif_buf = malloc(a + 1);
            if_indextoname(sid_node->oif_index, oif_buf);
            sid_node->oif = oif_buf;
            int mac_sock = socket(AF_INET, SOCK_STREAM, 0);
            struct ifreq ifreq;
            strcpy(ifreq.ifr_name, oif_buf);
            ioctl(mac_sock, SIOCGIFHWADDR, &ifreq);
            memcpy(sid_node->src_mac, ifreq.ifr_hwaddr.sa_data, 6);
        }
        if (tb[RTA_GATEWAY]) {
            struct in6_addr *via = (struct in6_addr *) RTA_DATA(tb[RTA_GATEWAY]);
            char ip[64];
            inet_ntop(rtm_family, via, ip, 64);
            void *mac_value = find_arp_table(ip);
            memcpy(sid_node->dst_mac, mac_value, 6);

//            printf("%s", ip);
        }
        if (tb[RTA_ENCAP]) {
            int encap_type = *(__u16 *) RTA_DATA(tb[RTA_ENCAP_TYPE]);
            switch (encap_type) {
                case LWTUNNEL_ENCAP_SEG6: {
                    sid_node->encap_type = LWTUNNEL_ENCAP_SEG6;

                    struct rtattr *seg_tb[SEG6_IPTUNNEL_MAX + 1];
                    memset(seg_tb, 0, sizeof(struct rtattr *) * (SEG6_IPTUNNEL_MAX + 1));
                    parse_encap_seg6local(seg_tb, tb[RTA_ENCAP]);
                    if (!seg_tb[SEG6_IPTUNNEL_SRH])
                        return;

                    struct seg6_iptunnel_encap *tuninfo = (struct seg6_iptunnel_encap *) RTA_DATA(
                            seg_tb[SEG6_IPTUNNEL_SRH]);
                    sid_node->srhNode = malloc(4 + (tuninfo->srh[0].hdrlen + 1) * 8);
                    memset(sid_node->srhNode, 0, 4 + (tuninfo->srh[0].hdrlen + 1) * 8);
                    sid_node->srhNode->length = (tuninfo->srh[0].hdrlen + 1) * 8;
                    memcpy(&(sid_node->srhNode->srh), &tuninfo->srh, sid_node->srhNode->length);
                    sid_node->behavior = tuninfo->mode;

//                    char ip[50];
//                    inet_ntop(AF_INET6, &sid_node->srhNode->srh.segments[0], ip, sizeof(ip));
//                    printf("%s\n", ip);

                    switch (tuninfo->mode) {
                        case SEG6_IPTUN_MODE_INLINE: {

                        }

                            break;
                        case SEG6_IPTUN_MODE_ENCAP: {

                        }
                            sid_node->srhNode->srh.nexthdr = IPPROTO_IPV6;
                            break;
                        case SEG6_IPTUN_MODE_L2ENCAP:
                            break;
                    }
                }
                    break;
                case LWTUNNEL_ENCAP_SEG6_LOCAL: {
                    sid_node->encap_type = LWTUNNEL_ENCAP_SEG6_LOCAL;
                    struct rtattr *seg_local_tb[SEG6_LOCAL_MAX + 1];
                    memset(seg_local_tb, 0, sizeof(struct rtattr *) * (SEG6_LOCAL_MAX + 1));
                    parse_encap_seg6local(seg_local_tb, tb[RTA_ENCAP]);
                    sid_node->behavior = *(uint8_t *) RTA_DATA(seg_local_tb[SEG6_LOCAL_ACTION]);
                    if (seg_local_tb[SEG6_LOCAL_NH6]) {
                        struct in6_addr *nh6 = (struct in6_addr *) RTA_DATA(seg_local_tb[SEG6_LOCAL_NH6]);
                        struct net_addr_ip6 a = {2, 128, sizeof(struct net_addr_ip6),
                                                 *(struct in6_addr *) RTA_DATA(seg_local_tb[SEG6_LOCAL_NH6])};
                        sid_node->nh6 = a;
                        char ip[64];
                        inet_ntop(rtm_family, nh6, ip, 64);
                        void *mac_value = find_arp_table(ip);
                        memcpy(sid_node->dst_mac, mac_value, 6);
                    }

                    if (seg_local_tb[SEG6_LOCAL_OIF]) {
                        sid_node->oif_index = *(__u32 *) RTA_DATA(seg_local_tb[SEG6_LOCAL_OIF]);
                        size_t a = 16;
                        void *oif_buf = malloc(a + 1);
                        if_indextoname(sid_node->oif_index, oif_buf);
                        sid_node->oif = oif_buf;
                        int mac_sock = socket(AF_INET, SOCK_STREAM, 0);
                        struct ifreq ifreq;
                        strcpy(ifreq.ifr_name, oif_buf);
                        ioctl(mac_sock, SIOCGIFHWADDR, &ifreq);
                        memcpy(sid_node->src_mac, ifreq.ifr_hwaddr.sa_data, 6);
//                        memcpy()
                    }
                    break;
                }
            }
        }


    }
}

/* Function to read the existing route table  when the process is launched*/
static int get_route_table(int rtm_family, struct hash_fib *f) {
    struct sockaddr_nl sa;
    struct nlmsghdr *nh;
    int sock, seq = 0;
    struct msghdr msg;
    struct iovec iov;
    int ret = 0;
    int nll;
    char buf[8192];
    struct {
        struct nlmsghdr nl;
        struct rtmsg rt;
        char buf[8192];
    } req;

    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        printf("open netlink socket: %s\n", strerror(errno));
        return -1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(sock, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        printf("bind to netlink: %s\n", strerror(errno));
        ret = -1;
        goto cleanup;
    }
    memset(&req, 0, sizeof(req));
    req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nl.nlmsg_type = RTM_GETROUTE;

    req.rt.rtm_family = rtm_family;
    req.rt.rtm_table = RT_TABLE_MAIN;
    req.nl.nlmsg_pid = 0;
    req.nl.nlmsg_seq = ++seq;
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = (void *) &req.nl;
    iov.iov_len = req.nl.nlmsg_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    ret = sendmsg(sock, &msg, 0);
    if (ret < 0) {
        printf("send to netlink: %s\n", strerror(errno));
        ret = -1;
        goto cleanup;
    }
    memset(buf, 0, sizeof(buf));
    nll = recv_msg(sa, sock, buf, sizeof(buf));
    if (nll < 0) {
        printf("recv from netlink: %s\n", strerror(nll));
        ret = -1;
        goto cleanup;
    }
    nh = (struct nlmsghdr *) buf;
    read_route(nh, nll, f);
    cleanup:
    close(sock);
    return ret;
}

void fib6_print(struct hash_fib *f) {
    // FIB_WALK(&t->hash_fib, net, n)

    struct fib_node *fn_, **ff_ = f->hash_table;
    uint count_ = f->hash_size;
    struct hash_sid6_info *n;
    while (count_--)
        for (fn_ = *ff_++; n = fib_node_to_user(f, fn_); fn_ = fn_->next) {
            struct net_addr_ip6 *a = (struct net_addr_ip6 *) &n->n.addr;
            char ip[50];
            inet_ntop(AF_INET6, &a->prefix, ip, sizeof(ip));
            printf("%s/%d, %d, %d \n", ip, a->pxlen, n->behavior, n->oif_index);

//            if (n->encap_type == LWTUNNEL_ENCAP_SEG6) {
//                inet_ntop(AF_INET6, &n->srhNode->srh.segments[0], ip, sizeof(ip));
//                printf("%s\n", ip);
//                printf("he");
//            }
        }
}

#endif