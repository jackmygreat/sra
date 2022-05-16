//
// Created by root on 2021/10/10.
//


#include <linux/socket.h>
#include <linux/netlink.h>
//#include <bits/types/struct_iovec.h>
#include <linux/neighbour.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "hash_fib.h"
#include <glib.h>
#include "arp_table.h"

char buf[8192];
static GHashTable *arp_hashtable;

const char *ll_addr_n2a(const unsigned char *addr, int alen, char *buf, int blen) {
    int i;
    int l;
    snprintf(buf, blen, "%02x", addr[0]);
    for (i = 1, l = 2; i < alen && l < blen; i++, l += 3)
        snprintf(buf + l, blen - l, ":%02x", addr[i]);
    return buf;
}

static int recv_msg(struct sockaddr_nl sock_addr, int sock) {
    struct nlmsghdr *nh;
    int len, nll = 0;
    char *buf_ptr;

    buf_ptr = buf;
    while (1) {
        len = recv(sock, buf_ptr, sizeof(buf) - nll, 0);
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

static void displayhash(gpointer key, gpointer value, gpointer user_data) {
    char mac[24];
    printf("user_data:%s\n", user_data);
    ll_addr_n2a(value, 6, mac, 24);
    printf("key:%s  value:%s \n", key, mac);
}

/* Function to parse the arp entry returned by netlink
 * Updates the arp entry related map entries
 */
static void read_arp(struct nlmsghdr *nh, int nll) {
    struct rtattr *rt_attr;
    char dsts[64], mac[24];
    struct ndmsg *rt_msg;
    int rtl, ndm_family;
    char buff[32] = {0};

    arp_hashtable = g_hash_table_new(g_str_hash, g_int_equal);


    if (nh->nlmsg_type == RTM_GETNEIGH)
        printf("READING arp entry\n");
    printf("Address\tHwAddress\n");
    for (; NLMSG_OK(nh, nll); nh = NLMSG_NEXT(nh, nll)) {
        rt_msg = (struct ndmsg *) NLMSG_DATA(nh);
        rt_attr = (struct rtattr *) RTM_RTA(rt_msg);
        ndm_family = rt_msg->ndm_family;
        rtl = RTM_PAYLOAD(nh);

        if (rt_msg->ndm_state == NUD_NOARP) {
            continue;
        }
//        rt_msg->ndm_flags=
        struct arp_node *node = malloc(sizeof(struct arp_node));
        memset(node, 0, sizeof(struct arp_node));
        for (; RTA_OK(rt_attr, rtl); rt_attr = RTA_NEXT(rt_attr, rtl)) {

            switch (rt_attr->rta_type) {
                case NDA_DST:
                    inet_ntop(ndm_family, RTA_DATA(rt_attr), dsts, 64);
//                    struct net_addr_ip6 a = {2, 128, sizeof(struct net_addr_ip6),
//                                             *(struct in6_addr *) RTA_DATA(rt_attr)};
//                    sprintf(dsts, "%u", *((__be32 *) RTA_DATA(rt_attr)));

                    memcpy(node->ip6, dsts, 64);

                    break;
                case NDA_LLADDR:
                    ll_addr_n2a(RTA_DATA(rt_attr), RTA_PAYLOAD(rt_attr), mac, 24);
//                    sprintf(mac, "%lld", *((__be64 *) RTA_DATA(rt_attr)));
                    memcpy(node->mac, RTA_DATA(rt_attr), RTA_PAYLOAD(rt_attr));
                    break;
                case NDA_IFINDEX:

                default:
                    break;
            }
        }
        g_hash_table_insert(arp_hashtable, &node->ip6, &node->mac);
        printf("%s\t\t%s\n", dsts, mac);
        memset(dsts, 0, sizeof(dsts));
        memset(mac, 0, sizeof(mac));
    }
//    g_hash_table_foreach(arp_hashtable, displayhash, buff);
}

/* Function to read the existing arp table  when the process is launched*/
int get_arp_table(int rtm_family) {
    struct sockaddr_nl sa;
    struct nlmsghdr *nh;
    int sock, seq = 0;
    struct msghdr msg;
    struct iovec iov;
    int ret = 0;
    int nll;

    struct {
        struct nlmsghdr nl;
        struct ndmsg rt;
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
    req.nl.nlmsg_type = RTM_GETNEIGH;
    req.rt.ndm_state = NUD_REACHABLE;
    req.rt.ndm_family = rtm_family;
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
    nll = recv_msg(sa, sock);
    if (nll < 0) {
        printf("recv from netlink: %s\n", strerror(nll));
        ret = -1;
        goto cleanup;
    }
    nh = (struct nlmsghdr *) buf;
    read_arp(nh, nll);
    cleanup:
    close(sock);
    return ret;
}

void *find_arp_table(char *ip) {
    return g_hash_table_lookup(arp_hashtable, ip);
}

//int main() {
//    get_arp_table(AF_UNSPEC);
//}
