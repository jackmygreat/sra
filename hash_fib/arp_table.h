//
// Created by root on 2021/10/11.
//

#ifndef XDP_SRV6_ARP_TABLE_H
#define XDP_SRV6_ARP_TABLE_H

#include <glib.h>


struct arp_node {
    char ip6[64];
    char mac[6];
};

get_arp_table(int rtm_family);

void *find_arp_table(char *ip);

#endif //XDP_SRV6_ARP_TABLE_H
