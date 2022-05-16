//
// Created by root on 2021/11/12.
//
#include "arp_table.h"
#include "fib_netlink.h"
#include "radix_fib.h"

radix_tree_t *init_userspace_radix() {
    get_arp_table(AF_INET6);
    radix_tree_t *t = New_Radix();
    /* code */
    get_route_table(AF_INET6, t);
    fib6_print(t);
    return t;
}
