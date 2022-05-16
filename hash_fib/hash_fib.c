//
// Created by zbs on 9/23/21.
//

#include <assert.h>
#include <alloca.h>
#include <linux/types.h>

#include "hash_fib.h"
#include "fib_netlink.h"
#include "arp_table.h"

/**
 * fib_init - initialize a new FIB
 * @f: the FIB to be initialized (the structure itself being allocated by the caller)
 * @p: pool to allocate the nodes in
 * @node_size: node size to be used (each node consists of a standard header &fib_node
 * followed by user data)
 * @hash_order: initial hash order (a binary logarithm of hash table size), 0 to use default order
 * (recommended)
 * @init: pointer a function to be called to initialize a newly created node
 *
 * This function initializes a newly allocated FIB and prepares it for use.
 */
int fib_init(struct hash_fib *f, uint addr_type, uint node_size, uint node_offset, uint hash_order) {
//    uint addr_length = net_addr_length[addr_type];
    if (!hash_order)
        hash_order = HASH_DEF_ORDER;
    f->addr_type = addr_type;
    f->node_size = node_size;
    f->node_offset = node_offset;
    f->hash_order = hash_order;
    fib_ht_alloc(f);
    bzero(f->hash_table, f->hash_size * sizeof(struct fib_node *));
    f->entries = 0;
    f->entries_min = 0;
}

/**
 * fib_find - search for FIB node by prefix
 * @f: FIB to search in
 * @n: network address
 *
 * Search for a FIB node corresponding to the given prefix, return
 * a pointer to it or %NULL if no such node exists.
 */
void *fib_find(struct hash_fib *f, const net_addr *a) {
    assert(f->addr_type == a->type);

    switch (f->addr_type) {
        case NET_IP4: {
            struct fib_node *e = f->hash_table[(net_hash_ip4((const net_addr_ip4 *) a) >> f->hash_shift)];
            while (e && !net_equal_ip4((const net_addr_ip4 *) &e->addr, (const net_addr_ip4 *) a)) {
                e = e->next;
            }
            return fib_node_to_user(f, e);
        }
        case NET_IP6: {
            struct fib_node *e = f->hash_table[(net_hash_ip6((const net_addr_ip6 *) a) >> f->hash_shift)];
            while (e && !net_equal_ip6((const net_addr_ip6 *) &e->addr, (const net_addr_ip6 *) a))
                e = e->next;
            return fib_node_to_user(f, e);
        }
        default:
            printf("%s\n", "invalid type");
    }
}

static void fib_insert(struct hash_fib *f, const net_addr *a, struct fib_node *e) {
    assert(f->addr_type == a->type);

    switch (f->addr_type) {
        case NET_IP4: {
            uint32_t h = net_hash_ip4((const net_addr_ip4 *) a);
            struct fib_node **ee = f->hash_table + (h >> f->hash_shift);
            struct fib_node *g;
            while ((g = *ee) && (net_hash_ip4((const net_addr_ip4 *) &g->addr) < h)) {
                ee = &g->next;
            }
            net_copy_ip4((net_addr_ip4 *) &e->addr, (const net_addr_ip4 *) a);

            e->next = *ee;
            *ee = e;
            return;
        }
        case NET_IP6:
            ( {
                uint32_t h = net_hash_ip6((const net_addr_ip6 *) a);
                struct fib_node **ee = f->hash_table + (h >> f->hash_shift);
                struct fib_node *g;
                while ((g = *ee) && (net_hash_ip6((const net_addr_ip6 *) &g->addr) < h)) ee = &g->next;
                net_copy_ip6((net_addr_ip6 *) &e->addr, (const net_addr_ip6 *) a);
                e->next = *ee;
                *ee = e;
            });
            return;

        default:
            printf("invalid type");
    }
}

/**
 * fib_find_or_insert - find or create a FIB node
 * @f: FIB to work with
 * @n: network address
 *
 * Search for a FIB node corresponding to the given prefix and
 * return a pointer to it. If no such node exists, create it.
 */
void *fib_find_or_insert(struct hash_fib *f, const net_addr *a) {
    void *b = fib_find(f, a);
    if (b)
        return b;
    b = malloc(f->node_size);

    struct fib_node *e = fib_user_to_node(f, b);
    e->readers = NULL;
    fib_insert(f, a, e);

    memset(b, 0, f->node_offset);

    if (f->entries++ > f->entries_max)
        fib_rehash(f, HASH_HI_STEP);

    return b;
}

static inline void *fib_route_ip4(struct hash_fib *f, net_addr_ip4 *n) {
    void *r;

    while (!(r = fib_find(f, (net_addr *) n)) && (n->pxlen > 0)) {
        n->pxlen--;
        ip4_clrbit(&n->prefix, n->pxlen);
    }

    return r;
}

static inline void *fib_route_ip6(struct hash_fib *f, net_addr_ip6 *n) {
    void *r;

    while (!(r = fib_find(f, (net_addr *) n)) && (n->pxlen > 0)) {
        n->pxlen--;
        ip6_clrbit(&n->prefix, n->pxlen);
    }

    return r;
}

void *fib_route(struct hash_fib *f, const net_addr *n) {
    assert(f->addr_type == n->type);

    net_addr *n0 = alloca(n->length);
    net_copy(n0, n);

    switch (n->type) {
        case NET_IP4:
            return fib_route_ip4(f, (net_addr_ip4 *) n0);

        case NET_IP6:
            return fib_route_ip6(f, (net_addr_ip6 *) n0);

        default:
            return NULL;
    }
}


void fib_print(struct hash_fib *f) {
    // FIB_WALK(&t->hash_fib, net, n)
    do {
        struct fib_node *fn_, **ff_ = f->hash_table;
        uint count_ = f->hash_size;
        struct hash_sid6_info *n;
        while (count_--)
            for (fn_ = *ff_++; n = fib_node_to_user(f, fn_); fn_ = fn_->next) {
                struct net_addr_ip4 *a = (struct net_addr_ip4 *) &n->n.addr;
                printf("%s/%d\n", inet_ntoa(a->prefix), a->pxlen);
            }
    } while (0);
}

//struct hash_fib f;
//int main(void) {
//    struct hash_sid6_info *n;
//    fib_init(&f, 1, sizeof(struct hash_sid6_info), 0, 4);
//
//    struct net_addr_ip4 a = {1, 16, sizeof(struct net_addr_ip4), (((u_int32_t) (0x01020304)))};
//    n = fib_find_or_insert(&f, &a);
//    n->behavior = 2;
//    struct net_addr_ip4 b = {1, 15, sizeof(struct net_addr_ip4), (((u_int32_t) (0x02020304)))};
//    n = fib_find_or_insert(&f, &b);
//
//    struct hash_sid6_info *s = (struct hash_sid6_info *) fib_route(&f, &a);
//    printf("%d\n", s->behavior);
//    s = (struct hash_sid6_info *) fib_route(&f, &b);
//    printf("%d\n", s->behavior);
//    fib_print(&f);
//    return 0;
//}

//int main(void) {
//    struct hash_sid6_info *n;
//    fib_init(&f, 2, sizeof(struct hash_sid6_info), 0, 4);
//    struct in6_addr prefix;
//    inet_pton(AF_INET6, "fe80::", &prefix);
//    struct net_addr_ip6 a = {2, 64, sizeof(struct net_addr_ip6), prefix};
//    n = fib_find_or_insert(&f, &a);
//    n->behavior = 2;
//    struct net_addr_ip6 b = {2, 16, sizeof(struct net_addr_ip6), prefix};
//    n = fib_find_or_insert(&f, &b);
//
//    struct hash_sid6_info *s = (struct hash_sid6_info *) fib_route(&f, &a);
//    printf("%d\n", s->behavior);
//    s = (struct hash_sid6_info *) fib_route(&f, &b);
//    printf("%d\n", s->behavior);
////    fib_print(&f);
//    return 0;
//}
//struct hash_fib ipv4_fib;
//struct hash_fib ipv6_fib;

int init_userspace_fib(struct hash_fib *ipv6_fib) {
    get_arp_table(AF_INET6);
    fib_init(ipv6_fib, NET_IP6, sizeof(struct hash_sid6_info), 0, 8);
    /* code */
    get_route_table(AF_INET6, ipv6_fib);
    fib6_print(ipv6_fib);
    return 0;
}


