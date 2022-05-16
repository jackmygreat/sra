#ifndef XDP_SRV6_FIB_H
#define XDP_SRV6_FIB_H

#include <linux/net.h>
#include <linux/types.h>
#include <linux/seg6.h>
//#include <linux/ip.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <malloc.h>
#include <string.h>
#include <stdbool.h>


typedef struct net_addr {
    uint8_t type;
    uint8_t pxlen;
    uint8_t length;
    uint8_t data[20];
    uint64_t align[0];
} net_addr;

typedef struct net_addr_ip4 {
    uint8_t type;
    uint8_t pxlen;
    uint16_t length;
    struct in_addr prefix;
} net_addr_ip4;

typedef struct net_addr_ip6 {
    uint8_t type;
    uint8_t pxlen;
    uint16_t length;
    struct in6_addr prefix;
} net_addr_ip6;

struct fib_node {
    struct fib_node *next;        /* Next in hash chain */
    struct fib_iterator *readers;        /* List of readers of this node */
    net_addr addr;
};

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
struct hash_sid6_info {
    struct fib_node n;
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

struct fib_iterator {            /* See lib/slists.h for an explanation */
    struct fib_iterator *prev, *next;    /* Must be synced with struct fib_node! */
    uint8_t efef;                /* 0xff to distinguish between iterator and node */
    uint8_t pad[3];
    struct fib_node *node;        /* Or NULL if freshly merged */
    uint hash;
};

struct hash_fib {
    struct fib_node **hash_table;        /* Node hash table */
    uint hash_size;            /* Number of hash table entries (a power of two) */
    uint hash_order;            /* Binary logarithm of hash_size */
    uint hash_shift;            /* 32 - hash_order */
    uint addr_type;            /* Type of address data stored in hash_fib (NET_*) */
    uint node_size;            /* FIB node size, 0 for nonuniform */
    uint node_offset;            /* Offset of fib_node struct inside of user data */
    uint entries;                /* Number of entries */
    uint entries_min, entries_max;    /* Entry count limits (else start rehashing) */
};

#define NET_IP4        1
#define NET_IP6        2


#define HASH_DEF_ORDER 10
#define HASH_HI_MARK * 2
#define HASH_HI_STEP 1
#define HASH_HI_MAX 24
#define HASH_LO_MARK / 5
#define HASH_LO_STEP 2
#define HASH_LO_MIN 10

#define FIB_HASH(f, a, t) (net_hash_##t(CAST(t) a) >> f->hash_shift)

static void
fib_ht_alloc(struct hash_fib *f) {
    f->hash_size = 1 << f->hash_order;
    f->hash_shift = 32 - f->hash_order;
    if (f->hash_order > HASH_HI_MAX - HASH_HI_STEP)
        f->entries_max = ~0;
    else
        f->entries_max = f->hash_size HASH_HI_MARK;
    if (f->hash_order < HASH_LO_MIN + HASH_LO_STEP)
        f->entries_min = 0;
    else
        f->entries_min = f->hash_size HASH_LO_MARK;
    f->hash_table = malloc(f->hash_size * sizeof(struct fib_node *));
}

static inline int net_equal_ip4(const net_addr_ip4 *a, const net_addr_ip4 *b) {
    return !memcmp(a, b, sizeof(net_addr_ip4));
}

static inline int net_equal_ip6(const net_addr_ip6 *a, const net_addr_ip6 *b) {
    return !memcmp(a, b, sizeof(net_addr_ip6));
}

static inline void *fib_node_to_user(struct hash_fib *f, struct fib_node *e) {
    return e ? (void *) ((char *) e - f->node_offset) : NULL;
}

static inline struct fib_node *fib_user_to_node(struct hash_fib *f, void *e) {
    return e ? (void *) ((char *) e + f->node_offset) : NULL;
}

static inline uint32_t u32_hash(uint32_t v) { return v * 2902958171u; }

static inline uint32_t ip4_hash(struct in_addr a) { return u32_hash(a.s_addr); }

static inline uint32_t net_hash_ip4(const net_addr_ip4 *n) { return ip4_hash(n->prefix) ^ ((uint32_t) n->pxlen << 26); }

static inline uint32_t ip6_hash(struct in6_addr a) {
    /* Returns a 32-bit hash key, although low-order bits are not mixed */
    uint32_t x = ((a).s6_addr32[0]) ^ ((a).s6_addr32[1]) ^ ((a).s6_addr32[2]) ^ ((a).s6_addr32[3]);
    return x ^ (x << 16) ^ (x << 24);
}

static inline uint32_t net_hash_ip6(const net_addr_ip6 *n) {
    return ip6_hash(n->prefix) ^ ((uint32_t) n->pxlen << 26);
}

static inline void net_copy_ip4(net_addr_ip4 *dst, const net_addr_ip4 *src) {
    printf("%d\n", sizeof(net_addr_ip4));
    memcpy(dst, src, sizeof(net_addr_ip4));
    printf("%d\n", dst->pxlen);
}

static inline void net_copy_ip6(net_addr_ip6 *dst, const net_addr_ip6 *src) { memcpy(dst, src, sizeof(net_addr_ip6)); }

static inline void net_copy(net_addr *dst, const net_addr *src) { memcpy(dst, src, src->length); }

static inline uint32_t ip4_clrbit(struct in_addr *a, uint pos) { return (a->s_addr) &= ~(0x80000000 >> pos); }

static inline uint32_t ip6_clrbit(struct in6_addr *a, uint pos) {
    return a->s6_addr32[pos / 32] &= ~(0x80000000 >> (pos % 32));
}


static uint32_t net_hash(const net_addr *n) {
    switch (n->type) {
        case NET_IP4:
            return net_hash_ip4((const net_addr_ip4 *) n);
        case NET_IP6:
            return net_hash_ip6((const net_addr_ip6 *) n);
        default:
            printf("invalid type");
    }
}


static inline uint32_t fib_hash(struct hash_fib *f, const net_addr *a) {
    /* Same as FIB_HASH() */
    return net_hash(a) >> f->hash_shift;
}

static void
fib_rehash(struct hash_fib *f, int step) {
    unsigned old, new, oldn, newn, ni, nh;
    struct fib_node **n, *e, *x, **t, **m, **h;

    old = f->hash_order;
    oldn = f->hash_size;
    new = old + step;
    m = h = f->hash_table;
//    DBG("Re-hashing FIB from order %d to %d\n", old, new);
    f->hash_order = new;
    fib_ht_alloc(f);
    t = n = f->hash_table;
    newn = f->hash_size;
    ni = 0;

    while (oldn--) {
        x = *h++;
        while (e = x) {
            x = e->next;
            nh = fib_hash(f, &e->addr);
            while (nh > ni) {
                *t = NULL;
                ni++;
                t = ++n;
            }
            *t = e;
            t = &e->next;
        }
    }
    while (ni < newn) {
        *t = NULL;
        ni++;
        t = ++n;
    }
    free(m);
}

int fib_init(struct hash_fib *f, uint addr_type, uint node_size, uint node_offset, uint hash_order);

void *fib_find(struct hash_fib *, const net_addr *);    /* Find or return NULL if doesn't exist */
void *fib_find_or_insert(struct hash_fib *, const net_addr *);    /* Find or create new if nonexistent */
void *fib_route(struct hash_fib *, const net_addr *); /* Longest-match routing lookup */
void fib_delete(struct hash_fib *, void *);    /* Remove hash_fib entry */
void fib_free(struct hash_fib *);        /* Destroy the hash_fib */
void fib_check(struct hash_fib *);        /* Consistency check for debugging */
void fib_print(struct hash_fib *);

int init_userspace_fib(struct hash_fib *);

#endif