#define _GNU_SOURCE

#include <stdio.h>
#include <poll.h>
#include <sched.h>
#include <pthread.h>
#include <bpf/xsk.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <errno.h>
#include <linux/if_link.h>
#include "common/common_user_bpf_xdp.h"
#include "common/common_defines.h"
#include "radix_fib/radix_fib.h"
#include "radix_fib/function.h"
#include <linux/lwtunnel.h>
#include <linux/seg6_iptunnel.h>
#include <glib.h>
#include <sys/ioctl.h>

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

#ifndef MAX_BURST_RX
#define MAX_BURST_RX 256
#endif

#ifndef MAX_BURST_TX
#define MAX_BURST_TX 256
#endif

#ifndef MAX_PORTS
#define MAX_PORTS 64
#endif

#ifndef NIC_PORT
#define NIC_PORT 16
#endif

#ifndef NIC_NUM
#define NIC_NUM 16
#endif

#ifndef MAX_THREADS
#define MAX_THREADS 64
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define SEG6_LOCAL_ACTION_END_AD4 16
#define SEG6_LOCAL_ACTION_END_AD6 17

radix_tree_t *ipv6_fib;

struct bpool_params {
    u32 n_buffers;
    u32 buffer_size;
    int mmap_flags;

    u32 n_users_max;
    u32 n_buffers_per_slab;
};

/* This buffer pool implementation organizes the buffers into equally sized
 * slabs of *n_buffers_per_slab*. Initially, there are *n_slabs* slabs in the
 * pool that are completely filled with buffer pointers (full slabs).
 *
 * Each buffer cache has a slab for buffer allocation and a slab for buffer
 * free, with both of these slabs initially empty. When the cache's allocation
 * slab goes empty, it is swapped with one of the available full slabs from the
 * pool, if any is available. When the cache's free slab goes full, it is
 * swapped for one of the empty slabs from the pool, which is guaranteed to
 * succeed.
 *
 * Partially filled slabs never get traded between the cache and the pool
 * (except when the cache itself is destroyed), which enables fast operation
 * through pointer swapping.
 */
struct bpool {
    struct bpool_params params;
    pthread_mutex_t lock;
    void *addr;

    u64 **slabs;
    u64 **slabs_reserved;
    u64 *buffers;
    u64 *buffers_reserved;

    u64 n_slabs;
    u64 n_slabs_reserved;
    u64 n_buffers;

    u64 n_slabs_available;
    u64 n_slabs_reserved_available;

    struct xsk_umem_config umem_cfg;
    struct xsk_ring_prod umem_fq;
    struct xsk_ring_cons umem_cq;
    struct xsk_umem *umem;
};


/*
 * Port
 *
 * Each of the forwarding ports sits on top of an AF_XDP socket. In order for
 * packet forwarding to happen with no packet buffer copy, all the sockets need
 * to share the same UMEM area, which is used as the buffer pool memory.
 */
struct burst_rx {
    u64 addr[MAX_BURST_RX];
    u32 len[MAX_BURST_RX];
};

struct burst_tx {
    u64 addr[MAX_BURST_TX];
    u32 len[MAX_BURST_TX];
    struct port *out_port[MAX_BURST_TX];
    u32 n_pkts;
};

struct port_params {
    bool init;
    struct xsk_socket_config xsk_cfg;
    struct bpool *bp;
    const char *iface;
    u32 iface_queue;
    int ifindex;
    char progsec[32];
    char filename[512];
};

struct port {
    struct port_params params;

    struct bcache *bc;

    struct xsk_ring_cons rxq;
    struct xsk_ring_prod txq;
    struct xsk_ring_prod umem_fq;
    struct xsk_ring_cons umem_cq;
    struct xsk_socket *xsk;
    int umem_fq_initialized;

    u64 n_pkts_rx;
    u64 n_pkts_tx;
};

struct bcache {
    struct bpool *bp;

    u64 *slab_cons;
    u64 *slab_prod;

    u64 n_buffers_cons;
    u64 n_buffers_prod;
};

/*
 * Process
 */
static const struct bpool_params bpool_params_default = {
        .n_buffers = 128 * 2048,
        .buffer_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
        .mmap_flags = 0,
        .n_users_max = 64,
        .n_buffers_per_slab = XSK_RING_PROD__DEFAULT_NUM_DESCS,
};

static const struct xsk_umem_config umem_cfg_default = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
};

static const struct port_params port_params_default = {
        .xsk_cfg = {
                .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
                .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
                .libbpf_flags = 0,
                .xdp_flags = XDP_FLAGS_SKB_MODE,
                .bind_flags = XDP_COPY,
        },

        .bp = NULL,
        .iface = NULL,
        .iface_queue = 0,
};

struct nic_node {
    int if_index;
    int port_num;
    struct port *port_array[NIC_PORT];
};

struct thread_data {
//    struct nic_node *rx_nicNode;
    GHashTable *global_nics;
    struct burst_rx burst_rx;
    struct burst_tx burst_tx;
    u32 cpu_core_id;
    int quit;
};

struct input_cfg_params {
    const char *iface;
    u32 iface_queue;
    int ifindex;
    const char *filename;;
    u32 xdp_flags;
    u16 bind_flags;
};

struct input_cfg_array {
    int num;
    struct input_cfg_params inputCfgParams[NIC_NUM];
};

//struct nic_node global_nic_list[8] = {0};
GHashTable *global_nic_hash = NULL;

static struct bpool_params bpool_params;
static struct xsk_umem_config umem_cfg;
static struct bpool *bp;
static struct port_params port_params[MAX_PORTS];
static int n_threads = 0;
static int n_nic;
static struct thread_data thread_data[MAX_THREADS];
static pthread_t threads[MAX_THREADS];
//static struct port *ports[MAX_PORTS] = {NULL};
static u64 n_pkts_rx[MAX_PORTS];
static u64 n_pkts_tx[MAX_PORTS];
static int n_ports;
static int quit;
struct input_cfg_array inputCfgArray;

static int parse_args(int argc, char **argv) {
    struct option lgopts[] = {
            {NULL, 0, 0, 0}
    };
    int opt, option_index;
    inputCfgArray.num = 0;
    /* Parse the input arguments. */
    for (;;) {
        opt = getopt_long(argc, argv, "c:i:q:f:s:e:m:", lgopts, &option_index);
        if (opt == EOF)
            break;

        switch (opt) {
            case 's':
                break;
            case 'e':
                inputCfgArray.num += 1;
                break;


            case 'i':
//                if (n_ports == MAX_PORTS) {
//                    printf("Max number of ports (%d) reached.\n",
//                           MAX_PORTS);
//                    return -1;
//                }

//                for (int i = 0; i < NIC_PORT; ++i) {
//                    port_params[n_ports].iface = optarg;
//                    port_params[n_ports].iface_queue = i;
//                    port_params[n_ports].ifindex = if_nametoindex(port_params[n_ports].iface);
//                    n_ports++;
//                }
                inputCfgArray.inputCfgParams[inputCfgArray.num].iface = optarg;
                inputCfgArray.inputCfgParams[inputCfgArray.num].ifindex = if_nametoindex(optarg);
                n_nic++;
                break;

            case 'q':
//                if (n_ports == 0) {
//                    printf("No port specified for queue.\n");
//                    return -1;
//                }
                inputCfgArray.inputCfgParams[inputCfgArray.num].iface_queue = atoi(optarg);
                break;
            case 'f':
                inputCfgArray.inputCfgParams[inputCfgArray.num].filename = optarg;
                break;
            case 'm':
                printf("%s", optarg);
                if (atoi(optarg) == 0) {
                    inputCfgArray.inputCfgParams[inputCfgArray.num].xdp_flags = XDP_FLAGS_SKB_MODE;
                    inputCfgArray.inputCfgParams[inputCfgArray.num].bind_flags = XDP_COPY;
                }
                if (atoi(optarg) == 1) {
                    inputCfgArray.inputCfgParams[inputCfgArray.num].xdp_flags = XDP_FLAGS_DRV_MODE;
                    inputCfgArray.inputCfgParams[inputCfgArray.num].bind_flags = XDP_ZEROCOPY;
                }
                break;

            case 'c':
                if (n_threads == MAX_THREADS) {
                    printf("Max number of threads (%d) reached.\n",
                           MAX_THREADS);
                    return -1;
                }

                thread_data[n_threads].cpu_core_id = atoi(optarg);
                n_threads++;
                break;
            default:
                printf("Illegal argument.\n");
                return -1;
        }
    }

    optind = 1; /* reset getopt lib */

    /* Check the input arguments. */
//    if (!n_ports) {
//        printf("No ports specified.\n");
//        return -1;
//    }

    if (!n_threads) {
        printf("No threads specified.\n");
        return -1;
    }

//    if (n_ports % n_threads) {
//        printf("Ports cannot be evenly distributed to threads.\n");
//        return -1;
//    }

    return 0;
}

static void
print_port_stats_separator(void) {
    printf("+-%4s-+-%12s-+-%13s-+-%12s-+-%13s-+\n",
           "----",
           "------------",
           "-------------",
           "------------",
           "-------------");
}

static void
print_port_stats_header(void) {
    print_port_stats_separator();
    printf("| %4s | %12s | %13s | %12s | %13s |\n",
           "Port",
           "RX packets",
           "RX rate (pps)",
           "TX packets",
           "TX_rate (pps)");
    print_port_stats_separator();
}

static void
print_port_stats_trailer(void) {
    print_port_stats_separator();
    printf("\n");
}

//static void
//print_port_stats(int port_id, u64 ns_diff) {
//    struct port *p = ports[port_id];
//    double rx_pps, tx_pps;
//
//    rx_pps = (p->n_pkts_rx - n_pkts_rx[port_id]) * 1000000000. / ns_diff;
//    tx_pps = (p->n_pkts_tx - n_pkts_tx[port_id]) * 1000000000. / ns_diff;
//
//    printf("| %4d | %12llu | %13.0f | %12llu | %13.0f |\n",
//           port_id,
//           p->n_pkts_rx,
//           rx_pps,
//           p->n_pkts_tx,
//           tx_pps);
//
//    n_pkts_rx[port_id] = p->n_pkts_rx;
//    n_pkts_tx[port_id] = p->n_pkts_tx;
//}

//static void
//print_port_stats_all(u64 ns_diff) {
//    int i;
//
//    print_port_stats_header();
//    for (i = 0; i < n_ports; i++)
//        print_port_stats(i, ns_diff);
//    print_port_stats_trailer();
//}
//

static void remove_xdp_program(void) {
    int i;

    for (i = 0; i < n_ports; i++)
        bpf_set_link_xdp_fd(if_nametoindex(port_params[i].iface), -1,
                            port_params[i].xsk_cfg.xdp_flags);
}

static struct bpool *bpool_init(struct bpool_params *params, struct xsk_umem_config *umem_cfg) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    u64 n_slabs, n_slabs_reserved, n_buffers, n_buffers_reserved;
    u64 slabs_size, slabs_reserved_size;
    u64 buffers_size, buffers_reserved_size;
    u64 total_size, i;
    struct bpool *bp;
    u8 *p;
    int status;

    /* mmap prep. */
    if (setrlimit(RLIMIT_MEMLOCK, &r))
        return NULL;

    /* bpool internals dimensioning. */
    n_slabs = (params->n_buffers + params->n_buffers_per_slab - 1) / params->n_buffers_per_slab;
    n_slabs_reserved = params->n_users_max * 2;
    n_buffers = n_slabs * params->n_buffers_per_slab;
    n_buffers_reserved = n_slabs_reserved * params->n_buffers_per_slab;

    slabs_size = n_slabs * sizeof(u64 *);
    slabs_reserved_size = n_slabs_reserved * sizeof(u64 *);
    buffers_size = n_buffers * sizeof(u64);
    buffers_reserved_size = n_buffers_reserved * sizeof(u64);

    total_size = sizeof(struct bpool) +
                 slabs_size + slabs_reserved_size +
                 buffers_size + buffers_reserved_size;

    /* bpool memory allocation. */
    p = calloc(total_size, sizeof(u8));
    if (!p)
        return NULL;

    /* bpool memory initialization. */
    bp = (struct bpool *) p;
    memcpy(&bp->params, params, sizeof(*params));
    bp->params.n_buffers = n_buffers;

    bp->slabs = (u64 **) &p[sizeof(struct bpool)];
    bp->slabs_reserved = (u64 **) &p[sizeof(struct bpool) + slabs_size];
    bp->buffers = (u64 *) &p[sizeof(struct bpool) + slabs_size + slabs_reserved_size];
    bp->buffers_reserved = (u64 *) &p[sizeof(struct bpool) + slabs_size + slabs_reserved_size + buffers_size];

    bp->n_slabs = n_slabs;
    bp->n_slabs_reserved = n_slabs_reserved;
    bp->n_buffers = n_buffers;

    for (i = 0; i < n_slabs; i++)
        bp->slabs[i] = &bp->buffers[i * params->n_buffers_per_slab];
    bp->n_slabs_available = n_slabs;

    for (i = 0; i < n_slabs_reserved; i++)
        bp->slabs_reserved[i] = &bp->buffers_reserved[i * params->n_buffers_per_slab];
    bp->n_slabs_reserved_available = n_slabs_reserved;

    for (i = 0; i < n_buffers; i++)
        bp->buffers[i] = i * params->buffer_size;

    /* lock. */
    status = pthread_mutex_init(&bp->lock, NULL);
    if (status) {
        free(p);
        return NULL;
    }

    /* mmap. */
    bp->addr = mmap(NULL,
                    n_buffers * params->buffer_size,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | params->mmap_flags,
                    -1,
                    0);
    if (bp->addr == MAP_FAILED) {
        pthread_mutex_destroy(&bp->lock);
        free(p);
        return NULL;
    }

    /* umem. */
    status = xsk_umem__create(&bp->umem,
                              bp->addr,
                              bp->params.n_buffers * bp->params.buffer_size,
                              &bp->umem_fq,
                              &bp->umem_cq,
                              umem_cfg);
    if (status) {
        munmap(bp->addr, bp->params.n_buffers * bp->params.buffer_size);
        pthread_mutex_destroy(&bp->lock);
        free(p);
        return NULL;
    }
    memcpy(&bp->umem_cfg, umem_cfg, sizeof(*umem_cfg));

    return bp;
}

static struct bcache *bcache_init(struct bpool *bp) {
    struct bcache *bc;

    bc = calloc(1, sizeof(struct bcache));
    if (!bc)
        return NULL;

    bc->bp = bp;
    bc->n_buffers_cons = 0;
    bc->n_buffers_prod = 0;

    pthread_mutex_lock(&bp->lock);
    if (bp->n_slabs_reserved_available == 0) {
        pthread_mutex_unlock(&bp->lock);
        free(bc);
        return NULL;
    }

    bc->slab_cons = bp->slabs_reserved[bp->n_slabs_reserved_available - 1];
    bc->slab_prod = bp->slabs_reserved[bp->n_slabs_reserved_available - 2];
    bp->n_slabs_reserved_available -= 2;
    pthread_mutex_unlock(&bp->lock);

    return bc;
}

static u32 bcache_slab_size(struct bcache *bc) {
    struct bpool *bp = bc->bp;

    return bp->params.n_buffers_per_slab;
}

/* To work correctly, the implementation requires that the *n_buffers* input
 * argument is never greater than the buffer pool's *n_buffers_per_slab*. This
 * is typically the case, with one exception taking place when large number of
 * buffers are allocated at init time (e.g. for the UMEM fill queue setup).
 */
static inline u32
bcache_cons_check(struct bcache *bc, u32 n_buffers) {
    struct bpool *bp = bc->bp;
    u64 n_buffers_per_slab = bp->params.n_buffers_per_slab;
    u64 n_buffers_cons = bc->n_buffers_cons;
    u64 n_slabs_available;
    u64 *slab_full;

    /*
     * Consumer slab is not empty: Use what's available locally. Do not
     * look for more buffers from the pool when the ask can only be
     * partially satisfied.
     */
    if (n_buffers_cons) {
        return (n_buffers_cons < n_buffers) ?
               n_buffers_cons :
               n_buffers;

    }

    /*
     * Consumer slab is empty: look to trade the current consumer slab
     * (full) for a full slab from the pool, if any is available.
     */
//    pthread_mutex_lock(&bp->lock);
    n_slabs_available = bp->n_slabs_available;
    if (!n_slabs_available) {
//        pthread_mutex_unlock(&bp->lock);
        return 0;
    }

    n_slabs_available--;
    slab_full = bp->slabs[n_slabs_available];
    bp->slabs[n_slabs_available] = bc->slab_cons;
    bp->n_slabs_available = n_slabs_available;
//    pthread_mutex_unlock(&bp->lock);

    bc->slab_cons = slab_full;
    bc->n_buffers_cons = n_buffers_per_slab;
    return n_buffers;
}

static inline u64

bcache_cons(struct bcache *bc) {
    u64 buffer;
    buffer = bc->slab_cons[--bc->n_buffers_cons];
    return buffer;
}

static inline void
bcache_prod(struct bcache *bc, u64 buffer) {
    struct bpool *bp = bc->bp;
    u64 n_buffers_per_slab = bp->params.n_buffers_per_slab;
    u64 n_buffers_prod = bc->n_buffers_prod;
    u64 n_slabs_available;
    u64 *slab_empty;

    /*
     * Producer slab is not yet full: store the current buffer to it.
     */
    if (n_buffers_prod < n_buffers_per_slab) {
        bc->slab_prod[bc->n_buffers_prod++] = buffer;
        return;
    }

    /*
     * Producer slab is full: trade the cache's current producer slab
     * (full) for an empty slab from the pool, then store the current
     * buffer to the new producer slab. As one full slab exists in the
     * cache, it is guaranteed that there is at least one empty slab
     * available in the pool.
     */
//    pthread_mutex_lock(&bp->lock);
    n_slabs_available = bp->n_slabs_available;
    slab_empty = bp->slabs[n_slabs_available];
    bp->slabs[n_slabs_available] = bc->slab_prod;
    bp->n_slabs_available = n_slabs_available + 1;
//    pthread_mutex_unlock(&bp->lock);

    slab_empty[0] = buffer;
    bc->slab_prod = slab_empty;
    bc->n_buffers_prod = 1;
}


static void
bcache_free(struct bcache *bc) {
    struct bpool *bp;

    if (!bc)
        return;

    /* In order to keep this example simple, the case of freeing any
     * existing buffers from the cache back to the pool is ignored.
     */

    bp = bc->bp;
    pthread_mutex_lock(&bp->lock);
    bp->slabs_reserved[bp->n_slabs_reserved_available] = bc->slab_prod;
    bp->slabs_reserved[bp->n_slabs_reserved_available + 1] = bc->slab_cons;
    bp->n_slabs_reserved_available += 2;
    pthread_mutex_unlock(&bp->lock);

    free(bc);
}

static void
port_free(struct port *p) {
    if (!p)
        return;

    /* To keep this example simple, the code to free the buffers from the
     * socket's receive and transmit queues, as well as from the UMEM fill
     * and completion queues, is not included.
     */

    if (p->xsk)
        xsk_socket__delete(p->xsk);

    bcache_free(p->bc);

    free(p);
}

static struct port *port_init(struct port_params *params) {
    struct port *p;
    u32 umem_fq_size, pos = 0;
    int status, i;

    /* Memory allocation and initialization. */
    p = calloc(sizeof(struct port), 1);
    if (!p)
        return NULL;

    memcpy(&p->params, params, sizeof(p->params));
    umem_fq_size = params->bp->umem_cfg.fill_size;

    /* bcache. */
    p->bc = bcache_init(params->bp);
    if (!p->bc ||
        (bcache_slab_size(p->bc) < umem_fq_size) ||
        (bcache_cons_check(p->bc, umem_fq_size) < umem_fq_size)) {
        printf("%d\n", bcache_cons_check(p->bc, umem_fq_size));
        port_free(p);
        return NULL;
    }

    /* xsk socket. */
    status = xsk_socket__create_shared(&p->xsk,
                                       params->iface,
                                       params->iface_queue,
                                       params->bp->umem,
                                       &p->rxq,
                                       &p->txq,
                                       &p->umem_fq,
                                       &p->umem_cq,
                                       &params->xsk_cfg);

    if (status) {
        port_free(p);
        return NULL;
    }

    /* umem fq. */
    xsk_ring_prod__reserve(&p->umem_fq, umem_fq_size, &pos);

    for (i = 0; i < umem_fq_size; i++)
        *xsk_ring_prod__fill_addr(&p->umem_fq, pos + i) = bcache_cons(p->bc);

    xsk_ring_prod__submit(&p->umem_fq, umem_fq_size);
    p->umem_fq_initialized = 1;

    return p;
}

//static void print_port(u32 port_id) {
//    struct port *port = ports[port_id];
//
//    printf("Port %u: interface = %s, queue = %u\n",
//           port_id, port->params.iface, port->params.iface_queue);
//}

static void
signal_handler(int sig) {
    for (int i = 0; i < n_threads; i++)
        thread_data[i].quit = 1;
}

static void
bpool_free(struct bpool *bp) {
    if (!bp)
        return;

    xsk_umem__delete(bp->umem);
    munmap(bp->addr, bp->params.n_buffers * bp->params.buffer_size);
    pthread_mutex_destroy(&bp->lock);
    free(bp);
}

//static inline void
//port_tx_burst(struct port *p) {
//    u32 n_pkts, pos, i;
//    int status;
//    int ret = 0;
//    kick_retry:
//    ret = sendto(xsk_socket__fd(p->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
//    if (ret < 0 && errno == EAGAIN) {
//        goto kick_retry;
//    }
//    /* UMEM CQ. */
//    n_pkts = p->params.bp->umem_cfg.comp_size;
//
//    n_pkts = xsk_ring_cons__peek(&p->umem_cq, n_pkts, &pos);
//    printf("port_tx_burst:%d\n", n_pkts);
//
//    for (i = 0; i < n_pkts; i++) {
//        u64 addr = *xsk_ring_cons__comp_addr(&p->umem_cq, pos + i);
//        bcache_prod(p->bc, addr);
//    }
//
//    xsk_ring_cons__release(&p->umem_cq, n_pkts);
//    p->n_pkts_tx += n_pkts;
//    printf("p->n_pkts_tx:%d\n", p->n_pkts_tx);
//}

//static inline bool
//port_rx_burst(struct port *port_rx, struct burst_rx *brx, struct port *port_tx, struct burst_tx *btx) {
//    u32 rx_pkts = 0, pos_rx = 0, pos_fill = 0, pos_tx = 0, i = 0, j = 0, fill_pkts = 0, tx_pkts = 0;
//    int status = 0;
//
//    struct hash_sid6_info *info = NULL;
//
//
//    rx_pkts = ARRAY_SIZE(brx->addr);
//    rx_pkts = xsk_ring_cons__peek(&port_rx->rxq, rx_pkts, &pos_rx);
//    if (!rx_pkts) {
//        return false;
//    }
//    printf("rx_pkts:%d\n", rx_pkts);
//
//    /* UMEM FQ. */
//    fill_pkts = bcache_cons_check(port_rx->bc, rx_pkts);
//    if (fill_pkts) {
//        /* Free buffers for FQ replenish. */
//        printf("fill_pkts:%d\n", fill_pkts);
//        status = xsk_ring_prod__reserve(&port_rx->umem_fq, fill_pkts, &pos_fill);
//        if (status) {
//            for (i = 0; i < status; i++)
//                *xsk_ring_prod__fill_addr(&port_rx->umem_fq, pos_fill + i) = bcache_cons(port_rx->bc);
//            xsk_ring_prod__submit(&port_rx->umem_fq, status);
//        } else {
//            printf("status == fill_pkts");
//
//        }
//    } else {
//        printf("!fill_pkts");
//    }
//    port_tx_burst(port_tx);
//    for (i = 0; i < rx_pkts; i++) {
//        brx->addr[i] = xsk_ring_cons__rx_desc(&port_rx->rxq, pos_rx + i)->addr;
//        brx->len[i] = xsk_ring_cons__rx_desc(&port_rx->rxq, pos_rx + i)->len;
//
//        //process
//        u64 addr = xsk_umem__add_offset_to_addr(brx->addr[i]);
//        u8 *pkt = xsk_umem__get_data(port_rx->params.bp->addr, addr);
//
//        struct ethhdr *eth = (struct ethhdr *) pkt;
//        struct ipv6hdr *ipv6 = (struct ipv6hdr *) (eth + 1);
//        if (info) {
//            if (memcmp(&ipv6->daddr, info->n.addr.data, info->n.addr.pxlen)) {
//                memcpy(eth->h_dest, info->dst_mac, 6);
//                memcpy(eth->h_source, info->src_mac, 6);
//                continue;
//            } else {
//                tx_pkts = i - j;
//                status = xsk_ring_prod__reserve(&port_tx->txq, tx_pkts, &pos_tx);
//                if (status != tx_pkts) {
//                    /* No more transmit slots, drop the packet */
//                    return false;
//                }
//
//                if (xsk_ring_prod__needs_wakeup(&port_tx->txq))
//                    sendto(xsk_socket__fd(port_tx->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
//
//                for (int tmp = 0; tmp < tx_pkts; tmp++, j++) {
//                    xsk_ring_prod__tx_desc(&port_tx->txq, pos_tx + tmp)->addr = brx->addr[j];
//                    xsk_ring_prod__tx_desc(&port_tx->txq, pos_tx + tmp)->len = brx->len[j];
//                }
//                xsk_ring_prod__submit(&port_tx->txq, tx_pkts);
//            }
//        }
//        struct net_addr_ip6 a = {2, 128, sizeof(struct net_addr_ip6), ipv6->daddr};
//        info = fib_route(&ipv6_fib, &a);
//        memcpy(eth->h_dest, info->dst_mac, 6);
//        memcpy(eth->h_source, info->src_mac, 6);
//
//    }
//    if (i != j) {
//        tx_pkts = i - j;
//        status = xsk_ring_prod__reserve(&port_tx->txq, tx_pkts, &pos_tx);
//        if (xsk_ring_prod__needs_wakeup(&port_tx->txq))
//            sendto(xsk_socket__fd(port_tx->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
//        if (status != tx_pkts) {
//            printf("false status:%d\n", status);
//            printf("%d\n", xsk_prod_nb_free(&port_rx->umem_fq, 1));
//            printf("%d\n ", xsk_prod_nb_free(&port_tx->txq, 1));
//            printf("%d\n ", xsk_cons_nb_avail(&port_tx->umem_cq, 1));
//
//            /* No more transmit slots, drop the packet */
//            return false;
//        }
//
//        for (int tmp = 0; tmp < tx_pkts; tmp++, j++) {
//            xsk_ring_prod__tx_desc(&port_tx->txq, pos_tx + tmp)->addr = brx->addr[j];
//            xsk_ring_prod__tx_desc(&port_tx->txq, pos_tx + tmp)->len = brx->len[j];
//        }
//        xsk_ring_prod__submit(&port_tx->txq, tx_pkts);
//        printf("tx_pkts:%d\n", tx_pkts);
//    }
//
//    xsk_ring_cons__release(&port_rx->rxq, rx_pkts);
//    port_rx->n_pkts_rx += rx_pkts;
//    printf("port_rx->n_pkts_rx:%d\n", port_rx->n_pkts_rx);
//
//    return rx_pkts;
//}

static inline u32
port_rx_burst(struct port *p, struct burst_rx *b) {
    u32 n_pkts = 0, pos = 0, i = 0;

    /* Free buffers for FQ replenish. */
    n_pkts = ARRAY_SIZE(b->addr);

//    n_pkts = bcache_cons_check(p->bc, n_pkts);
//    if (!n_pkts)
//        return 0;

    /* RXQ. */
    n_pkts = xsk_ring_cons__peek(&p->rxq, n_pkts, &pos);
    if (!n_pkts) {
        return 0;
    }

    for (i = 0; i < n_pkts; i++) {
        b->addr[i] = xsk_ring_cons__rx_desc(&p->rxq, pos + i)->addr;
        b->len[i] = xsk_ring_cons__rx_desc(&p->rxq, pos + i)->len;
    }

    xsk_ring_cons__release(&p->rxq, n_pkts);
    p->n_pkts_rx += n_pkts;

    /* UMEM FQ. */
    for (;;) {
        int status;

        status = xsk_ring_prod__reserve(&p->umem_fq, n_pkts, &pos);
        if (status == n_pkts)
            break;
//        if (xsk_ring_prod__needs_wakeup(&p->umem_fq)) {
//            struct pollfd pollfd = {
//                    .fd = xsk_socket__fd(p->xsk),
//                    .events = POLLIN,
//            };
//
//            poll(&pollfd, 1, 0);
//        }
    }

    for (u32 n_pkts_new = 0; n_pkts_new < n_pkts;) {
        u32 check_pkts = n_pkts - n_pkts_new;
        check_pkts = bcache_cons_check(p->bc, check_pkts);
        for (i = 0; i < check_pkts; i++) {
            *xsk_ring_prod__fill_addr(&p->umem_fq, pos + n_pkts_new) =
                    bcache_cons(p->bc);
            n_pkts_new++;
        }
    }


//    for (i = 0; i < n_pkts; i++)
//        *xsk_ring_prod__fill_addr(&p->umem_fq, pos + i) =
//                bcache_cons(p->bc);

    xsk_ring_prod__submit(&p->umem_fq, n_pkts);

    return n_pkts;
}

static inline void
port_tx_burst(struct port *p, struct burst_tx *b) {
    u32 n_pkts, pos, i;
    int status;

    /* UMEM CQ. */
    n_pkts = p->params.bp->umem_cfg.comp_size;

    n_pkts = xsk_ring_cons__peek(&p->umem_cq, n_pkts, &pos);

    for (i = 0; i < n_pkts; i++) {
        u64 addr = *xsk_ring_cons__comp_addr(&p->umem_cq, pos + i);

        bcache_prod(p->bc, addr);
    }

    xsk_ring_cons__release(&p->umem_cq, n_pkts);

    /* TXQ. */
    n_pkts = b->n_pkts;

    for (;;) {
        status = xsk_ring_prod__reserve(&p->txq, n_pkts, &pos);
        if (status == n_pkts)
            break;

//        if (xsk_ring_prod__needs_wakeup(&p->txq))
        sendto(xsk_socket__fd(p->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    }

    for (i = 0; i < n_pkts; i++) {
        xsk_ring_prod__tx_desc(&p->txq, pos + i)->addr = b->addr[i];
        xsk_ring_prod__tx_desc(&p->txq, pos + i)->len = b->len[i];
    }

    xsk_ring_prod__submit(&p->txq, n_pkts);
//    if (xsk_ring_prod__needs_wakeup(&p->txq))
    sendto(xsk_socket__fd(p->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    p->n_pkts_tx += n_pkts;
}

static void *process_packet(void *data, u32 *pkt_len, struct port *port_rx, struct radix_sid6_info *info,
                            GHashTable *dev_cache_hashtable) {

    struct dev_cache_struct *devCacheStruct = g_hash_table_lookup(dev_cache_hashtable, port_rx->params.iface);
    if (devCacheStruct != NULL) {
        struct ethhdr *eth = (struct ethhdr *) data;
        if (ntohs(eth->h_proto) != ETH_P_IPV6) {
//        if (port_rx->params.)
            return NULL;
        }
        void *ip_hdr = (void *) (eth + 1);
        end_ad4_encap(data, pkt_len, ip_hdr, devCacheStruct);
    }

    struct ethhdr *eth = (struct ethhdr *) data;
    struct ipv6hdr *ipv6 = (struct ipv6hdr *) (eth + 1);
    struct ipv6_rt_hdr *rt_hdr;
    struct ipv6_sr_hdr *srh;
    prefix_t a;
    radix_node_t *t;


    if (ntohs(eth->h_proto) != ETH_P_IPV6) {

//        if (port_rx->params.)
        return NULL;
    }



//    rt_hdr = (struct ipv6_rt_hdr *) find_srh(ipv6);
//    if (!rt_hdr || rt_hdr->type != IPV6_SRCRT_TYPE_4) {
//        return NULL;
//    } else {
//        srh = (struct ipv6_sr_hdr *) rt_hdr;
//        struct net_addr_ip6 a = {2, 128, sizeof(struct net_addr_ip6), ipv6->daddr};
//        n = fib_route(&ipv6_fib, &a);
//        if (n) {
////            if ((*seg6_action_func[n->behavior])(data, ipv6, srh)) {
//            return NULL;
////            }
//        }
//    }
//    if (info) {
//        if (memcmp(&ipv6->daddr, info->n.addr.data, info->n.addr.pxlen)) {
//            memcpy(eth->h_dest, info->dst_mac, 6);
//            memcpy(eth->h_source, info->src_mac, 6);
//            return info;
//        }
//    }


//    ipv6


    look:
    a.bitlen = 128;
    a.family = AF_INET6;
    a.ref_count = 0;
    a.add.sin6 = ipv6->daddr;

    t = radix_search_best(ipv6_fib, &a);
    info = t->data;
    switch (info->encap_type) {
        case LWTUNNEL_ENCAP_NONE:
            memcpy(eth->h_dest, info->dst_mac, 6);
            memcpy(eth->h_source, info->src_mac, 6);
            break;
        case LWTUNNEL_ENCAP_SEG6:
            switch (info->behavior) {
                case SEG6_IPTUN_MODE_ENCAP:
                    encap(data, pkt_len, ipv6, info);
                    a.bitlen = 128;
                    a.family = AF_INET6;
                    a.ref_count = 0;
                    a.add.sin6 = ipv6->daddr;
                    t = radix_search_best(ipv6_fib, &a);
                    info = t->data;
                    memcpy(eth->h_dest, info->dst_mac, 6);
                    memcpy(eth->h_source, info->src_mac, 6);
                    break;
                case SEG6_IPTUN_MODE_INLINE:
                    encap_inline(data, pkt_len, ipv6, info);
                    goto look;
                    break;
            }
            break;
        case LWTUNNEL_ENCAP_SEG6_LOCAL:
            switch (info->behavior) {
                case SEG6_LOCAL_ACTION_END:
                    rt_hdr = (struct ipv6_rt_hdr *) find_srh(ipv6);
                    if (!rt_hdr)
                        return NULL;
                    srh = (struct ipv6_sr_hdr *) rt_hdr;
                    end(data, ipv6, srh, info);
                    a.bitlen = 128;
                    a.family = AF_INET6;
                    a.ref_count = 0;
                    a.add.sin6 = ipv6->daddr;
                    t = radix_search_best(ipv6_fib, &a);
                    info = t->data;
                    memcpy(eth->h_dest, info->dst_mac, 6);
                    memcpy(eth->h_source, info->src_mac, 6);
                    break;
                case SEG6_LOCAL_ACTION_END_X:
                    rt_hdr = (struct ipv6_rt_hdr *) find_srh(ipv6);
                    if (!rt_hdr)
                        return NULL;
                    srh = (struct ipv6_sr_hdr *) rt_hdr;

                    end_x(data, ipv6, srh, info);
                    memcpy(eth->h_dest, info->dst_mac, 6);
                    a.bitlen = 128;
                    a.family = AF_INET6;
                    a.ref_count = 0;
                    a.add.sin6 = info->nh6.prefix;
                    t = radix_search_best(ipv6_fib, &a);
                    info = t->data;
                    memcpy(eth->h_source, info->src_mac, 6);
                    break;

                case SEG6_LOCAL_ACTION_END_DX6:
                    rt_hdr = (struct ipv6_rt_hdr *) find_srh(ipv6);
                    if (!rt_hdr)
                        return NULL;
                    srh = (struct ipv6_sr_hdr *) rt_hdr;
                    end_dx6(data, pkt_len, ipv6, srh, info);
                    memcpy(eth->h_dest, info->dst_mac, 6);
                    a.bitlen = 128;
                    a.family = AF_INET6;
                    a.ref_count = 0;
                    a.add.sin6 = info->nh6.prefix;
                    t = radix_search_best(ipv6_fib, &a);
                    info = t->data;
                    memcpy(eth->h_source, info->src_mac, 6);
                    break;

                case SEG6_LOCAL_ACTION_END_DX2:
                    rt_hdr = (struct ipv6_rt_hdr *) find_srh(ipv6);
                    if (!rt_hdr)
                        return NULL;
                    srh = (struct ipv6_sr_hdr *) rt_hdr;
                    end_dx2(data, pkt_len, ipv6, srh, info);
                    break;
                case SEG6_LOCAL_ACTION_END_AD4:
                    rt_hdr = (struct ipv6_rt_hdr *) find_srh(ipv6);
                    if (!rt_hdr)
                        return NULL;
                    srh = (struct ipv6_sr_hdr *) rt_hdr;
                    end_ad4(data, pkt_len, ipv6, srh, info, dev_cache_hashtable);
                    memcpy(eth->h_dest, info->dst_mac, 6);
                    memcpy(eth->h_source, info->src_mac, 6);
                    break;
                case SEG6_LOCAL_ACTION_END_AD6:
                    rt_hdr = (struct ipv6_rt_hdr *) find_srh(ipv6);
                    if (!rt_hdr)
                        return NULL;
                    srh = (struct ipv6_sr_hdr *) rt_hdr;
                    end_ad6(data, pkt_len, ipv6, srh, info, dev_cache_hashtable);
                    memcpy(eth->h_dest, info->dst_mac, 6);
                    memcpy(eth->h_source, info->src_mac, 6);
                    break;

            }
            break;
    }
    return info;
}

static void *thread_func(void *arg) {
    struct thread_data *t = arg;
    cpu_set_t cpu_cores;
//    u32 i, poll_ret;
//    struct nic_node *rx_nicNode = t->rx_nicNode;
    GHashTable *globalNics = t->global_nics;
    int nic_nums = g_hash_table_size(globalNics);
    CPU_ZERO(&cpu_cores);
    CPU_SET(t->cpu_core_id, &cpu_cores);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
    GList *gList = g_hash_table_get_values(globalNics);
    GHashTable *dev_cache_hashtable = g_hash_table_new(g_str_hash, g_str_equal);

    while (!t->quit) {
        for (int i = 0; i < nic_nums; ++i) {
            struct nic_node *nicNode = g_list_nth_data(gList, i);
            for (int j = 0; j < nicNode->port_num; ++j) {
                struct port *port_rx = nicNode->port_array[j];
                struct port *port_tx = NULL;
                struct burst_rx *brx = &t->burst_rx;
                struct burst_tx *btx = &t->burst_tx;
                u32 n_pkts, k;

                /* RX. */
                n_pkts = port_rx_burst(port_rx, brx);
                if (!n_pkts)
                    continue;
                struct radix_sid6_info *info = NULL;

                /* Process & TX. */
                for (k = 0; k < n_pkts; k++) {
                    u64 addr = xsk_umem__add_offset_to_addr(brx->addr[k]);
                    u8 *pkt = xsk_umem__get_data(port_rx->params.bp->addr, addr);

                    info = process_packet(pkt, &brx->len[k], port_rx, info, dev_cache_hashtable);
                    if (info) {
                        struct nic_node *tx_nicNode = g_hash_table_lookup(globalNics, &info->oif_index);
                        struct port *port_tx_new = tx_nicNode->port_array[j % (tx_nicNode->port_num)];
                        if (port_tx) {
                            if (port_tx != port_tx_new) {
                                port_tx_burst(port_tx, btx);
                                btx->n_pkts = 0;
                            }
                        }
                        port_tx = port_tx_new;
//                    btx->out_port[btx->n_pkts] = port_rx;
                    }

                    btx->addr[btx->n_pkts] = brx->addr[k];
                    btx->len[btx->n_pkts] = brx->len[k];
                    btx->n_pkts++;

                }


//            if (btx->n_pkts == n_pkts) {
                port_tx_burst(port_tx, btx);
                btx->n_pkts = 0;
            }
        }
    }


//    }

    return NULL;
}

void port_free_iterator(gpointer key, gpointer value, gpointer userdata) {
    struct nic_node *nicNode = (struct nic_node *) value;
    for (int i = 0; i < nicNode->port_num; ++i) {
        struct port *pPort = nicNode->port_array[i];
        port_free(pPort);
    }
}

void print_nic(gpointer key, gpointer value, gpointer userdata) {
    int *a = key;
    struct nic_node *nicNode = (struct nic_node *) value;
    printf("key: %d ifinde: %d \n", *a, nicNode->if_index);
}


int main(int argc, char **argv) {
    struct timespec time;
    u64 ns0;

    struct bpf_object *bpf_obj = NULL;
    int xsks_map_fd;
    n_ports = 0;
//    ipv6_fib = (struct hash_fib *) malloc(sizeof(ipv6_fib));
    ipv6_fib = init_userspace_radix();

    struct radix_sid6_info *sid_node = malloc(sizeof(struct radix_sid6_info));
    radix_node_t *node = make_node(ipv6_fib, "f1::", NULL);
    node->data = sid_node;
    sid_node->encap_type = 7;
    sid_node->behavior = SEG6_LOCAL_ACTION_END_AD6;
    char oif[] = "veth0";
    char iif[] = "veth1";
    size_t a = 16;
    void *oif_buf = malloc(a + 1);
    strcpy(oif_buf, oif);
    size_t b = 16;
    void *iif_buf = malloc(a + 1);
    strcpy(iif_buf, iif);
    sid_node->oif_index = if_nametoindex(oif);
    sid_node->oif = oif_buf;
    sid_node->iif = iif_buf;

    int mac_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct ifreq ifreq;
    strcpy(ifreq.ifr_name, oif);
    ioctl(mac_sock, SIOCGIFHWADDR, &ifreq);
    memcpy(sid_node->src_mac, ifreq.ifr_hwaddr.sa_data, 6);
//    1a:b9:41:35:89:e3
    sid_node->dst_mac[0] = 0xaa;
    sid_node->dst_mac[1] = 0xaa;
    sid_node->dst_mac[2] = 0xaa;
    sid_node->dst_mac[3] = 0xaa;
    sid_node->dst_mac[4] = 0xaa;
    sid_node->dst_mac[5] = 0xa2;
//    -s 0 -i enp161s0f0 -f /root/sra/xsk_srv6_46/xsk_srv6/kernel.o -q 1 -m 0 -e 0 -s 1 -i enp161s0f1 -f /root/sra/xsk_srv6_46/xsk_srv6/kernel.o -q 1 -m 0 -e 1  -c 4
    close(mac_sock);

    /* Parse args. */
    if (parse_args(argc, argv)) {
//        print_usage(argv[0]);
        return -1;
    }

    memcpy(&bpool_params, &bpool_params_default, sizeof(struct bpool_params));
    memcpy(&umem_cfg, &umem_cfg_default, sizeof(struct xsk_umem_config));
    /* Buffer pool initialization. */
    bp = bpool_init(&bpool_params, &umem_cfg);
    if (!bp) {
        printf("Buffer pool initialization failed.\n");
        return -1;
    }
    printf("Buffer pool created successfully.\n");

    /* Ports initialization. */
    for (int i = 0; i < MAX_PORTS; i++)
        memcpy(&port_params[i], &port_params_default, sizeof(struct port_params));

    global_nic_hash = g_hash_table_new(g_int_hash, g_int_equal);
    for (int j = 0; j < inputCfgArray.num; ++j) {
        if (inputCfgArray.inputCfgParams[j].filename) {
            struct nic_node *nicNode = malloc(sizeof(struct nic_node));
            nicNode->if_index = inputCfgArray.inputCfgParams[j].ifindex;
            nicNode->port_num = 0;
            for (int i = 0; i < inputCfgArray.inputCfgParams[j].iface_queue; ++i) {
                port_params[n_ports].ifindex = inputCfgArray.inputCfgParams[j].ifindex;
                port_params[n_ports].iface = inputCfgArray.inputCfgParams[j].iface;
                port_params[n_ports].iface_queue = i;
                port_params[n_ports].xsk_cfg.xdp_flags = inputCfgArray.inputCfgParams[j].xdp_flags;
                port_params[n_ports].xsk_cfg.bind_flags = inputCfgArray.inputCfgParams[j].bind_flags;
                strcpy(port_params[n_ports].filename, inputCfgArray.inputCfgParams[j].filename);

                struct bpf_map *map;
                struct config cfg = {
                        .ifindex   = port_params[n_ports].ifindex,
                        .ifname=port_params[n_ports].iface,
                        .do_unload = false,
                        .progsec = "xdp_sock",
                        .xdp_flags=port_params[n_ports].xsk_cfg.xdp_flags,
                };
                strcpy(cfg.filename, inputCfgArray.inputCfgParams[j].filename);
                bpf_obj = load_bpf_and_xdp_attach(&cfg);
                printf("filename:%s\n", cfg.filename);
                if (!bpf_obj) {
                    /* Error handling done in load_bpf_and_xdp_attach() */
                    exit(EXIT_FAILURE);
                }

                /* We also need to load the xsks_map */
                map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
                xsks_map_fd = bpf_map__fd(map);
                if (xsks_map_fd < 0) {
                    fprintf(stderr, "ERROR: no xsks map found: %s\n", strerror(xsks_map_fd));
                    exit(EXIT_FAILURE);
                }
//                port_params[n_ports].bp = bp;
//                struct port *p = port_init(&port_params[n_ports]);
//                if (!p) {
//                    printf("Port %d initialization failed.\n", i);
//                    return -1;
//                }
//                nicNode->port_array[nicNode->port_num] = p;
//                nicNode->port_num = nicNode->port_num + 1;
                n_ports++;
            }
            g_hash_table_insert(global_nic_hash, &nicNode->if_index, nicNode);
        }
    }

    for (int i = 0; i < n_ports; ++i) {
        port_params[i].bp = bp;
        struct port *p = port_init(&port_params[i]);
        if (!p) {
            printf("Port %d initialization failed.\n", i);
            return -1;
        }
        struct nic_node *nicNode = g_hash_table_lookup(global_nic_hash, &port_params[i].ifindex);
        nicNode->port_array[nicNode->port_num] = p;
        nicNode->port_num += 1;
    }
    g_hash_table_foreach(global_nic_hash, print_nic, NULL);




//    for (int i = 0; i < n_ports; i++) {
//        struct port *p = port_init(&port_params[i]);
//        if (!p) {
//            printf("Port %d initialization failed.\n", i);
//            return -1;
//        }
//        global_nic_list[p->params.ifindex].if_index = p->params.ifindex;
//        global_nic_list[p->params.ifindex].ports[global_nic_list[p->params.ifindex].port_num++] = p;
//    }
    printf("All ports created successfully.\n");


//    /* Threads. */
    for (int i = 0; i < n_threads; i++) {
        struct thread_data *t = &thread_data[i];
//        t->rx_nicNode = &global_nic_list[2];
        t->global_nics = global_nic_hash;
//        print_thread(i);
    }

    for (int i = 0; i < n_threads; i++) {
        int status;

        status = pthread_create(&threads[i], NULL, thread_func, &thread_data[i]);
        if (status) {
            printf("Thread %d creation failed.\n", i);
            return -1;
        }
    }
    printf("All threads created successfully.\n");

    /* Print statistics. */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGABRT, signal_handler);

//    clock_gettime(CLOCK_MONOTONIC, &time);
//    ns0 = time.tv_sec * 1000000000UL + time.tv_nsec;
//    for (; !quit;) {
//        u64 ns1, ns_diff;
//
//        sleep(-1);
//        clock_gettime(CLOCK_MONOTONIC, &time);
//        ns1 = time.tv_sec * 1000000000UL + time.tv_nsec;
//        ns_diff = ns1 - ns0;
//        ns0 = ns1;
//
//        print_port_stats_all(ns_diff);
//    }

    for (int i = 0; i < n_threads; i++)
        pthread_join(threads[i], NULL);
    /* Threads completion. */
    printf("Quit.\n");
    for (int i = 0; i < n_threads; i++)
        thread_data[i].quit = 1;



//    for (i = 0; i < MAX_PORTS; i++) {
//        if (ports[i]) {
//            port_free(ports[i]);
//        }
//    }

    g_hash_table_foreach(global_nic_hash, port_free_iterator, NULL);

    printf("Quit.\n");
    bpool_free(bp);

    remove_xdp_program();

    return 0;
}