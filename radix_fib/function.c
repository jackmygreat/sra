//
// Created by root on 9/13/21.
//

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <string.h>
#include "function.h"

/**
 * end()
 * SRv6 Endpoint behavior
 * @skb: packet buffer
 * @s6 : localsid table entry
 */

int end(void *pkt, struct ipv6hdr *iph, struct ipv6_sr_hdr *srh, struct radix_sid6_info *info) {
    if (iph->hop_limit <= 1) {
        goto drop;
    }
    iph->hop_limit--;

    if (srh->segments_left <= 0) {
        goto drop;
    }

    srh->segments_left--;
    iph->daddr = *(srh->segments + srh->segments_left);
    return 1;

    drop:
    return -1;
}

int end_x(void *pkt, struct ipv6hdr *iph, struct ipv6_sr_hdr *srh, struct radix_sid6_info *info) {
    if (iph->hop_limit <= 1) {
        goto drop;
    }
    iph->hop_limit--;

    if (srh->segments_left <= 0) {
        goto drop;
    }

    srh->segments_left--;
    iph->daddr = *(srh->segments + srh->segments_left);
    return 1;

    drop:
    return -1;
}

int end_dx2(void *pkt, uint32_t *pkt_len, struct ipv6hdr *iph, struct ipv6_sr_hdr *srh, struct radix_sid6_info *info) {

    if (srh->segments_left > 0) {
        goto drop;
    }
    if (srh->nexthdr != 143) {
        goto drop;
    }

    void *srh_point = (void *) srh;
    uint32_t srh_len = (srh->hdrlen) * 8 + 8;
    void *eth2 = srh_point + srh_len;

    uint32_t copy_len = (*pkt_len) - sizeof(struct ethhdr) - 40 - srh_len;
    *pkt_len = copy_len;
    memcpy(pkt, eth2, copy_len);
    return 1;

    drop:
    return -1;
}

int end_dx6(void *pkt, uint32_t *pkt_len, struct ipv6hdr *iph, struct ipv6_sr_hdr *srh, struct radix_sid6_info *info) {

    if (srh->segments_left > 0) {
        goto drop;
    }
    if (srh->nexthdr != IPPROTO_IPV6) {
        goto drop;
    }

    void *iph_point = (void *) iph;
    void *srh_point = (void *) srh;
    void *iph2 = srh_point + (srh->hdrlen) * 8 + 8;

    uint32_t copy_len = (*pkt_len) - (iph2 - pkt);
    *pkt_len = (*pkt_len) - (iph2 - iph_point);
    memcpy(iph, iph2, copy_len);
    return 1;

    drop:
    return -1;

}

int end_ad4(void *pkt, uint32_t *pkt_len, struct ipv6hdr *iph, struct ipv6_sr_hdr *srh, struct radix_sid6_info *info,
            GHashTable *dev_cache_hashtable) {


    if (iph->hop_limit <= 1) {
        goto drop;
    }
    iph->hop_limit--;

    if (srh->segments_left <= 0) {
        goto drop;
    }

    srh->segments_left--;
    iph->daddr = *(srh->segments + srh->segments_left);

    void *iph_point = (void *) iph;
    void *srh_point = (void *) srh;
    void *iph2 = srh_point + (srh->hdrlen) * 8 + 8;

    struct dev_cache_struct *devCacheStruct = g_hash_table_lookup(dev_cache_hashtable, info->iif);
    if (devCacheStruct == NULL) {
        int cache_size = iph2 - iph_point;
        void *cache = malloc(cache_size);
        memset(cache, 0, cache_size);
        memcpy(cache, iph, cache_size);
        struct dev_cache_struct cacheStruct = {
                .size=cache_size,
                .cache=cache,
        };
        g_hash_table_insert(dev_cache_hashtable, info->iif, &cacheStruct);
    }

    uint32_t copy_len = (*pkt_len) - (iph2 - pkt);
    *pkt_len = (*pkt_len) - (iph2 - iph_point);
    memcpy(iph, iph2, copy_len);
    return 1;

    drop:
    return -1;

}

int end_ad6(void *pkt, uint32_t *pkt_len, struct ipv6hdr *iph, struct ipv6_sr_hdr *srh, struct radix_sid6_info *info,
            GHashTable *dev_cache_hashtable) {


    if (iph->hop_limit <= 1) {
        goto drop;
    }
    iph->hop_limit--;

    if (srh->segments_left <= 0) {
        goto drop;
    }

    srh->segments_left--;
    iph->daddr = *(srh->segments + srh->segments_left);

    void *iph_point = (void *) iph;
    void *srh_point = (void *) srh;
    void *iph2 = srh_point + (srh->hdrlen) * 8 + 8;

    struct dev_cache_struct *devCacheStruct = g_hash_table_lookup(dev_cache_hashtable, info->iif);
    if (devCacheStruct == NULL) {
        int cache_size = iph2 - iph_point;
        void *cache = malloc(cache_size);
        memset(cache, 0, cache_size);
        memcpy(cache, iph, cache_size);
        struct dev_cache_struct *cacheStruct = malloc(sizeof(struct dev_cache_struct));
        cacheStruct->size = cache_size;
        cacheStruct->cache = cache;
        g_hash_table_insert(dev_cache_hashtable, info->iif, cacheStruct);
    }

    uint32_t copy_len = (*pkt_len) - (iph2 - pkt);
    *pkt_len = (*pkt_len) - (iph2 - iph_point);
    memcpy(iph, iph2, copy_len);
    return 1;

    drop:
    return -1;

}


int encap(void *pkt, uint32_t *pkt_len, struct ipv6hdr *iph, struct radix_sid6_info *info) {
    if (iph->hop_limit <= 1) {
        goto drop;
    }
    iph->hop_limit--;

    void *iph_point = (void *) iph;
    struct ipv6_sr_hdr *srh = &info->srhNode->srh;

    uint32_t srh_len = info->srhNode->length;
    uint32_t encap_len = 40 + srh_len;
    uint32_t new_pkt_len = encap_len + *pkt_len;
    uint32_t move_len = ntohs(iph->payload_len) + 40;

    void *m1 = pkt + *pkt_len;
    void *m2 = m1 - encap_len;
    for (uint32_t i = move_len; i > 0;) {
        uint32_t j = i >= encap_len ? encap_len : i;
        memcpy(m1, m2, j);
        m1 -= j;
        m2 -= j;
        i -= j;
    }
    memcpy(iph_point + 40, srh, srh_len);
    iph->daddr = srh->segments[srh->first_segment];
    iph->nexthdr = IPPROTO_ROUTING;
    iph->payload_len = htons(ntohs(iph->payload_len) + 40 + srh_len);
    *pkt_len = new_pkt_len;
    return 1;

    drop:
    return -1;
}

int encap_inline(void *pkt, uint32_t *pkt_len, struct ipv6hdr *iph, struct radix_sid6_info *info) {
    if (iph->hop_limit <= 1) {
        goto drop;
    }
    iph->hop_limit--;

    void *iph_point = (void *) iph;
    struct ipv6_sr_hdr *srh = &info->srhNode->srh;

    uint32_t srh_len = info->srhNode->length;
    uint32_t encap_len = srh_len;
    uint32_t new_pkt_len = encap_len + *pkt_len;
    uint16_t move_len = ntohs(iph->payload_len);

    void *m1 = pkt + *pkt_len;
    void *m2 = m1 - encap_len;
    for (uint32_t i = move_len; i > 0;) {
        uint32_t j = i >= encap_len ? encap_len : i;
        memcpy(m1, m2, j);
        m1 -= j;
        m2 -= j;
        i -= j;
    }
    struct ipv6_sr_hdr *pkg_srh = iph_point + 40;
    memcpy(pkg_srh, srh, srh_len);
    pkg_srh->nexthdr = iph->nexthdr;
    iph->daddr = pkg_srh->segments[pkg_srh->first_segment];
    iph->nexthdr = IPPROTO_ROUTING;
    iph->payload_len = ntohl(iph->payload_len) + srh_len;
    *pkt_len = new_pkt_len;
    return 1;

    drop:
    return -1;
}

int end_ad4_encap(void *pkt, uint32_t *pkt_len, void *ip_hdr, struct dev_cache_struct *devCacheStruct) {
    uint32_t encap_len = devCacheStruct->size;
    void *m1 = pkt + *pkt_len;
    void *m2 = m1 - encap_len;
    uint32_t not_move_len = ip_hdr - pkt;
    uint32_t move_len = *pkt_len - not_move_len;

    for (uint32_t i = move_len; i > 0;) {
        uint32_t j = i >= encap_len ? encap_len : i;
        memcpy(m1, m2, j);
        m1 -= j;
        m2 -= j;
        i -= j;
    }
    memcpy(ip_hdr, devCacheStruct->cache, devCacheStruct->size);
    *pkt_len = *pkt_len + encap_len;
    return 1;
}
