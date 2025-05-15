#pragma once
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/string.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include "constants.h"
#include "kern_maps.h"

static __always_inline __u8 get_ethhdr(struct ethhdr** eth, void* packet_start, void* packet_end)
{
    *eth = (struct ethhdr*) packet_start;
    if(((void*)(*eth + 1)) > packet_end)
    {
        return FAILURE;
    }
    return SUCCESS;
}

static __always_inline __u16 get_ip_proto(struct ethhdr* eth)
{
    return eth->h_proto;
}

static __always_inline __u8 get_iphdr(void** ip_hdr, void* packet_start, void* packet_end, bool is_ipv6)
{
    if(is_ipv6)
    {
        struct ipv6hdr* ipv6 = NULL;
        ipv6 = (struct ipv6hdr*)(packet_start + sizeof(struct ethhdr));
        if((void*)(ipv6 + 1) > packet_end)
            return FAILURE;
        *ip_hdr = ipv6;
    }
    else
    {
        struct iphdr* ipv4hdr = NULL;
        ipv4hdr = (struct iphdr*)(packet_start + sizeof(struct ethhdr));
        if((void*)(ipv4hdr + 1) > packet_end)
        {
            return FAILURE;
        }
        *ip_hdr = ipv4hdr;
    }
    return SUCCESS;
}


static __always_inline __u8 parse_ipv6_ext_hdrs(__u8 nexthdr, void** hdr_pos, void* data_end) {
    struct ipv6_opt_hdr *ext_hdr;

    while (1) {
        if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP || nexthdr == IPPROTO_ICMPV6) {
            return nexthdr;
        }

        ext_hdr = (struct ipv6_opt_hdr *)(*hdr_pos);
        if ((void*)(ext_hdr + 1) > data_end) {
            return 0; 
        }

        __u8 hdrlen = ext_hdr->hdrlen;
        *hdr_pos = (void*)ext_hdr + (hdrlen + 1) * 8;

        if (*hdr_pos >= data_end) {
            return 0;
        }

        nexthdr = ext_hdr->nexthdr;
    }
}

static __always_inline __u8 get_tcphdr(struct tcphdr** tcp, void* packet_start, void* packet_end, bool is_ipv6)
{
    if (!is_ipv6) {
        *tcp = (struct tcphdr*)(packet_start + sizeof(struct ethhdr) + sizeof(struct iphdr));
    } else {
        void* hdr_pos = packet_start + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        struct ipv6hdr* ip6h = (struct ipv6hdr*)(packet_start + sizeof(struct ethhdr));
        __u8 final_hdr = parse_ipv6_ext_hdrs(ip6h->nexthdr, &hdr_pos, packet_end);
        if (final_hdr != IPPROTO_TCP)
            return FAILURE;

        *tcp = (struct tcphdr*)hdr_pos;
    }

    if ((void*)(*tcp + 1) > packet_end)
        return FAILURE;

    return SUCCESS;
}

static __always_inline __u8 get_udphdr(struct udphdr** udp, void* packet_start, void* packet_end, bool is_ipv6)
{
    if (!is_ipv6) {
        *udp = (struct udphdr*)(packet_start + sizeof(struct ethhdr) + sizeof(struct iphdr));
    } else {
        void* hdr_pos = packet_start + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        struct ipv6hdr* ip6h = (struct ipv6hdr*)(packet_start + sizeof(struct ethhdr));
        __u8 final_hdr = parse_ipv6_ext_hdrs(ip6h->nexthdr, &hdr_pos, packet_end);
        if (final_hdr != IPPROTO_UDP)
            return FAILURE;

        *udp = (struct udphdr*)hdr_pos;
    }

    if ((void*)(*udp + 1) > packet_end)
        return FAILURE;

    return SUCCESS;
}

static __always_inline __u8 get_icmphdr(void** icmp, void* packet_start, void* packet_end, bool is_ipv6)
{
    if (!is_ipv6) {
        *icmp = (void*)(packet_start + sizeof(struct ethhdr) + sizeof(struct iphdr));
    } else {
        void* hdr_pos = packet_start + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        struct ipv6hdr* ip6h = (struct ipv6hdr*)(packet_start + sizeof(struct ethhdr));
        __u8 final_hdr = parse_ipv6_ext_hdrs(ip6h->nexthdr, &hdr_pos, packet_end);
        if (final_hdr != IPPROTO_ICMPV6)
            return FAILURE;

        *icmp = hdr_pos;
    }

    // Ensure entire header fits within bounds
    if (!is_ipv6) {
        if ((void*)((struct icmphdr*)(*icmp) + 1) > packet_end)
            return FAILURE;
    } else {
        if ((void*)((struct icmp6hdr*)(*icmp) + 1) > packet_end)
            return FAILURE;
    }

    return SUCCESS;
}


static __always_inline __u16 get_dest_port(void* transport_hdr, __u8 ip_protocol)
{
    if(ip_protocol == IPPROTO_TCP)
    {
        struct tcphdr* tcp = (struct tcphdr*) transport_hdr;
        return tcp->dest;
    }
    else if(ip_protocol == IPPROTO_UDP)
    {
        struct udphdr* udp = (struct udphdr*) transport_hdr;
        return udp->dest;
    }
    return 0;
}

static __always_inline __u16 get_src_port(void* transport_hdr, __u8 ip_protocol)
{
    if(ip_protocol == IPPROTO_TCP)
    {
        struct tcphdr* tcp = (struct tcphdr*) transport_hdr;
        return tcp->source;
    }
    else if(ip_protocol == IPPROTO_UDP)
    {
        struct udphdr* udp = (struct udphdr*) transport_hdr;
        return udp->source;
    }
    return 0;
}

static __always_inline __u8 is_feature_enabled(__u32 feature)
{
    __u8 *enabled = (__u8*)bpf_map_lookup_elem(&feature_map, &feature);
    return enabled && *enabled == 1;
}

static __always_inline void build_tuple(struct client_tuple *client,
                                        void* ip_hdr,
                                        void* trans_hdr,
                                        int is_ipv6)
{
    memset(client, 0, sizeof(*client));
    __u8 trans_protocol;
    if(is_ipv6)
    {
        struct ipv6hdr* ipv6_hdr = (struct ipv6hdr*) ip_hdr;
        memcpy(client->src_ipv6, &ipv6_hdr->saddr, sizeof((*client).src_ipv6));
        memcpy(client->dest_ipv6, &ipv6_hdr->daddr, sizeof((*client).dest_ipv6));
        client->protocol = ipv6_hdr->nexthdr;
        trans_protocol = ipv6_hdr->nexthdr;
    }
    else
    {
        struct iphdr* ipv4_hdr = (struct iphdr*) ip_hdr;
        client->src_ipv4 = ipv4_hdr->saddr;
        client->dest_ipv4 = ipv4_hdr->daddr;
        client->protocol = ipv4_hdr->protocol;
        trans_protocol = ipv4_hdr->protocol;
    }
    if(trans_protocol == IPPROTO_TCP)
    {
        struct tcphdr* tcp = (struct tcphdr*) trans_hdr;
        client->src_port = tcp->source;
        client->dst_port = tcp->dest;
    }
    else if(trans_protocol == IPPROTO_UDP)
    {
        struct udphdr* udp = (struct udphdr*) trans_hdr;
        client->src_port = udp->source;
        client->dst_port = udp->dest;
    }
}

static __always_inline __u8 update_stat(void* ip_hdr, void* transport_hdr, __u64* curr_time, bool is_ipv6)
{
    struct client_tuple client;
    build_tuple(&client, ip_hdr, transport_hdr, is_ipv6);

    // first lookup in the map
    struct client_data *data = (struct client_data *)bpf_map_lookup_elem(&cli_stat, &client);
    if (data == NULL)
    {
        struct client_data new_data = {
            .packets = 1,
            .last_visit = *curr_time,
            .tokens = TOKEN_BUCKET_CAPACITY,
            .times_exceeded = 0,
        };
        bpf_map_update_elem(&cli_stat, &client, &new_data, BPF_ANY);
    }
    else
    {
        data->packets = data->packets + 1;
        // We use last_visit, tokens and times_exceeded only if the feature Rate limiting is enabled!
    }
    return XDP_CONTINUE;
}


static __always_inline __u8 is_port_allowed(void* transport_hdr, __u8 ip_proto, __u64 *curr_time)
{
    __u16 dest_port = bpf_htons(get_dest_port(transport_hdr, ip_proto));
    
    if(!dest_port)
        return XDP_DROP;
    
    struct block_stats* stat = (struct block_stats*)bpf_map_lookup_elem(&port_map, &dest_port);

    if(stat != NULL)
    {
        // We have to block indefinitely or until expiration time or block indefinitely if it is 0
        if((stat->expires == 0) || (*curr_time < stat->expires))
        {
            stat->dropped_count++;
            return XDP_DROP;
        }
    }
    return XDP_CONTINUE;
}

static __always_inline __u8 is_ip_allowed(void* src_ip, __u64 *curr_time, bool is_ipv6)
{
    struct block_stats* stat = NULL;
    if(!is_ipv6)
        stat = (struct block_stats*)bpf_map_lookup_elem(&ip_map, src_ip);
    else
        stat = (struct block_stats*)bpf_map_lookup_elem(&ipv6_map, src_ip);

    if(stat != NULL)
    {
        // If it is already 0, then block indefinitely or until expiration time
        if((stat->expires == 0) || (*curr_time < stat->expires))
        {
            stat->dropped_count++;
            return XDP_DROP;
        }
    }
    return XDP_CONTINUE;
}

static __always_inline int check_and_consume_token(struct client_data *data, __u64* now, void* src_ip, bool is_ipv6)
{

    if(data == NULL)
        return 1;
    __u64 elapsed_ns = *now - data->last_visit;
    __u64 new_tokens = (elapsed_ns / TOKEN_REFILL_RATE) * TOKEN_BUCKET_RATE;
        
    data->tokens += new_tokens;
        
    if (data->tokens > TOKEN_BUCKET_CAPACITY) {
        data->tokens = TOKEN_BUCKET_CAPACITY;
    }
        
    data->last_visit = *now;
        

    if (data->tokens > 0) {
        data->tokens--;
        return XDP_CONTINUE;
    } else {
        data->times_exceeded++;
        // If it is exceeded the limit, then we add that IP address to the block list for some time
        if(is_feature_enabled(F_BLOCK_IP_ON_EXHAUST) && is_feature_enabled(F_IP_BLOCK)){
            if(data->times_exceeded >= TOKEN_EXHAUSTED_LIMIT)
            {
                __u64 deadline = *now + TEN_MS_IN_NS;
                struct block_stats block;
                memset(&block, 0, sizeof(block));
                block.expires = deadline;
                block.dropped_count = 0;
                if(is_ipv6)
                    bpf_map_update_elem(&ipv6_map, src_ip, &block, BPF_ANY);
                else
                    bpf_map_update_elem(&ip_map, src_ip, &block, BPF_ANY);
            }
        }
        return XDP_DROP;
    }
    return XDP_CONTINUE;
}


static __always_inline void update_stat_map(__u32 offset)
{
    __u64* stat = (__u64*)bpf_map_lookup_elem(&stat_map, &offset);
    if(stat != NULL)
    {
        *stat = *stat + 1;
    }
}

static __always_inline __u8 handle_lpm(void* src_ip, void* ip_hdr, __u32 prefix_len,
                                       __u8 ip_proto, void* l4hdr, __u64* curr_time, bool is_ipv6)
{
    struct lpm_key_ip lpm = {
        .prefixlen = prefix_len,
    };

    memcpy(lpm.data, src_ip, prefix_len / 8);  
    __u64* count = (__u64*)bpf_map_lookup_elem(&lpm_ip, &lpm);
    if(count != NULL)
    {
        *count = *count + 1;
        // We stat this LPM subnets also if this feature is enabled
        if(is_feature_enabled(F_STAT_CONN))
        {
            update_stat((void*)ip_hdr, (void*)l4hdr, curr_time, is_ipv6);
        }
        return XDP_PASS;
    }
    return XDP_CONTINUE;
}

static __always_inline __u8 handle_ip_block(void* ip_hdr, __u64 * curr_time, bool is_ipv6)
{
    
    if(!is_ipv6)
    {
        __be32 src_ip;
        struct iphdr* ip = (struct iphdr*) ip_hdr;
        memcpy(&src_ip, &ip->saddr, 4);
        return is_ip_allowed(&src_ip, curr_time, is_ipv6);
    }
    else
    {
        __be32 src_ip[4] = {0};
        struct ipv6hdr* ipv6 = (struct ipv6hdr*) ip_hdr;
        memcpy(src_ip, &ipv6->saddr, 16);
        return is_ip_allowed(&src_ip, curr_time, is_ipv6);
    }
}

static __always_inline __u8 handle_port_block(void* trans_hdr, __u8 ip_proto, __u64* curr_time)
{
    return is_port_allowed(trans_hdr, ip_proto, curr_time);
}

static __always_inline __u8 handle_stat_conn(void* ip_hdr, void* trans_hdr, __u64* curr_time, bool is_ipv6)
{
    return update_stat(ip_hdr, trans_hdr, curr_time, is_ipv6);
}

static __always_inline __u8 handle_rate_limit(void* ip_hdr, void* trans_hdr, __u64 *curr_time, bool is_ipv6)
{
    if(!is_feature_enabled(F_STAT_CONN))
        return XDP_CONTINUE;
    
    struct client_tuple tuple;
    
    build_tuple(&tuple, (void*)ip_hdr, (void*)trans_hdr, is_ipv6);
    struct client_data *c_data = (struct client_data *)bpf_map_lookup_elem(&cli_stat, &tuple);
    
    if(c_data != NULL)
    {
        if(!is_ipv6)
        {
            __be32 src_ip;
            struct iphdr* ip = (struct iphdr*) ip_hdr;
            memcpy(&src_ip, &ip->saddr, 4);
            return check_and_consume_token(c_data, curr_time, &src_ip, false);
        }
        else
        {
            __be32 src_ip[4] = {0};
            struct ipv6hdr* ipv6 = (struct ipv6hdr*) ip_hdr;
            memcpy(src_ip, &ipv6->saddr, 16);
            return check_and_consume_token(c_data, curr_time, src_ip, true);
        }
    }

    return XDP_CONTINUE;
}