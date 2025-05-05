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

static __always_inline __u8 get_tcphdr(struct tcphdr** tcp, void* packet_start, void* packet_end, bool is_ipv6)
{
    if(is_ipv6)
    {
        *tcp = (struct tcphdr*) (packet_start + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
    }
    else
    {
        *tcp = (struct tcphdr*) ( packet_start + sizeof(struct ethhdr) + sizeof(struct iphdr));
    }
    if((void*)(*tcp + 1) > packet_end)
    {
        return FAILURE;
    }
    return SUCCESS;
}

static __always_inline __u8 get_udphdr(struct udphdr** udp, void* packet_start, void* packet_end, bool is_ipv6)
{
    if(is_ipv6)
    {
        *udp = (struct udphdr*) (packet_start + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
    }
    else
    {
        *udp = (struct udphdr*) ( packet_start + sizeof(struct ethhdr) + sizeof(struct iphdr));
    }
    if((void*)(*udp + 1) > packet_end)
    {
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

static __always_inline void update_stat_map(__u32 offset)
{
    __u64* stat = bpf_map_lookup_elem(&stat_map, &offset);
    if(stat != NULL)
    {
        *stat = *stat + 1;
    }
}