#include "utils/helpers.h"

static __always_inline __u8 filter_ipv4(struct xdp_md* packet)
{
    void* pckt_start = (void*)(long)packet->data;
    void* pckt_end   = (void*)(long)packet->data_end;
    
    struct iphdr* ip_hdr = NULL;
    if(get_iphdr((void**)&ip_hdr, pckt_start, pckt_end, false))
    {
        return XDP_DROP;
    }

    __u8 ip_proto = ip_hdr->protocol;

    struct tcphdr* tcp_hdr = NULL;
    struct udphdr* udp = NULL;
    struct icmphdr* icmp_hdr = NULL;
    void* trans_hdr = NULL;

    switch(ip_proto)
    {
        case IPPROTO_TCP:
            if(get_tcphdr(&tcp_hdr, pckt_start, pckt_end, false) == FAILURE)
            {
                return XDP_DROP;
            }
            trans_hdr = tcp_hdr;
            if(tcp_hdr->syn)
                update_stat_map(S_SYN);
            update_stat_map(S_TCP);
            break;
        
        case IPPROTO_UDP:
            if(get_udphdr(&udp, pckt_start, pckt_end, false) == FAILURE)
            {
                return XDP_DROP;
            }
            trans_hdr = udp;
            update_stat_map(S_UDP);
            break;
        
        case IPPROTO_ICMP:
            if(get_icmphdr((void*)&icmp_hdr, pckt_start, pckt_end, false) == FAILURE)
            {
                return XDP_DROP;
            }
            trans_hdr = (void*) icmp_hdr;
            update_stat_map(S_ICMP);
            break;
        
        default:
            return XDP_PASS;
    }

    __u64 curr_time = bpf_ktime_get_ns();

    if(trans_hdr == NULL)
        return XDP_DROP;

    // we need to handle ICMP flood and SYN flood in future
    if(ip_proto == IPPROTO_ICMP)
        return XDP_PASS;

    if(is_feature_enabled(F_LPM_RULE))
    {
        if(handle_lpm(&ip_hdr->saddr, (void*)ip_hdr, IPv4_PREFIX_LEN, 
                      ip_proto, trans_hdr, &curr_time, false) == XDP_PASS)
            return XDP_PASS;
    }

    if(is_feature_enabled(F_IP_BLOCK))
    {
        if(handle_ip_block((void*)ip_hdr, &curr_time, false) == XDP_DROP){
            return XDP_DROP;
        }
    }

    if(is_feature_enabled(F_PORT_BLOCK))
    {
        if(handle_port_block(trans_hdr, ip_proto, &curr_time) == XDP_DROP)
        {
            return XDP_DROP;
        }
    }

    if(is_feature_enabled(F_STAT_CONN))
    {
        handle_stat_conn((void*)ip_hdr, (void*)trans_hdr, &curr_time, false);
    }

    if(is_feature_enabled(F_RATE_LIMIT))
    {
        if(handle_rate_limit(ip_hdr, trans_hdr, &curr_time, false) == XDP_DROP){
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

static __always_inline int filter_ipv6(struct xdp_md* packet)
{
    void* pckt_start = (void*)(long)packet->data;
    void* pckt_end   = (void*)(long)packet->data_end;
    
    struct ipv6hdr* ip_hdr = NULL;
    if(get_iphdr((void**)&ip_hdr, pckt_start, pckt_end, true))
    {
        return XDP_DROP;
    }

    __u8 ip_proto = ip_hdr->nexthdr;

    struct tcphdr* tcp_hdr = NULL;
    struct udphdr* udp = NULL;
    void* trans_hdr = NULL;

    switch(ip_proto)
    {
        case IPPROTO_TCP:
            if(get_tcphdr(&tcp_hdr, pckt_start, pckt_end, true) == FAILURE)
            {
                return XDP_DROP;
            }
            trans_hdr = (void*) tcp_hdr;
            if(tcp_hdr->syn)
                update_stat_map(S_SYN);
            update_stat_map(S_TCP);
            break;
        
        case IPPROTO_UDP:
            if(get_udphdr(&udp, pckt_start, pckt_end, true) == FAILURE)
            {
                return XDP_DROP;
            }
            trans_hdr = (void*) udp;
            update_stat_map(S_UDP);
            break;
        
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            update_stat_map(S_ICMP);
            break;
        
        default:
            return XDP_PASS;
    }

    __u64 curr_time = bpf_ktime_get_ns();

    if(ip_proto == IPPROTO_ICMPV6 || ip_proto == IPPROTO_ICMP)
        return XDP_PASS;

    if(trans_hdr == NULL)
        return XDP_DROP;

    if(is_feature_enabled(F_LPM_RULE))
    {
        __u32 src_ip[4] = {0};
        memcpy(src_ip, &ip_hdr->saddr, sizeof(src_ip[0]) * 4);
        if(handle_lpm(src_ip, ip_hdr, IPv6_PREFIX_LEN, ip_proto, trans_hdr, &curr_time, true) == XDP_PASS)
            return XDP_PASS;
    }

    if(is_feature_enabled(F_IP_BLOCK))
        if(handle_ip_block((void*)ip_hdr, &curr_time, true) == XDP_DROP)
            return XDP_DROP;
    

    if(is_feature_enabled(F_PORT_BLOCK))
    {
        if(handle_port_block(trans_hdr, ip_proto, &curr_time) == XDP_DROP)
            return XDP_DROP;
    }

    if(is_feature_enabled(F_STAT_CONN))
    {
        handle_stat_conn(ip_hdr, trans_hdr, &curr_time, true);
    }

    if(is_feature_enabled(F_RATE_LIMIT))
    {
        if(handle_rate_limit(ip_hdr, trans_hdr, &curr_time, true) == XDP_DROP)
            return XDP_DROP;
    }

    exit:
    return XDP_PASS;
}

SEC("xdp")
int ingress_filter(struct xdp_md* packet)
{
    void* pckt_start = (void*)(long)packet->data;
    void* pckt_end   = (void*)(long)packet->data_end;
    
    struct ethhdr* eth_hdr = NULL;
    if(get_ethhdr(&eth_hdr, pckt_start, pckt_end))
    {
        return XDP_DROP;
    }

    __be16 eth_proto = get_ip_proto(eth_hdr);

    if(eth_proto == BE_ETH_PROTO_IP)
    {
        __u8 ret = filter_ipv4(packet);
        if(ret  == XDP_DROP)
        {
            update_stat_map(S_V4_DROPS);
        }
        else if(ret == XDP_PASS)
        {
            update_stat_map(S_V4_PASS);
        }
        return ret;
    }
    else if(eth_proto == BE_ETH_PROTO_IP6)
    {
        __u8 ret = filter_ipv6(packet);
        if (ret == XDP_DROP)
        {
            update_stat_map(S_V6_DROPS);
        }
        else if(ret == XDP_PASS)
        {
            update_stat_map(S_V6_PASS);
        }
        return ret;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";