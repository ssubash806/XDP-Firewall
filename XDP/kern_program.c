
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
#include "utils/constants.h"
#include "utils/kern_maps.h"
#include "utils/kern_structs.h"
#include "utils/helpers.h"

static __always_inline __u8 is_port_allowed(void* transport_hdr, __u8 ip_proto, __u64 *curr_time)
{
    __u16 dest_port = bpf_htons(get_dest_port(transport_hdr, ip_proto));
    
    if(!dest_port)
        return FAILURE;
    
    struct block_stats* stat = bpf_map_lookup_elem(&port_map, &dest_port);
    
    if(stat != NULL)
    {
        // We have to block indefinitely or until expiration time or block indefinitely if it is 0
        if((stat->expires == 0) || (*curr_time < stat->expires))
        {
            stat->dropped_count++;
            return FAILURE;
        }
    }
    return SUCCESS;
}

static __always_inline __u8 is_ip_allowed(__be32* src_ip, __u64 *curr_time)
{
    
    struct block_stats* stat = bpf_map_lookup_elem(&ip_map, src_ip);
    if(stat != NULL)
    {
        // If it is already 0, then block indefinitely or until expiration time
        if((stat->expires == 0) || (*curr_time < stat->expires))
        {
            stat->dropped_count++;
            return FAILURE;
        }
    }
    return SUCCESS;
}

static __always_inline void update_stat(void* ip_hdr, void* transport_hdr, __u64* curr_time, bool is_ipv6)
{
    struct client_tuple client;
    build_tuple(&client, ip_hdr, transport_hdr, is_ipv6);

    // first lookup in the map
    struct client_data *data = (struct client_data *)bpf_map_lookup_elem(&cli_stat, &client);
    if (data == NULL)
    {
        struct client_data new_data = {
            .last_visit = *curr_time,
            .packets = 1,
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
}

static __always_inline int check_and_consume_token(struct client_data *data, __u64* now, __u32* src_ip)
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
        return 0;
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
                bpf_map_update_elem(&ip_map, src_ip, &block, BPF_ANY);
            }
        }
    }
    return 0;
}


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

    switch(ip_proto)
    {
        case IPPROTO_TCP:
            if(get_tcphdr(&tcp_hdr, pckt_start, pckt_end, false) == FAILURE)
            {
                return XDP_DROP;
            }
            if(tcp_hdr->syn)
                update_stat_map(S_SYN);
            update_stat_map(S_TCP);
            break;
        
        case IPPROTO_UDP:
            if(get_udphdr(&udp, pckt_start, pckt_end, false) == FAILURE)
            {
                return XDP_DROP;
            }
            update_stat_map(S_UDP);
            break;
        
        case IPPROTO_ICMP:
            update_stat_map(S_ICMP);
            break;
        
        default:
            return XDP_PASS;
    }

    __u64 curr_time = bpf_ktime_get_ns();

    if(is_feature_enabled(F_LPM_RULE))
    {
        struct lpm_key_ip lpm = {
            .prefixlen = 32,
        };

        memcpy(lpm.data, &ip_hdr->saddr, 4);
        __u64* count = bpf_map_lookup_elem(&lpm_ip, &lpm);
        
        if(count != NULL)
        {
            *count = *count + 1;
            
            // We stat this LPM subnets also if this feature is enabled
            if(is_feature_enabled(F_STAT_CONN))
            {
                if(ip_proto == IPPROTO_TCP)
                    update_stat((void*)ip_hdr, (void*)tcp_hdr, &curr_time, false);
                else if(ip_proto == IPPROTO_UDP)
                    update_stat((void*)ip_hdr, (void*)udp, &curr_time, false);
            }
            return XDP_PASS;
        }
    }

    if(is_feature_enabled(F_IP_BLOCK))
    {
        __be32 src_ip = ip_hdr->saddr;
        if(is_ip_allowed(&src_ip, &curr_time) == FAILURE)
        {
            bpf_printk("%u dropped", src_ip);
            return XDP_DROP;
        }
    }

    if(is_feature_enabled(F_PORT_BLOCK))
    {
        if(ip_proto == IPPROTO_TCP)
        {
            // use ! if only the ports in the map to be blocked. In reverse, if only need to allow the ports in the map, just remove !
            if(is_port_allowed((void*)tcp_hdr, ip_proto, &curr_time) == FAILURE)
            {
                return XDP_DROP;
            }
        }
        if(ip_proto == IPPROTO_UDP)
        {
            // use ! if only the ports in the map to be blocked. In reverse, if only need to allow the ports in the map, just remove !
            if(is_port_allowed((void*)udp, ip_proto, &curr_time) == FAILURE)
            {
                return XDP_DROP;
            }
        }
    }

    if(is_feature_enabled(F_STAT_CONN))
    {
        if(ip_proto == IPPROTO_TCP)
            update_stat((void*)ip_hdr, (void*)tcp_hdr, &curr_time, false);
        else if(ip_proto == IPPROTO_UDP)
            update_stat((void*)ip_hdr, (void*)udp, &curr_time, false);
    }

    if(is_feature_enabled(F_RATE_LIMIT))
    {
        if(!is_feature_enabled(F_STAT_CONN))
            goto exit;
        
        if(get_tcphdr(&tcp_hdr, pckt_start, pckt_end, false))
        {
            return XDP_PASS;
        }
        struct client_tuple tuple;
        
        build_tuple(&tuple, (void*)ip_hdr, (void*)tcp_hdr, false);
        struct client_data *c_data = (struct client_data *)bpf_map_lookup_elem(&cli_stat, &tuple);
        
        if(c_data != NULL)
        {
            check_and_consume_token(c_data, &curr_time, &ip_hdr->saddr);
        }
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
            update_stat_map(S_DROPS);
        }
        else if(ret == XDP_PASS)
        {
            update_stat_map(S_PASS);
        }
        return ret;
    }
    else if(eth_proto == BE_ETH_PROTO_IP6)
    {
        //Needs to be implemented yet!
        //return filter_ipv6(pckt_start, pckt_end);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";