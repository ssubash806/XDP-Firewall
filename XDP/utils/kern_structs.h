#pragma once

#include <linux/types.h>


// This struct is used for both ip block and port block
// expires: 0 means block indefinitely, other than 0 must represent expiration time(in monotonic format)
struct block_stats
{
    __u64 expires;
    __u64 dropped_count;
};

struct client_tuple
{
    union{
        __u32 src_ipv4;
        __u32 src_ipv6[4];
    };
    union
    {
        __u32 dest_ipv4;
        __u32 dest_ipv6[4];
    };
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

struct client_data
{
    __u64 packets;
    __u64 last_visit;
    __u32 tokens;
    __u8 times_exceeded; // This count increases, if the token bucket is empty and packet is dropped due to that.
                         // Because according to me I calculated the tokens that can be maximum utilized based on my service,
                         // If it is exceeeding this limit multiple times, then I assume that someone is sending heavy packets than needed
                         // So if ip block feature is enabled, I just add the source ip to the block list for particular amount of time, else drop here
};


// structure supports both ipv4 aand ipv6.
// For ipv4, jsut read first 4 bytes, and for ipv6 read full array
struct lpm_key_ip {
    __u32 prefixlen;
    __u8  data[16]; 
};

