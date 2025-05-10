#pragma once

// constants for Ethernet protocol version. No need to do le to be conversion for comparison
#define BE_ETH_PROTO_IP            8
#define BE_ETH_PROTO_IP6           56710

#define ONE_MS_IN_NS               1000000ULL   
#define TEN_MS_IN_NS               10000000ULL
#define HUNDRED_MS_IN_NS           100000000ULL
#define ONE_SEC_IN_NS              1000000000ULL
#define ONE_HOUR_IN_NS             3600000000000ULL

#define PORT_MAP_MAX_ENTRIES       412
#define IP_MAP_MAX_ENTRIES         412
#define MAX_FEATURES               6
#define MAX_TRIE_RULES             10
#define MAX_CLIENT_STAT            10000
#define MAX_STATS                  6

// Modify this definitions according to your needs!
#define TOKEN_BUCKET_CAPACITY      1000
#define TOKEN_BUCKET_RATE          5
#define TOKEN_REFILL_RATE          TEN_MS_IN_NS
#define TOKEN_EXHAUSTED_LIMIT      3
#define TOKEN_EXHAUSTED_TIME       ONE_HOUR_IN_NS // Time to block IP

enum features
{
    F_STAT_CONN,          // This feature is used to stat the incoming connections.
    F_LPM_RULE,           /* This feature is only used for subnet classes, 
                             where this part is primary than IP block. Example: IP matched in this part will not get filtered by ip block or port block.*/
    F_IP_BLOCK,           // This feature is to block ip indefinitely or a period of time
    F_PORT_BLOCK,         // This feature is to block port indefinitely or a particular period of time
    F_RATE_LIMIT,         // This feature enables rate limiting. But only works if connection tracking also enabled. It used Token Bucket algorithm to connection tracking
    F_BLOCK_IP_ON_EXHAUST,// Enable this feature if you need to block ip if it exceeded the limit of TOKEN BuckeT
    F_INVALID = -1,       // Only used in user space code 
};

enum stat_offset
{
    S_DROPS,           // Stat drops
    S_PASS,            // Stat Pass
    S_SYN,             // Stat Syn packets
    S_TCP,             // Stat number of TCP packets
    S_UDP,             // Stat number of UDP packets
    S_ICMP,            // Stat number of ICMP packets
};