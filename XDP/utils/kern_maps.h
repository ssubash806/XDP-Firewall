
#pragma once
#include "constants.h"
#include "kern_structs.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
// This map is only used when port map is compiled with it. 
// In key it store the port number and in value, it sets the state to allow or block.
// What we have done is, only allow the ports in this map and drop all the other ports!
// Value part is unnecessary, but doesn't have any other approaches though!
struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, struct block_stats);
    __uint(max_entries, PORT_MAP_MAX_ENTRIES);
    __uint(map_flags, 0);
} port_map SEC(".maps");

// Features can be enabled or disbled at run time based on the values in this map
struct 
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, MAX_FEATURES);
    __uint(map_flags, 0);
} feature_map SEC(".maps");

// A sepcific IP's can be blocked using this map. The value is the time it takes to expire.
// value: 0 means block indefinitely, other than 0 represents the clock monotonic until which it was supposed to be blocked!
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct block_stats);
    __uint(max_entries, IP_MAP_MAX_ENTRIES);
    __uint(map_flags, 0);
} ip_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32[4]);
    __type(value, struct block_stats);
    __uint(max_entries, IP_MAP_MAX_ENTRIES);
    __uint(map_flags, 0);
} ipv6_map SEC(".maps");

// In value part we store how many packets passed through the LPM TRIE stats for each subnet!
struct 
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key_ip);
    __type(value, __u64);
    __uint(max_entries, MAX_TRIE_RULES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_ip SEC(".maps");

// Struct to store client connections. In case if it is full then we can adjust it if needed!
// Note: IP addresses and port are stored in network byte order, so in user space program do proper conversions
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct client_tuple);
    __type(value, struct client_data);
    __uint(max_entries, MAX_CLIENT_STAT);
    __uint(map_flags, 0);
} cli_stat SEC(".maps");

// Sturct to store stat maps
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MAX_STATS);
    __uint(map_flags, 0);
} stat_map SEC(".maps");

//
//
//
//
//
// Conflicts with user space code! needs to be stored somewhere later
enum return_code
{
    SUCCESS,
    FAILURE
};