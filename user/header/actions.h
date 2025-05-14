#pragma once
#include <iostream>
#include <unordered_map>
#include <vector>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <cstring>
#include <unistd.h>
#include <array>
#include <optional>
#include "constants.h"
#include "helpers.h"
#include "../../XDP/utils/kern_structs.h"
#include "../../XDP/utils/constants.h"
#include "./helpers.h"

// IPv6 needs to be implemented in future

struct Maps
{
    std::string map_name;
    int entries;
    int key_size;
    int val_size;
};

const int IPv4_WIDTH = 15;
const int IPv6_WIDTH = 39;
const int PORT_WIDTH =  7;
const int TIME_WIDTH = 20;
const int DROP_WIDTH = 14;
const int STAT_WIDTH = 13;

class Actions
{
    private:
        std::unordered_map<std::string, int> mapFD;
        std::vector<struct Maps> loadedMaps;

    public:
        void get_maps();
        void print_loaded_maps();
        void enable_feature(__u32 feature, __u8 flag);
        void set_feature(const char* feature, const char* status);
        int get_map_fd(const char* map_name);
        bool is_feature_enabled(__u32 feature);
        void add_ip_block(const char* ip, const char* dur);
        void del_ip_block(const char* ip);
        std::vector<std::pair<__u32, struct block_stats>> get_ip_block();
        std::vector<std::pair<std::array<__u32, 4>, struct block_stats>> get_ipv6_block();
        void print_ip_block();
        void print_ipv4_block();
        void print_ipv6_block();
        std::optional<struct block_stats> get_block_stat_from_ipv4(const char* ip);
        void add_port_block(const char* port, const char* dur);
        void del_port_block(const char* port);
        std::vector<std::pair<__u16, struct block_stats>> get_port_block();
        void print_port_block();
        void add_ip_subnet(const char* ip, const char* prefix_len);
        void del_ip_subnet(const char* ip, const char* prefix_len);
        std::vector<__u64> get_overall_stat();
        void print_ip_subnets();
        void print_feature_status();
        void print_overall_stats();

        ~Actions();
};