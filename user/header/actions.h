#pragma once
#include <iostream>
#include <unordered_map>
#include <vector>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <cstring>
#include <unistd.h>
#include "constants.h"
#include "helpers.h"
#include "../../XDP/utils/kern_structs.h"
#include "../../XDP/utils/constants.h"

// IPv6 needs to be implemented in future

struct Maps
{
    std::string map_name;
    int entries;
    int key_size;
    int val_size;
};


class Actions
{
    private:
        std::unordered_map<std::string, int> mapFD;
        std::vector<struct Maps> loadedMaps;

    public:
        void get_maps();
        void print_loaded_maps();
        void enable_feature(__u32 feature, __u8 flag);
        void enable_feature(const char* feature, const char* status);
        int get_map_fd(const char* map_name);
        bool is_feature_enabled(__u32 feature);
        void add_ip_block(const char* ip, const char* dur);
        void del_ip_block(const char* ip);
        std::vector<std::pair<__u32, struct block_stats>> get_ip_block();
        void print_ip_block();
        void add_port_block(const char* port, const char* dur);
        void del_port_block(const char* port);
        std::vector<std::pair<__u16, struct block_stats>> get_port_block();
        void print_port_block();
        void add_ip_subnet(const char* ip, const char* prefix_len);
        void del_ip_subnet(const char* ip, const char* prefix_len);
        void get_ip_subnet();
        void print_feature_status();

        ~Actions();
};