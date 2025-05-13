#include "../header/actions.h"



void Actions::get_maps()
{
    __u32 id = 0;
    int err = 0;

    mapFD.clear();
    loadedMaps.clear();

    while (bpf_map_get_next_id(id, &id) == 0)
    {
        struct bpf_map_info info;
        __u32 info_len = sizeof(info);
        memset(&info, 0, sizeof(info));

        int fd = bpf_map_get_fd_by_id(id);
        if (fd < 0)
            continue;

        err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
        if (err)
        {
            close(fd);
            continue;
        }

        std::string name(info.name);

        mapFD[name] = fd;

        Maps map_struct;
        map_struct.map_name = name;
        map_struct.entries = info.max_entries;
        map_struct.key_size = info.key_size;
        map_struct.val_size = info.value_size;

        loadedMaps.push_back(map_struct);
    }
}

void Actions::print_loaded_maps()
{
    for (const auto& map : loadedMaps)
    {
        std::cout << "Map Name: " << map.map_name
                  << ", Entries: " << map.entries
                  << ", Key Size: " << map.key_size
                  << ", Value Size: " << map.val_size
                  << std::endl;
    }
}

void Actions::enable_feature(__u32 feature, __u8 status)
{
    int map = FEATURE_MAP;
    int fd = get_map_fd(maps_to_names[map]);
    if(fd > 0)
    {
        int ret = bpf_map_update_elem(fd, &feature, &status, BPF_ANY);
        if(ret!=0)
        {
            std::cout << "Cannot update the " << maps_to_names[map] << " map, returned with code " << ret << std::endl;
        }
        std::cout<< "Feature: " << features_names[feature] << " " << status_names[status] << std::endl; 
    }
    else
    {
        std::cout<< "Map " << maps_to_names[map] <<" is either not loaded or not found!" << std::endl;
    }
}

void Actions::set_feature(const char* feature, const char* status)
{
    __u32 feature_off = get_feature_enum_from_string(feature);
    if(feature_off == F_INVALID)
    {
        std::cout<< "Invalid feature: " << feature << std::endl;
        return;
    }
    __u8 status_num;
    if(strcmp(status, "enable") == 0)
    {
        status_num = status::ENABLE;
    }
    else if(strcmp(status, "disable") == 0)
    {
        status_num = status::DISABLE;
    }
    else
    {
        std::cout<< "Invalid status " << status << std::endl;
        return;
    }
    
    enable_feature(feature_off, status_num);
}

int Actions::get_map_fd(const char* map_name)
{
    auto it = mapFD.find(map_name);
    if(it != mapFD.end()) 
        return it->second;
    else
        return -1;
}

bool Actions::is_feature_enabled(__u32 feature)
{
    int map = FEATURE_MAP;
    int fd = get_map_fd(maps_to_names[map]);
    __u8 value;
    if( fd > 0){
        bpf_map_lookup_elem(fd, &feature, &value);
        if(value) return true;
        else return false;
    }
    else
    {
        std::cout<< "Map " << maps_to_names[map] <<" is either not loaded or not found!" << std::endl;
        return false;
    }
}

void Actions::add_ip_block(const char* ip, const char* dur)
{
    __u32 dec_ip[4] = {0};
    bool is_ipv6 = false;
    if(!do_ip_conversion(ip, dec_ip, &is_ipv6))
        return;

    int map;
    int feature = F_IP_BLOCK;
    if(!is_ipv6)
        map = maps::IP_MAP;
    else
        map = maps::IPV6_MAP;


    int fd = get_map_fd(maps_to_names[map]);
    if(fd > 0)
    {
        bool error = false;
        __u64 dur_ns = convert_duration(dur, error);
        if(error)
        {
            std::cout << "Given duration " << dur << " is invalid" << std::endl;
            return;
        }
        struct block_stats block;
        block.expires = dur_ns;
        block.dropped_count = 0;

        int ret = bpf_map_update_elem(fd, dec_ip, &block, BPF_NOEXIST);
        if(ret == 0)
        {
            if(!is_feature_enabled(feature))
            {
                std::cout << "Warning: Feature " << features_names[feature] << " is Disabled!" << std::endl;
            }
            std::cout << "Added the ip "
                      << ip << " to be blocked for ";
            if(!dur_ns)   
                std::cout << "indefinitely!" << std::endl;
            else
                std::cout << dur << std::endl;
        }
        else if(ret == -EEXIST)
        {
            std::cout << "IP " << ip 
            << " is already available in block list." 
            << std::endl;
        }
        else
        {
            std::cout << "Cannot update the " 
                      << maps_to_names[map] 
                      << " for ip address: " 
                      << ip << ", returned with ret code " 
                      << ret << std::endl;
        }
    }
    else
    {
        std::cout<< "Map " << maps_to_names[map] <<" is either not loaded or not found!" << std::endl;
    }
}

void Actions::del_ip_block(const char* ip)
{
    __u32 dec_ip[4] = {0};
    bool is_ipv6 = false;
    if(!do_ip_conversion(ip, dec_ip, &is_ipv6))
        return;

    int map;
    int feature = F_IP_BLOCK;
    if(!is_ipv6)
        map = maps::IP_MAP;
    else
        map = maps::IPV6_MAP;

    int fd = get_map_fd(maps_to_names[map]);
    if(fd > 0)
    {
        int ret = bpf_map_delete_elem(fd, &dec_ip);
        if(ret == 0)
        {
            std::cout << "Successfully deleted " << ip 
            << " from the " << maps_to_names[map] << std::endl;
        }
        else if(ret == -ENOENT)
        {
            std::cout << "No entries found for the given ip "
                      << ip << " in " << maps_to_names[map] 
                      << ". Not deleting it." << std::endl;
        }
        else
        {
            std::cout << "Deleting " << ip << " from the "
                      << maps_to_names[map] << " Failed" << std::endl;
        }
    }
    else
    {
        std::cout<< "Map " << maps_to_names[map] <<" is either not loaded or not found!" << std::endl;
    }
}

void Actions::add_port_block(const char* port, const char* dur)
{
    int map = PORT_MAP;
    int feature = F_PORT_BLOCK;

    int fd = get_map_fd(maps_to_names[map]);
    if(fd > 0)
    {
        __u16 port_num = convert_port_to_u16(port);
        if(!port_num)
        {
            std::cout << port << " is not a valid port number!" << std::endl;
            return;
        }
        bool error = false;
        __u64 dec_dur = convert_duration(dur, error);
        if(error)
        {
            std::cout << "Given duration " << dur << " is invalid" << std::endl;
            return;
        }
        struct block_stats block;
        block.expires = dec_dur;
        block.dropped_count = 0;

        int ret = bpf_map_update_elem(fd, &port_num, &block, BPF_NOEXIST);
        if(ret == 0)
        {
            if(!is_feature_enabled(feature))
            {
                std::cout << "Warning: Feature " << features_names[feature] << " is Disabled!" << std::endl;
            }
            std::cout << "Added the port "
                      << port << " to be blocked for ";
            if(!dec_dur)   
                std::cout << "indefinitely!" << std::endl;
            else
                std::cout << dur << std::endl;
        }
        else if(ret == -EEXIST)
        {
            std::cout << "Port " << port
            << " is already available in block list." 
            << std::endl;
        }
        else
        {
            std::cout << "Cannot update the " 
                      << maps_to_names[map] 
                      << " for port: " 
                      << port << ", returned with ret code " 
                      << ret << std::endl;
        }
    }
    else
    {
        std::cout<< "Map " << maps_to_names[map] <<" is either not loaded or not found!" << std::endl;
    }
}

void Actions::del_port_block(const char* port)
{
    int map = PORT_MAP;
    int feature = F_PORT_BLOCK;

    int fd = get_map_fd(maps_to_names[map]);
    if(fd > 0)
    {
        __u16 port_num = convert_port_to_u16(port);
        if(!port_num)
        {
            std::cout << "Given Port " << port << " is not valid" << std::endl;
            return;
        }
        int ret = bpf_map_delete_elem(fd, &port_num);
        if(ret == 0)
        {
            std::cout << "Successfully deleted " << port 
            << " from the " << maps_to_names[map] << std::endl;
        }
        else if(ret == -ENOENT)
        {
            std::cout << "No entries found for the given port "
                      << port << " in " << maps_to_names[map] 
                      << ". Not deleting it." << std::endl;
        }
        else
        {
            std::cout << "Deleting " << port << " from the "
                      << maps_to_names[map] << " Failed" << std::endl;
        }
    }
    else
    {
        std::cout<< "Map " << maps_to_names[map] <<" is either not loaded or not found!" << std::endl;
    }
}

void Actions::add_ip_subnet(const char* ip, const char* prefix_len)
{
    __u32 dec_ip[4];
    bool is_ipv6 = false;
    if(!do_ip_conversion(ip, dec_ip, &is_ipv6))
        return;

    int map = maps::LPM_IP;
    int feature = features::F_LPM_RULE;

    int fd = get_map_fd(maps_to_names[map]);
    if(fd > 0)
    {
        __u32 num_prefix_len = convert_string_to_u32(prefix_len);
        if(!is_ipv6)
        {
            if(num_prefix_len > IPv4_PREFIX_LEN)
            {
                std::cout<< "prefix len either invalid or cannot be greater than 32 for IPv4!" << std::endl;
                return;
            }
        }
        else
        {
            if(num_prefix_len > IPv6_PREFIX_LEN)
            {
                std::cout<< "prefix len either invalid or cannot be greater than 128 for IPv6!" << std::endl;
                return;
            }
        }
        
        struct lpm_key_ip lpm = {
            .prefixlen = num_prefix_len,
        };
        if(!is_ipv6)
            memcpy(&lpm.data, &dec_ip, IPv4_PREFIX_LEN / 8);
        else
            memcpy(&lpm.data, &dec_ip, IPv6_PREFIX_LEN / 8);

        __u64 count = 0;
        int ret = bpf_map_update_elem(fd, &lpm, &count, BPF_NOEXIST);
        if(ret == 0)
        {
            if(!is_feature_enabled(feature))
            {
                std::cout << "Warning: Feature " << features_names[feature] << " is Disabled!" << std::endl;
            }
            std::cout << "Added the ip "
                      << ip << " wint prefix len "
                      << prefix_len << std::endl;
        }
        else if(ret == -EEXIST)
        {
            std::cout << "IP " << ip 
            << " is already available in lpm rule." 
            << std::endl;
        }
        else
        {
            std::cout << "Cannot update the " 
                      << maps_to_names[map] 
                      << " for ip address: " 
                      << ip << ", returned with ret code " 
                      << ret << std::endl;
        }    
    }
    else
    {
        std::cout<< "Map " << maps_to_names[map] <<" is either not loaded or not found!" << std::endl;
    }
}

void Actions::del_ip_subnet(const char* ip, const char* prefix_len)
{
    __u32 dec_ip[4];
    bool is_ipv6 = false;
    if(!do_ip_conversion(ip, dec_ip, &is_ipv6))
        return;
    
    int map = maps::LPM_IP;
    int feature = features::F_LPM_RULE;

    int fd = get_map_fd(maps_to_names[map]);
    if(fd > 0)
    {
        __u32 num_prefix_len = convert_string_to_u32(prefix_len);
        if(!is_ipv6)
        {
            if(num_prefix_len > IPv4_PREFIX_LEN)
            {
                std::cout<< "prefix len either invalid or cannot be greater than 32 for IPv4!" << std::endl;
                return;
            }
        }
        else
        {
            if(num_prefix_len > IPv6_PREFIX_LEN)
            {
                std::cout<< "prefix len either invalid or cannot be greater than 128 for IPv6!" << std::endl;
                return;
            }
        }
        
        struct lpm_key_ip lpm = {
            .prefixlen = num_prefix_len,
        };

        if(!is_ipv6)
            memcpy(&lpm.data, &dec_ip, IPv4_PREFIX_LEN / 8);
        else
            memcpy(&lpm.data, &dec_ip, IPv6_PREFIX_LEN / 8);
        
        int ret = bpf_map_delete_elem(fd, &lpm);
        if(ret == 0)
        {
            std::cout << "Successfully deleted " << ip 
            << " from the " << maps_to_names[map] << std::endl;
        }
        else if(ret == -ENOENT)
        {
            std::cout << "No entries found for the given ip "
                      << ip << " in " << maps_to_names[map] 
                      << ". Not deleting it." << std::endl;
        }
        else
        {
            std::cout << "Deleting " << ip << " from the "
                      << maps_to_names[map] << " Failed" << std::endl;
        } 

    }
    else
    {
        std::cout<< "Map " << maps_to_names[map] <<" is either not loaded or not found!" << std::endl;
    }
}

std::vector<std::pair<__u32, struct block_stats>> Actions::get_ip_block()
{
    int map = maps::IP_MAP;
    int map_fd = get_map_fd(maps_to_names[map]);

    std::vector<std::pair<__u32, struct block_stats>> ip_block_data;

    if(map_fd > 0)
    {
        __u32 key = 0, next_key;
        struct block_stats value;

    do {
        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
            ip_block_data.emplace_back(key, value);
        }
    } while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0 && (key = next_key, true));

    }
    else
    {
        std::cout<< "Map " << maps_to_names[map] <<" is either not loaded or not found!" << std::endl;
    }
    return ip_block_data;
}

std::vector<std::pair<__u16, struct block_stats>> Actions::get_port_block()
{
    int map = maps::PORT_MAP;
    int map_fd = get_map_fd(maps_to_names[map]);

    std::vector<std::pair<__u16, struct block_stats>> port_block_data;
    if(map_fd > 0)
    {
        __u16 key = 0, next_key;
        struct block_stats value;

        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
                port_block_data.emplace_back(next_key, value);
            }
            key = next_key;
        }
    }
    else
    {
        std::cout<< "Map " << maps_to_names[map] <<" is either not loaded or not found!" << std::endl;
    }
    return (port_block_data);
}

std::optional<struct block_stats> Actions::get_block_stat_from_ipv4(const char* ip)
{
    auto ip_stats = get_ip_block();
    if(ip_stats.empty())
    {
        return std::nullopt;
    }
    __u32 dec_ip = 0;
    if(!convert_ipv4_to_u32(ip, &dec_ip))
    {
        std::cerr << "Invalid IP provided: " << ip << std::endl;
        return std::nullopt;
    }
    for(auto& ip_stat: ip_stats)
    {
        if(ip_stat.first == dec_ip)
            return ip_stat.second;
        
    }
    return std::nullopt;
}

void Actions::print_port_block()
{
    auto port_block = get_port_block();
    int feature = F_PORT_BLOCK;
    if(!is_feature_enabled(feature))
    {
        std::cerr << "Warning: Feature port block is not enabled!" << std::endl;
    }
    if (port_block.empty())
    {
        std::cerr << "No entries found for port block" << std::endl;
        return;
    }
    for (auto &port_data : port_block)
    {
        if (port_data.second.expires == 0)
        {
            std::cout << port_data.first << " | Indefinitely"
                      << " | " << port_data.second.dropped_count
                      << " | Blocked" << std::endl;
            continue;
        }

        __u64 epoch_time = ktime_to_epoch_seconds(port_data.second.expires);
        bool is_expired = is_expired_epoch(epoch_time);
        std::string formatted_time = epoch_to_local_string(epoch_time);

        std::cout << port_data.first << " | " << formatted_time
                  << " | " << port_data.second.dropped_count
                  << " | " << (is_expired ? "Expired" : "Not Expired") << std::endl;
    }
}


void Actions::print_ip_block()
{    
    auto ip_block = get_ip_block();
    int feature = F_IP_BLOCK;
    if(!is_feature_enabled(feature))
    {
        std::cerr << "Warning: Feature IP block is not enabled!" << std::endl;
    }
    if(ip_block.empty())
    {
        std::cout << "No entries found in IP block map" << std::endl;
        return;
    }
    
    std::cout << "IP blocked status" << std::endl;
    print_line('-', 60);
    for(auto& ip: ip_block)
    {
        char ip_addr[INET_ADDRSTRLEN];
        if(!u32_to_ipv4_str(ip_addr, sizeof(ip_addr), ip.first))
        {
            std::cerr << "Conversion of " << ip.first << " to dotted decimal failed!" << std::endl;
            continue;
        }

        if(ip.second.expires == 0)
        {
            std::cout << ip_addr << " | Indefinitely"
                      << " | " << ip.second.dropped_count
                      << " | Blocked" << std::endl;
            continue;
        }

        __u64 epoch_time = ktime_to_epoch_seconds(ip.second.expires);
        bool is_expired = is_expired_epoch(epoch_time);
        std::string formatted_time = epoch_to_local_string(epoch_time);

        std::cout << ip_addr << " | " << formatted_time
                  << " | " << ip.second.dropped_count
                  << " | " << (is_expired ? "Expired" : "Not Expired") << std::endl;
    }
}

std::vector<__u64> Actions::get_overall_stat()
{
    int map = maps::STAT_MAP;
    int map_fd = get_map_fd(maps_to_names[map]);
    std::vector<__u64> stats;
    if(map_fd > 0)
    {
        for (__u32 i = 0; i <= S_ICMP; ++i)
        {
            __u64 value = 0;
            if (bpf_map_lookup_elem(map_fd, &i, &value) == 0)
            {
                stats.push_back(value);
            }
            else
            {
                std::cerr << "Failed to read stat at index " << i << std::endl;
            }
        }
    }
    
    return stats;
}

void Actions::print_feature_status()
{
    size_t num_features = sizeof(features_names) / sizeof(features_names[0]);
    std::cout << "Features List\n";
    print_line('-', 50);
    for(int i=0; i<num_features; i++)
    {
        std::cout << "Feature " << std::left << std::setw(30) 
        << features_names[i] << " : ";
        is_feature_enabled(i) ? std::cout << "Enabled" : std::cout << "Disabled";
        std::cout << std::setfill(' ') << std::endl;
    }
}

void Actions::print_ip_subnets() {
    int map = maps::LPM_IP;
    int map_fd = get_map_fd(maps_to_names[map]);
    if (map_fd < 0) {
        std::cerr << "Failed to get lpm_ip map fd" << std::endl;
        return;
    }

    struct lpm_key_ip key{}, next_key{};
    __u64 value;

    std::cout << "IP Subnet Rules:" << std::endl;
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            char ip_str[INET6_ADDRSTRLEN];
            bool is_ipv4 = (next_key.prefixlen <= 32);

            if (is_ipv4) {
                if (!inet_ntop(AF_INET, next_key.data, ip_str, sizeof(ip_str))) {
                    std::cerr << "Failed to convert IPv4 to string" << std::endl;
                    continue;
                }
            } else {
                if (!inet_ntop(AF_INET6, next_key.data, ip_str, sizeof(ip_str))) {
                    std::cerr << "Failed to convert IPv6 to string" << std::endl;
                    continue;
                }
            }

            std::cout << ip_str << "/" << static_cast<int>(next_key.prefixlen)
                      << " | " << value << std::endl;
        }
        key = next_key;
    }
}

void Actions::print_overall_stats()
{
    auto stats = get_overall_stat();
    
    if(stats.empty())
    {
        std :: cerr << "Cannot get overall stat info" << std::endl;
        return;
    }
    else
    {
        std::cout << "OVERALL STATS\n";
        print_line('-', 40);
        for(int i=S_V4_DROPS; i<S_ICMP; i++)
        {
            std::cout << std::left << std::setw(20) << stat_labels[i] << " : " << stats[i] << std::endl;
        }
    }
}


Actions::~Actions()
{
    // close the map fd's if it is open
    for(auto& [name, fd] : mapFD)
    {
        if(fd)
            close(fd);
    }
}
