#include "../header/helpers.h"

bool is_root()
{
    return geteuid() == 0 ? true : false;
}

bool do_ip_conversion(const char* ip_str, __u32 *out_ip, bool *is_ipv6)
{
    if(!convert_ipv4_to_u32(ip_str, out_ip))
    {
        if(!convert_ipv6_to_u128(ip_str, out_ip))
        {
            std::cout << "Given IP address " << ip_str << " is not valid" << std::endl;
            return false;
        }
        else
            *is_ipv6 = true;
    }
    return true;
}

bool convert_ipv4_to_u32(const char* ip_str, __u32* out_ip)
{
    if (ip_str == nullptr || out_ip == nullptr) {
        return false;
    }

    struct in_addr addr;
    int ret = inet_pton(AF_INET, ip_str, &addr);
    if (ret == 1) {
        *out_ip = addr.s_addr; 
        return true;
    } else {
        *out_ip = 0;
        return false;
    }
}

bool convert_ipv6_to_u128(const char* ip_str, __u32 out_ip[4])
{
    if (ip_str == nullptr || out_ip == nullptr)
        return false;

    struct in6_addr addr6;
    int ret = inet_pton(AF_INET6, ip_str, &addr6);
    if (ret == 1)
    {
        memcpy(out_ip, &addr6, 16);
        return true;
    }
    return false;
}


__u64 convert_duration(const char* duration, bool& error)
{
    error = false; // Default: no error

    if (duration == nullptr || strlen(duration) == 0)
    {
        error = true;
        return 0;
    }

    size_t len = strlen(duration);

    // Special case: exactly "0" without any units
    if (len == 1 && duration[0] == '0')
        return 0;

    if (len < 2)
    {
        error = true;
        return 0; 
    }

    char unit = duration[len - 1]; 

    
    char numberPart[32] = {0};
    if (len - 1 >= sizeof(numberPart))
    {
        error = true;
        return 0; 
    }
    memcpy(numberPart, duration, len - 1);
    numberPart[len - 1] = '\0';

    int num = atoi(numberPart);
    if (num <= 0)
    {
        error = true;
        return 0; 
    }

    __u64 add_ns = 0;
    switch (unit)
    {
        case 'm': // minutes
            add_ns = num * 60ULL * 1000 * 1000 * 1000;
            break;
        case 'h': // hours
            add_ns = num * 60ULL * 60 * 1000 * 1000 * 1000;
            break;
        case 'd': // days
            add_ns = num * 24ULL * 60 * 60 * 1000 * 1000 * 1000;
            break;
        default:
            error = true;
            return 0; 
    }

    using namespace std::chrono;
    auto now = duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();

    return now + add_ns;
}

__u16 convert_port_to_u16(const char* port_str)
{
    if (port_str == nullptr || std::strlen(port_str) == 0)
        return 0;

    char* endptr = nullptr;
    long port = std::strtol(port_str, &endptr, 10);

    if (*endptr != '\0' || port <= 0 || port > 65535)
        return 0;

    return static_cast<__u16>(port);
}

__u32 convert_string_to_u32(const char* input)
{
    if (input == nullptr) {
        return UINT32_MAX;
    }

    errno = 0;
    char* endptr = nullptr;
    unsigned long val = strtoul(input, &endptr, 10);

    if (errno != 0 || endptr == input || *endptr != '\0' || val > UINT32_MAX) {
        return UINT32_MAX;
    }

    return static_cast<__u32>(val);
}

int get_feature_enum_from_string(const char* feature_name)
{
    if (feature_name == nullptr) {
        return -1;
    }

    if (strcmp(feature_name, "stat_conn") == 0) {
        return F_STAT_CONN;
    }
    else if (strcmp(feature_name, "cidr_rule") == 0) {
        return F_LPM_RULE;
    }
    else if (strcmp(feature_name, "ip_block") == 0) {
        return F_IP_BLOCK;
    }
    else if (strcmp(feature_name, "port_block") == 0) {
        return F_PORT_BLOCK;
    }
    else if (strcmp(feature_name, "rate_limit") == 0) {
        return F_RATE_LIMIT;
    }
    else if (strcmp(feature_name, "block_ip_on_exhaust") == 0) {
        return F_BLOCK_IP_ON_EXHAUST;
    }

    return -1; // If no match
}

__u64 ktime_to_epoch_seconds(__u64 expires_ns) {
    using namespace std::chrono;

    // Get monotonic time (same clock used by bpf_ktime_get_ns)
    auto now_boot_ns = duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();

    // Get current epoch time
    auto now_epoch_s = system_clock::to_time_t(system_clock::now());

    // Compute offset between monotonic and epoch
    __u64 offset_ns = now_epoch_s * 1'000'000'000ULL - now_boot_ns;

    return (expires_ns + offset_ns) / 1'000'000'000ULL;  // return as epoch time in seconds
}

bool is_expired_epoch(__u64 epoch_time_sec) {
    std::time_t now = std::time(nullptr);
    return epoch_time_sec <= now;
}

std::string epoch_to_utc_string(__u64 epoch_time_sec) {
    std::time_t t = static_cast<std::time_t>(epoch_time_sec);
    std::tm utc_tm;

    gmtime_r(&t, &utc_tm);

    std::ostringstream oss;
    oss << std::put_time(&utc_tm, "%d-%m-%Y %H:%M:%S");

    return oss.str();
}

std::string epoch_to_local_string(__u64 epoch_time_sec) {
    std::time_t t = static_cast<std::time_t>(epoch_time_sec);
    std::tm local_tm;

    localtime_r(&t, &local_tm); 

    std::ostringstream oss;
    oss << std::put_time(&local_tm, "%d-%m-%Y %H:%M:%S");
    return oss.str();
}



bool u32_to_ipv4_str(char* out, size_t out_len, __u32 ip) {
    if (out == nullptr || out_len < INET_ADDRSTRLEN)
        return false;

    struct in_addr addr;
    addr.s_addr = ip;

    const char* result = inet_ntop(AF_INET, &addr, out, out_len);
    return result != nullptr;
}

void print_line(char character, int times)
{
    std::cout << std::setfill(character) << std::setw(times) << "" <<std::endl;
    std::cout << std::setfill(' ');
}