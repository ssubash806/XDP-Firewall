#pragma once

enum return_value
{
    SUCCESS,
    FAILURE
};

enum status
{
    DISABLE,
    ENABLE
};

enum maps
{
    PORT_MAP,
    FEATURE_MAP,
    IP_MAP,
    IPV6_MAP,
    LPM_IP,
    CLI_STAT,
    STAT_MAP
};


// converts the given maps to names. The map index will be get from the maps enum
const char *const maps_to_names[] = {
    "port_map",
    "feature_map",
    "ip_map",
    "ipv6_map",
    "lpm_ip",
    "cli_stat",
    "stat_map"
};

// This is from the XDP kernel program constants!
const char *const features_names[] = {
    "connection tracking",
    "IP subnetting",
    "IP blocking",
    "Port blocking",
    "Rate limiting",
    "Rate limit exceeded block"
};

// status code either enabled or disabled!
const char* const status_names[] = {
    "disabled",
    "enabled"
};

const char* const stat_labels[] = {
    "IPv4 Dropped Packets",
    "IPv4 Passed Packets",
    "IPv6 Dropped Packets",
    "IPv6 Passed Packets",
    "SYN Packets",
    "TCP Packets",
    "UDP Packets",
    "ICMP Packets"
};

enum log_level
{
    INFO,
    WARN,
    ERROR,
    DEBUG
};

const char* const log_level_to_names[] = {
    "INFO",
    "WARN",
    "ERROR",
    "DEBUG"
};