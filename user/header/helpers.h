
#pragma once
#include <iostream>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <ctime>
#include <cstdint>
#include <cstring>
#include "../../XDP/utils/constants.h"
#include <cstdlib>

/* If the program runs with user privileges, then returns true, else false */
bool is_root();

/* Converts the ipv4 to __u32 in network byte order.
   Returns true, if conversion successfull, else returns false
   Param 1: ip address in decimal notation
   Param 2: pointer to the converted decimal to be stored*/
bool convert_ipv4_to_u32(const char* ip_str, __u32* out_ip);

bool convert_ipv6_to_u128(const char* ip_str, __u32 out_ip[4]);

/* Given the duration in 3 different formats as: 
   xm for minute
   xh for hour
   xd for day
   Where x represents integreal value
   
   If the given argument is valid, then it converts the given time into ns, then adds it to the system boot and returns the value
   Ex for 1d: (system boot time) + (1d in ns)


   If conversion fails it returns 0 and set the error value to true*/
__u64 convert_duration(const char* duration, bool& error);

/* Function that takes port number as const char*
   and returns the port number in int format.
   If port number not valid, then it returns -1*/
__u16 convert_port_to_u16(const char* port_str);


/* Function converts the given string into a __u32 number.
   If it is not valid or conversion failed, it returns UINT32MAX, it will be failed in the rule function itself
   else it returns the number*/
__u32 convert_string_to_u32(const char* input);


/* convret feature names into enum indexes */
int get_feature_enum_from_string(const char* feature_name);

// Converts the nanoseconds time since ssytem boot into a epoch time
__u64 ktime_to_epoch_seconds(__u64 expires_ns);

// Gets the epoch time and return true if it is expired else false
bool is_expired_epoch(__u64 epoch_time_sec);

// Convert epoch time into human readable string in the following format:
// 18-05-2025 05:45:26 in railway time 
std::string epoch_to_utc_string(__u64 epoch_time_sec);

// Convert to local time of system intead of UTC and functions same as above
std::string epoch_to_local_string(__u64 epoch_time_sec);

// Convert the u32 ipv4 into dotted decimal and store it in the passed char array
bool u32_to_ipv4_str(char* out, size_t out_len, __u32 ip);

void print_line(char character, int times);