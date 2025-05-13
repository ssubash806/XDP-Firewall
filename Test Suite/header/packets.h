
#pragma once
#include <iostream>
#include <vector>
#include <bpf/bpf.h>
    

struct Test_Packets
{
    std::string input_pckt;
    int ret_val;
    std::string description;
};


const std::vector<struct Test_Packets> Packets = {
    // Ether(src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb")/ IP(src: 10.0.0.1, Dst: 192.168.1.1, tos: 0x00) / TCP(src: 12345, dst: 80, F: "S")/Hello to firewall
    {
        .input_pckt = "ZneImaq7ABEiM0RVCABFAAA5AAEAAEAGrxQKAAABwKgBATA5AFAAAAPoAAAAAFACIAA6mAAASGVsbG8gdG8gZmlyZXdhbGw=",
        .ret_val = XDP_DROP,
        .description = "TCP Packet to test port block 80"
    },
    // Ether(src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb")/ IP(src: 10.0.0.1, Dst: 192.168.1.1, tos: 0x00) / UDP(src: 12345, dst: 80)/Hello to firewall
    {
        .input_pckt = "ZneImaq7ABEiM0RVCABFAAAtAAEAAEARrxUKAAABwKgBATA5AFAAGa5qSGVsbG8gdG8gZmlyZXdhbGw=",
        .ret_val = XDP_DROP,
        .description = "UDP Packet to test port block 80"
    },
    // Ether(src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb")/ IP(src: 10.0.0.2, Dst: 192.168.1.1, tos: 0x00) / TCP(src: 12345, dst: 80, F: "S")/Hello to firewall
    {
        .input_pckt = "ZneImaq7ABEiM0RVCABFAAA5AAEAAEAGrxMKAAACwKgBATA5AFAAAAPoAAAAAFACIAA6lwAASGVsbG8gdG8gZmlyZXdhbGw=",
        .ret_val = XDP_DROP,
        .description = "TCP packet to test ip block 10.0.0.2"
    },
    // Ether(src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb")/ IP(src: 10.0.0.2, Dst: 192.168.1.1, tos: 0x00) / UDP(src: 12345, dst: 80)/Hello to firewall
    {
        .input_pckt = "ZneImaq7ABEiM0RVCABFAAAtAAEAAEARrxQKAAACwKgBATA5AFAAGa5pSGVsbG8gdG8gZmlyZXdhbGw=",
        .ret_val = XDP_DROP,
        .description = "UDP packet to test ip block 10.0.0.2"
    },
    // Ether(src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb")/ IP(src: 10.0.0.1, Dst: 192.168.1.1, tos: 0x00) / TCP(src: 12345, dst: 80, F: "S")/Hello to firewall
    {
        .input_pckt = "ZneImaq7ABEiM0RVCABFAAA5AAEAAEAGrxQKAAABwKgBATA5AFAAAAPoAAAAAFACIAA6mAAASGVsbG8gdG8gZmlyZXdhbGw=",
        .ret_val = XDP_PASS,
        .description = "IP subnetting CIDR rule enabled with port block"
    },
    // Ether(src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb")/ IP(src: 10.0.0.2, Dst: 192.168.1.1, tos: 0x00) / TCP(src: 12345, dst: 80, F: "S")/Hello to firewall
    {
        .input_pckt = "ZneImaq7ABEiM0RVCABFAAA5AAEAAEAGrxMKAAACwKgBATA5AFAAAAPoAAAAAFACIAA6lwAASGVsbG8gdG8gZmlyZXdhbGw=",
        .ret_val = XDP_PASS,
        .description = "IP subnetting CIDR rule enabled with ip block"
    },
    // Ether(src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb")/ IP(src: 10.0.0.3, Dst: 192.168.1.1, tos: 0x00) / TCP(src: 12345, dst: 80, F: "S")/Hello to firewall
    {
        .input_pckt = "ZneImaq7ABEiM0RVCABFAAA5AAEAAEAGrxIKAAADwKgBATA5AFAAAAPoAAAAAFACIAA6lgAASGVsbG8gdG8gZmlyZXdhbGw=",
        .ret_val = XDP_PASS,
        .description = "Packets test on rate limiting without rate exhause ip block"
    },
    // Ether(src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb")/ IP(src: 10.0.0.4, Dst: 192.168.1.1, tos: 0x00) / TCP(src: 12345, dst: 80, F: "S")/Hello to firewall
    {
        .input_pckt = "ZneImaq7ABEiM0RVCABFAAA5AAEAAEAGrxEKAAAEwKgBATA5AFAAAAPoAAAAAFACIAA6lQAASGVsbG8gdG8gZmlyZXdhbGw=",
        .ret_val = XDP_PASS,
        .description = "Packet to test for rate limiting with rate exhaust ip block"
    },
    // Ether(src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb")/ IP(src: 10.0.0.5, Dst: 192.168.1.1, tos: 0x00) / ICMP(type:8, code:0)/Ping test to firewall
    {
        .input_pckt = "ZneImaq7ABEiM0RVCABFAAAxAAEAAEABrx0KAAAFwKgBAQgADfsAAAAAUGluZyB0ZXN0IHRvIGZpcmV3YWxs",
        .ret_val = XDP_PASS,
        .description = "Packet to test ICMP messages"
    },
};

const std::vector<__u64> expected_stats_count = {
    12,2003,0,0,2012,2012,2,1
};