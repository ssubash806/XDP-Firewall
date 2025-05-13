
#pragma once

#include <iostream>
#include "../../user/header/actions.h"
#include "./Base64.h"
#include "./packets.h" 

class Test
{
    private:
        int prog_fd;
        std::vector<bool> test_results;
        std::vector<__u64> overall_stats;
        bool send_packet(struct Test_Packets meta_packet, bool do_print_pckt, int repititions);

    public:
        Test(int);
        void set_prog_fd(int);
        void start_test();
        void print_results();
        
};