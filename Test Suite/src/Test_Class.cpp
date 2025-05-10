#include "../header/Test_Class.h"

Test::Test(int prog_fd)
{
    this->prog_fd = prog_fd;
}

void Test::set_prog_fd(int prog_fd)
{
    this->prog_fd = prog_fd;
}

bool Test::send_packet(struct Test_Packets meta_packet, 
                       bool do_print_pckt = false, 
                       int repititions = 1)
{

    bpf_test_run_opts test_struct;
    memset(&test_struct, 0, sizeof(test_struct));
    
    std::string packet = meta_packet.input_pckt;
    std::string decoded_pckt = base64Decode(packet);

    char output_pckt[decoded_pckt.length()];

    test_struct.data_in = decoded_pckt.c_str();
    test_struct.data_out = output_pckt;
    test_struct.sz = sizeof(test_struct);
    test_struct.data_size_in = decoded_pckt.length();
    test_struct.data_size_out = decoded_pckt.length();
    test_struct.repeat = repititions;

    if(bpf_prog_test_run_opts(this->prog_fd, &test_struct) != 0)
    {
        std::cerr << "Error in running the test with packet" << std::endl;
        return false;
    }

    if(meta_packet.ret_val == test_struct.retval)
        return true;
    
    return false;

}

void Test::start_test()
{
    if(!prog_fd)
    {
        std::cerr << "Program FD not set." << std::endl;
        return;
    }

    Actions action;
    action.get_maps();
    action.set_feature("stat_conn", "enable");

    action.set_feature("port_block", "enable");
    action.add_port_block("80", "1m");
    test_results.emplace_back(send_packet(Packets[0]));
    test_results.emplace_back(send_packet(Packets[1]));
    
    // We are disabling and enabling port blocks, so that we can isloate the return value of IP block alone
    // Even some how on code changes IP block allows blocked IP, port block to 80, drops it which means the return value is always XDP_DROP, but due to port block not IP block
    action.set_feature("port_block", "disable");
    action.set_feature("ip_block", "enable");
    action.add_ip_block("10.0.0.2", "1m");
    test_results.emplace_back(send_packet(Packets[2]));
    test_results.emplace_back(send_packet(Packets[3]));
    action.set_feature("port_block", "enable");

    action.set_feature("cidr_rule", "enable");
    action.add_ip_subnet("10.0.0.0", "24");
    test_results.emplace_back(send_packet(Packets[4]));
    // We do this, because IP block is first being checked in XDP program.
    // We needed to make sure that it didn't hit port_block too
    action.set_feature("ip_block", "disable");
    test_results.emplace_back(send_packet(Packets[5]));

    // Remove the LPM rule and port block to allow packets to reach rate limiting section
    action.del_ip_subnet("10.0.0.0", "24");
    action.del_port_block("80");

    // If rate limiting alone enabled the IP should not be blocked
    action.set_feature("rate_limit", "enable");
    send_packet(Packets[6], false, 1004);
    if(action.get_block_stat_from_ipv4("10.0.0.3").has_value())
        test_results.emplace_back(false);
    else
        test_results.emplace_back(true);

    // If block_ip_on_ehaust enabled IP should be blocked
    action.set_feature("ip_block", "enable");
    action.set_feature("block_ip_on_exhaust", "enable");
    send_packet(Packets[7], false, 1004);
    if(action.get_block_stat_from_ipv4("10.0.0.4").has_value())
        test_results.emplace_back(true);
    else
        test_results.emplace_back(false);
    
    //Testing ICMP packets
    test_results.emplace_back(send_packet(Packets[8]));

    overall_stats = action.get_overall_stat();

    print_results();
    
}


void Test::print_results()
{
    if(test_results.empty())
    {
        std::cerr << "Test results is empty!" << std::endl;
        return;
    }
    if(overall_stats.empty())
    {
        std::cerr << "Overall stats is empty\n";
        return;
    }
    
    if(test_results.size() != Packets.size())
    {
        std::cerr << "Test results and packets sent are not equal!\n";
        return;
    }
    if(overall_stats.size() != expected_stats_count.size())
    {
        std::cerr << "Overall stats and expected stats size not equal\n";
        return;
    }

    std::cout << "\n\n-----------------------Test Results---------------------------\n";
    for(int i = 0; i < test_results.size(); i++)
    {
        std::cout << std::left << std::setw(60)
          << Packets[i].description
          << " : "
          << (test_results[i] ? "Success" : "Failure")
          << std::endl;
    }

    std::cout << "\n---------------Packet Stat---------------\n";
    for(int i=0; i< overall_stats.size(); i++)
    {
        std::cout << std::left << std::setw(20) << stat_labels[i]
          << "  : " << std::left << std::setw(5) << overall_stats[i]
          << "  -  " << ((overall_stats[i] == expected_stats_count[i]) ? "Matched" : "Not Matched")
          << std::endl;
    }
}