#include "../header/cli.h"

CLI::CLI()
{
    
}

void CLI::print_usage(char **argv)
{
    std::cout << "===================================================\n";
    std::cout << "                XDP Firewall CLI Tool          \n";
    std::cout << "===================================================\n\n";

    std::cout << "Usage:\n";
    std::cout << argv[0] << " <main_command> <sub_command> <action> [arguments]\n\n";

    std::cout << "Main Commands and Sub-Commands:\n\n";

    std::cout << "  [XDP Commands]\n";
    std::cout << "  xdp load <mode> --interface <interface> --obj <xdp_path> --prog <prog_name>\n";
    std::cout << "  xdp unload <mode> --interface <interface>\n";

    std::cout << "  [IP Commands]\n";
    std::cout << "    ip block add --ip <IP_ADDRESS> --dur <DURATION>\n";
    std::cout << "    ip block del --ip <IP_ADDRESS>\n";
    std::cout << "    ip subnet add --ip <SUBNET_IP> --pre <PREFIX_LENGTH>\n";
    std::cout << "    ip subnet del --ip <SUBNET_IP> --pre <PREFIX_LENGTH>\n\n";

    std::cout << "  [PORT Commands]\n";
    std::cout << "    port block add --port <PORT_NUMBER> --dur <DURATION>\n";
    std::cout << "    port block del --port <PORT_NUMBER>\n\n";

    std::cout << "  [FEATURE Commands]\n";
    std::cout << "    feature <FEATURE_NAME> enable\n";
    std::cout << "    feature <FEATURE_NAME> disable\n\n";
    std::cout << "    feature list";

    std::cout << "Arguments:\n";
    std::cout << "  mode         : possible attach modes (skb, native, offload)\n";
    std::cout << "  --interface  : interface name to be attached\n";
    std::cout << "  --obj        : path to the XDP object\n";
    std::cout << "  --prog       : name of the xdp program\n";
    std::cout << "  --ip         : Specify an IPv4 address (e.g., 192.168.1.10)\n";
    std::cout << "  --dur        : Duration format (e.g., 5m, 2h, 1d), use 0 to block indefinitely\n";
    std::cout << "  --port       : TCP/UDP port number (e.g., 80, 443)\n";
    std::cout << "  --pre        : Prefix length for subnet (e.g., 24)\n\n";

    std::cout << "Duration format:\n";
    std::cout << "  <number>[m/h/d]  --> m: minutes, h: hours, d: days\n";
    std::cout << "  Examples: 5m (5 minutes), 2h (2 hours), 1d (1 day)\n\n";

    std::cout << "Available Features:\n";
    std::cout << "--------------------------------------------------------------\n";
    std::cout << "  stat_conn         : Track incoming connection stats\n";
    std::cout << "  lpm_rule          : Subnet-based rules for bypass/block\n";
    std::cout << "  ip_block          : Block specific IP addresses\n";
    std::cout << "  port_block        : Block specific ports\n";
    std::cout << "  rate_limit        : Enable rate-limiting using token bucket\n";
    std::cout << "  block_ip_on_exhaust: Block IP if token bucket exhausted\n";
    std::cout << "--------------------------------------------------------------\n\n";

    std::cout << "Example Commands:\n";
    std::cout << argv[0] <<" xdp load skb --interface eth0 --obj /home/user/xdp/kern_program --prog xdp_filter\n";
    std::cout << argv[0] <<" ip block add --ip 192.168.1.10 --dur 1d\n";
    std::cout << argv[0] <<" port block add --port 80 --dur 6h\n";
    std::cout << argv[0] <<" feature rate_limit enable\n\n";

    std::cout << "==============================================================\n";
}

void CLI::parse_cli(int argc, char **argv, Loader& loader, Actions& action_obj)
{
    if (argc < 2) {
        std::cerr << "Insufficient arguments.\n";
        return;
    }

    std::string main_cmd = argv[1];
    

    if(main_cmd == "--help" || main_cmd == "-h")
    {
        print_usage(argv);
        return;
    }
    
    std::string sub_cmd = argv[2];

    if (main_cmd == "ip") {
        if (argc < 4) {
            std::cerr << "Insufficient arguments for ip command.\n";
            return;
        }
        std::string action = argv[3];

        if (sub_cmd == "block") {
            if (action == "add") {
                if (argc < 8) { // ip block add --ip 192.168.1.10 --dur 1d
                    std::cerr << "Missing arguments for ip block add.\n";
                    return;
                }
                action_obj.add_ip_block(argv[5], argv[7]);
            }
            else if (action == "del") {
                if (argc < 6) {
                    std::cerr << "Missing arguments for ip block del.\n";
                    return;
                }
                action_obj.del_ip_block(argv[5]); // argv[5]=ip
            }
            else if(action == "print")
            {
                action_obj.print_ip_block();
            }
            else {
                std::cerr << "Unknown action for ip block.\n";
            }
        }
        else if (sub_cmd == "subnet") {
            if (action == "add") {
                if (argc < 8) {
                    std::cerr << "Missing arguments for ip subnet add.\n";
                    return;
                }
                action_obj.add_ip_subnet(argv[5], argv[7]); // argv[5]=ip, argv[7]=pre
            }
            else if (action == "del") {
                if (argc < 8) {
                    std::cerr << "Missing arguments for ip subnet del.\n";
                    return;
                }
                action_obj.del_ip_subnet(argv[5], argv[7]); // argv[5]=ip, argv[7]=pre
            }
            else {
                std::cerr << "Unknown action for ip subnet.\n";
            }
        }
        else {
            std::cerr << "Unknown ip subcommand.\n";
        }
    }
    else if (main_cmd == "port") {
        if (argc < 4) {
            std::cerr << "Insufficient arguments for port command.\n";
            return;
        }
        std::string action = argv[3];

        if (sub_cmd == "block") {
            if (action == "add") {
                if (argc < 8) { // port block add --port 80 --dur 1h
                    std::cerr << "Missing arguments for port block add.\n";
                    return;
                }
                action_obj.add_port_block(argv[5], argv[7]); // argv[5]=port, argv[7]=dur
            }
            else if (action == "del") {
                if (argc < 6) {
                    std::cerr << "Missing arguments for port block del.\n";
                    return;
                }
                action_obj.del_port_block(argv[5]); // argv[5]=port
            }
            else if (action == "print")
            {
                action_obj.print_port_block();
            }
            else {
                std::cerr << "Unknown action for port block.\n";
            }
        }
        else {
            std::cerr << "Unknown port subcommand.\n";
        }
    }
    else if (main_cmd == "feature") {
        if (argc < 3) {
            std::cerr << "Insufficient arguments for feature command.\n";
            return;
        }
        std::string feature_name = argv[2];
        if(feature_name == "list")
        {
            action_obj.print_feature_status();
            return;
        }

        std::string action = argv[3];

        if (action == "enable") {
            action_obj.enable_feature(feature_name.c_str(), action.c_str()); // passing const char*
        }
        else if (action == "disable") {
            action_obj.enable_feature(feature_name.c_str(), action.c_str());
        }
        else {
            std::cerr << "Unknown action for feature.\n";
        }
    }
    else if (main_cmd == "xdp")
    {
        if (argc < 4)
        {
            std::cerr << "Insufficient arguments for xdp command." << std::endl;
            return;
        }

        std::string sub_cmd = argv[2];
        std::string mode = argv[3]; // skb, native, offload

        if (sub_cmd == "load")
        {
            if (argc < 9) // ./main xdp load <mode> --interface <iface> --obj <obj_path> --prog <prog_name>
            {
                std::cerr << "Insufficient arguments for xdp load command." << std::endl;
                return;
            }

            std::string interface_name;
            std::string obj_path;
            std::string prog_name;

            for (int i = 4; i < argc; i += 2)
            {
                if (std::string(argv[i]) == "--interface")
                    interface_name = argv[i + 1];
                else if (std::string(argv[i]) == "--obj")
                    obj_path = argv[i + 1];
                else if (std::string(argv[i]) == "--prog")
                    prog_name = argv[i + 1];
                else
                {
                    std::cerr << "Unknown argument: " << argv[i] << std::endl;
                    return;
                }
            }

            if (interface_name.empty() || obj_path.empty() || prog_name.empty())
            {
                std::cerr << "Missing required arguments for xdp load." << std::endl;
                return;
            }

            loader.load_xdp(obj_path.c_str(), prog_name.c_str(), interface_name.c_str(), mode.c_str());
        }
        else if (sub_cmd == "unload")
        {
            if (argc < 6) // ./main xdp unload <mode> --interface <iface>
            {
                std::cerr << "Insufficient arguments for xdp unload command." << std::endl;
                return;
            }

            std::string interface_name;

            if (std::string(argv[4]) == "--interface")
                interface_name = argv[5];
            else
            {
                std::cerr << "Unknown argument: " << argv[4] << std::endl;
                return;
            }

            if (interface_name.empty())
            {
                std::cerr << "Missing interface for xdp unload." << std::endl;
                return;
            }

            loader.unload_xdp(mode.c_str(), interface_name.c_str());
        }
        else
        {
            std::cerr << "Unknown sub-command " << sub_cmd << " for XDP." << std::endl;
            return;
        }
    }

    else {
        std::cerr << "Unknown main command.\n";
    }
}

CLI::~CLI()
{

}