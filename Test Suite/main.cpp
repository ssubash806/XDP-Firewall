#include "../user/header/XDP_Loader.h"
#include "../user/header/helpers.h"
#include "./header/Test_Class.h"
#include <iostream>

int main()
{
    if(!is_root())
    {
        std::cerr << "Please run with root privileges!" << std::endl;
        return FAILURE;
    }

    Loader l;
    if(l.load_xdp("../XDP/kern_program", "ingress_filter", "null", "skb") == FAILURE)
    {
        std::cerr << "Failed to load XDP program to kernel" << std::endl;
        return FAILURE;
    }
    
    std::cout << "XDP program attached to kernel" << std::endl;

    Test test(l.get_prog_fd());
    test.start_test();
    
    return SUCCESS;
}