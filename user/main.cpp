#include <iostream>
#include "header/XDP_Loader.h"
#include "header/actions.h"
#include "../XDP/utils/constants.h"
#include "header/cli.h"
#include "header/helpers.h"

int main(int argc, char** argv)
{
    if(!is_root())
    {
        std::cerr << "Please run with root privileges!" <<std::endl;
        return FAILURE;
    }
    
    Actions action;
    action.get_maps();
    
    Loader loader;
    
    CLI command;
    command.parse_cli(argc, argv, loader, action);
    
    return 0;
}