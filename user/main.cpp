#include <iostream>
#include "header/XDP_Loader.h"
#include "header/actions.h"
#include "../XDP/utils/constants.h"
#include "header/cli.h"

int main(int argc, char** argv)
{
    Actions action;
    action.get_maps();
    
    Loader loader;
    
    CLI command;
    command.parse_cli(argc, argv, loader, action);
    
    return 0;
}