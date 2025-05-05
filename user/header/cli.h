#pragma once
#include <iostream>
#include <vector>
#include <unordered_map>
#include "actions.h"
#include "constants.h"
#include "XDP_Loader.h"

class CLI
{
    private:
    std::string command;
    std::vector<std::string> args;

    public:
    CLI();
    void parse_cli(int argc, char **argv, Loader&, Actions&);
    static void print_usage(char **argv);
    ~CLI();
};