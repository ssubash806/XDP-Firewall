#pragma once
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <iostream>
#include <string>
#include "../header/constants.h"
#include <unistd.h>

class Loader{
    private:
        int prog_fd;
        std::string _obj_path;
        std::string _prog_name;
        std::string _interface;
        std::string _mode;
        struct bpf_object* _bpf_obj;

    public:
        Loader();
        int load_xdp(const char* obj_path, const char* prog_name, const char* interface, const char*mode);
        int unload_xdp(const char* mode, const char* interface);
        int getFD() const;
        int get_prog_fd() const;
        ~Loader();
};