#include "../header/XDP_Lgit oader.h"

Loader::Loader()
{
    // Nothings needs to be loaded now!
}

int Loader::load_xdp(const char* obj_path, const char* prog_name, const char* interface, const char* mode)
{
    // Previously checked before calling this function. But I try to write it as generic function, so Again checking here :)
    if(!obj_path)
    {
        std::cout << "Object path is null" << std::endl;
        return FAILURE;
    }
    if(!prog_name)
    {
        std::cout << "Program name is null" << std::endl;
        return FAILURE;
    }
    if(!interface)
    {
        std::cout<< "Interface cannot be null" << std::endl;
        return FAILURE;
    }
    
    this->_obj_path  = obj_path;
    this->_prog_name = prog_name;
    this->_interface = interface;
    this->_mode = mode;

    int interface_idx = 0;

    // Checking if interface is available. 
    // If I give interface as null, the it means, load to kernel but never attach to any of ther interfaces
    if(_interface != "null")
    {
        interface_idx = if_nametoindex(interface);
        if(interface_idx == 0)
        {
            std::cout << "Cannot find the sepcified interface " << interface << std::endl;
            return FAILURE;
        }
    }
    

    __u32 mode_flag;

    // Check if interface is already attached in the given mode.
    if(interface_idx)
    {
        struct bpf_xdp_query_opts xdp_query_opts;
        memset(&xdp_query_opts, 0, sizeof(xdp_query_opts));
        xdp_query_opts.sz = sizeof(xdp_query_opts);
        int ret = bpf_xdp_query(interface_idx, 0, &xdp_query_opts);
        if(_mode == "skb")
        {
            
            mode_flag = XDP_FLAGS_SKB_MODE;
            if(xdp_query_opts.skb_prog_id != 0)
            {
                std::cout << "XDP program is already attached in interface " << interface 
                          << "in skb mode, with program id " << xdp_query_opts.prog_id << std::endl;
                return FAILURE;
            }
        }
        else if(_mode == "native")
        {
            mode_flag = XDP_FLAGS_DRV_MODE;
            if(xdp_query_opts.drv_prog_id != 0)
            {
                std::cout << "XDP program is already attached in interface " << interface 
                          << "in driver mode, with program id " << xdp_query_opts.skb_prog_id << std::endl;
                return FAILURE;
            }
        }
        else if(_mode == "offload")
        {
            mode_flag = XDP_FLAGS_HW_MODE;
            if(xdp_query_opts.hw_prog_id != 0)
            {
                std::cout << "XDP program is already attached in interface " << interface 
                          << "in offload mode, with program id " << xdp_query_opts.skb_prog_id << std::endl;
                return FAILURE;
            }
        }
        else
        {
            std::cerr << "Unknown mode " << _mode << std::endl;
            return FAILURE;
        }
    }

    _bpf_obj = bpf_object__open_file(obj_path, NULL);
    if(!_bpf_obj)
    {
        std::cout << "Cannot open the object!" << std::endl;
        return FAILURE;
    }

    if(bpf_object__load(_bpf_obj) < 0)
    {
        std::cout << "Cannot load the obj into memory" << std::endl;
        //goto error;
    }

    struct bpf_program* _bpf_prog = bpf_object__find_program_by_name(_bpf_obj, prog_name);
    if(!_bpf_prog)
    {
        std::cout << "Cannot find the program name " << this->_prog_name.c_str() << std::endl;
        goto error;
    }

    this->prog_fd = bpf_program__fd(_bpf_prog);
    if(prog_fd < 0)
    {
        std::cerr<<"Failed to get program fd" << std::endl;
        goto error;
    }

    if(interface_idx)
    {
        //std::cout<< interface_idx << " " << prog_fd << " " << mode_flag <<std::endl;
        int attach_ret = bpf_xdp_attach(interface_idx, prog_fd, mode_flag, NULL);
        if(attach_ret < 0)
        {
            std::cout << "Failed to attach XDP to the interface " << interface << std::endl;
            return FAILURE;
        }
        else
        {
            std::cout << "Successfully attached the xdp to interface " << interface << std::endl;
        }
    }

    return SUCCESS;

    error:
        bpf_object__close(_bpf_obj);
        return FAILURE;
}

int Loader::unload_xdp(const char* mode, const char* interface)
{
    if(!mode)
    {
        std::cerr <<"Mode cannot be null!" << std::endl;
        return FAILURE;
    }
    if(!interface)
    {
        std::cerr<< "Interface cannot be null" << std::endl;
        return FAILURE;
    }

    int interface_idx = if_nametoindex(interface);
    if(interface_idx == 0)
    {
        std::cerr << "Cannot find interface " << interface << std::endl;
        return FAILURE;
    }
    
    __u32 mode_flags;
    std::string s_interface = interface;
    std::string s_mode = mode;
    struct bpf_xdp_query_opts xdp_query_opts;
    memset(&xdp_query_opts, 0, sizeof(xdp_query_opts));
    xdp_query_opts.sz = sizeof(xdp_query_opts);
    int ret = bpf_xdp_query(interface_idx, 0, &xdp_query_opts);

    if(s_mode == "skb")
    {
        if(xdp_query_opts.skb_prog_id == 0)
        {
            std::cerr << "No XDP program attached for interface "<< interface
                      << " with skb mode" << std::endl;
        }
        mode_flags = XDP_FLAGS_SKB_MODE;
    }
    else if(s_mode == "native")
    {
        if(xdp_query_opts.drv_prog_id == 0)
        {
            std::cerr << "No XDP program attached for interface "<< interface
                      << " with native mode" << std::endl;
        }
        mode_flags = XDP_FLAGS_DRV_MODE;
    }
    else if(s_mode == "offload")
    {
        if(xdp_query_opts.hw_prog_id == 0)
        {
            std::cerr << "No XDP program attached for interface "<< interface
                      << " with offload mode" << std::endl;
        }
        mode_flags = XDP_FLAGS_HW_MODE;
    }
    else
    {
        std::cerr << "Unknown mode " << _mode << std::endl;
        return FAILURE;
    }

    if(bpf_xdp_detach(interface_idx, mode_flags, NULL) < 0)
    {
        std::cerr<< "XDP detach failed!" <<std::endl;
        return FAILURE;
    }
    else
    {
        std::cout<<"Succesfully detached XDP from interface " << s_interface << std::endl;
    }
    return SUCCESS;
}

int Loader::getFD() const
{
    return this->prog_fd;
}

Loader::~Loader()
{
    if(prog_fd)
        close(prog_fd);
    if(!_bpf_obj)
        bpf_object__close(_bpf_obj);
}