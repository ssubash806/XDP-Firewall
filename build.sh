#!/bin/bash

# Exit immediately on any command failure
set -e

check_status() {
    if [[ $1 -ne 0 ]]; then
        echo "Error: $2 failed. Exiting."
        exit 1
    fi
}

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "Error: This script must be run as root." >&2
        exit 1
    fi
}

check_build_tools() {
    local missing=()

    for tool in gcc g++ make; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "Missing: $tool"
            missing+=("$tool")
        fi
    done

    if [[ ${#missing[@]} -ne 0 ]]; then
        echo -e "\nSome essential build tools are missing: ${missing[*]}"
        echo "Install them on Debian-based systems with:"
        echo "  sudo apt update && sudo apt install build-essential"
        exit 1
    else
        echo "Build tools (gcc, g++, make) are installed."
    fi
}

check_clang() {
    if ! command -v clang >/dev/null 2>&1; then
        echo "Missing: clang"
        echo "Install it on Debian-based systems with:"
        echo "  sudo apt update && sudo apt install clang"
        exit 1
    else
        echo "Clang is installed."
    fi
}

check_libbpf() {
    if pkg-config --exists libbpf; then
        echo "libbpf is installed."
    elif [[ -f /usr/include/bpf/libbpf.h ]]; then
        echo "libbpf headers found."
    else
        echo "Missing: libbpf-dev"
        echo "Install it on Debian-based systems with:"
        echo "  sudo apt update && sudo apt install libbpf-dev"
        exit 1
    fi
}

compile_xdp() {
    echo "Compiling XDP program..."
    (cd ./XDP && make xdp)
    check_status $? "XDP compilation"
}

compile_user() {
    echo "Compiling user program..."
    (cd ./user && make xdpfw)
    check_status $? "User program compilation"
}

move_binary() {
    echo "Moving xdpfw to /usr/sbin..."
    mv ./user/xdpfw /usr/sbin/
    check_status $? "Moving binary to /usr/sbin"
    echo "Binary moved successfully."
}

main() {
    check_root
    check_build_tools
    check_clang
    check_libbpf
    compile_xdp
    compile_user
    move_binary
    echo "XDP firewall compilation is successfull"
    echo "Please run the sudo xdpfw --help to know the list of commands used"
}

main
