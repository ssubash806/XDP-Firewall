# 🚀 XDP-Firewall

![GitHub Repo stars](https://img.shields.io/github/stars/ssubash806/XDP-Firewall?style=flat-square)
![GitHub forks](https://img.shields.io/github/forks/ssubash806/XDP-Firewall?style=flat-square)
![GitHub issues](https://img.shields.io/github/issues/ssubash806/XDP-Firewall?style=flat-square)
![GitHub last commit](https://img.shields.io/github/last-commit/ssubash806/XDP-Firewall?style=flat-square)
![License](https://img.shields.io/github/license/ssubash806/XDP-Firewall?style=flat-square)

---

## 🔥 Introduction

**XDP-Firewall** is a high-performance packet filtering framework built using **eBPF/XDP** (eXpress Data Path). It allows user-defined port and IP-based filtering rules that operate directly in the Linux kernel's networking stack — enabling ultra-fast, programmable, and lightweight firewall behavior.

It comes with a C++ user-space controller for easy interaction, blocking, unblocking, logging, and future integration with visualization tools like Grafana.

---

## 🧠 About XDP

XDP (eXpress Data Path) allows BPF programs to run **very early** in the Linux networking stack. This enables:

- Low-latency, high-throughput packet processing
- Dropping or redirecting packets before kernel allocates resources
- Dynamic loading/unloading without kernel module overhead

---

## ✨ Features

- ✅ High-speed firewall using XDP hooks
- ✅ Supports Port blocking
- ✅ Supports both IPv4 and IPv6 blocking
- ✅ Supports CIDR rule for allowing IP's from particular range. If IP falls in that range, then neither port block nor ip block applied.
- ✅ Blocking temporary like ("1m" - 1 minute, "1h" - 1 hour, "2d" - 2 day) or permanent blocking.
- ✅ Supports rate limiting. Uses Token bucket algorithm.
- ✅ If rate limiting and IP block feature enabled then the rate limiting exceeding IP's will be blocked for 10 minutes
- ✅ Supports dynamic enabling/disabiling of features.
- ✅ Uses CLI tool (xdpfw) from user to add ip block, port block, enabling or disabling features and other management.
- ✅ Dropped packet statistics per IP/ports
- ✅ Uses the constants from /XDP/utils/constants.h. Modify this constants according to your needs.
- ✅ Provided the Test suite, in case if you modify kernel code run the test suite for correctness.
- ⚠️ IPv6 Tested via Test suite, not tested on a real environment. Make sure to test it before deployment.

---

## 🛠️ Build Instructions

> Prerequisites:
> - `clang`, `llvm`, `bpftool`, and `libbpf-dev`
> - Linux with kernel 5.x+ and XDP support
> - C++ compiler (`g++`)

```
🧩 Build Firewall

sudo ./build.sh 

The build script automatically compiles both cli tool and XDP. Places cli in /usr/sbin.
Use sudo xdpfw --help for more commands.

🧩 Build Test Suite
Move to Test Suite directory

make all

To run the test suite
sudo ./test

It will run all the feature tests and Display the results as with and all success and which and all failed.

🚀 Usage

Example commands:

# Attach XDP commands
sudo xdpfw xdp load native --interface eth0 --obj /home/user/XDP-Firewall/XDP/kern_program --prog ingress_filter

# Detach XDP from interface
sudo xdpfw xdp unload native --interface eth0

# Block port 80 for 2 hour
sudo xdpfw port block add --port 80 --dur 1h

# List active port block rules
sudo xdpfw port block print

# Block IPv4 for 10 minutes
sudo xdpfw ip block add --ip 192.168.1.10 --dur 10m

# Block IPv6 permanently (0 for permanent)
sudo xdpfw ip block add --ip fd80::1 --dur 0

# List active blocked IP's
sudo xdpfw ip block print

# ADD CIDR Rule
sudo xdpfw ip subnet add --ip 192.168.1.0 --pre 24

# Delete CIDR Rule
sudo xdpfw ip subnet del --ip 192.168.1.0 --pre 24

# Enable or disable features
sudo xdpfw feature ip_block enable
sudo xdpfw feature port_block disable

# List features status
sudo xdpfw features list
```