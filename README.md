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

## ✨ Features

- ✅ High-speed firewall using XDP hooks
- ✅ Port and IP-based dynamic blocking
- ✅ Dropped packet statistics per IP/port
- ✅ Expiration-based temporary blocking
- ✅ Indefinite blocking support
- ✅ CLI-based interface for management
- 🚧 **Upcoming:**
  - Test Suite support for IPv6 packets
- ⚠️ IPv6 Not tested in real environment. Mak sure to test it before implementation.

---

## 🧠 About XDP

XDP (eXpress Data Path) allows BPF programs to run **very early** in the Linux networking stack. This enables:

- Low-latency, high-throughput packet processing
- Dropping or redirecting packets before kernel allocates resources
- Dynamic loading/unloading without kernel module overhead

---

## 🛠️ Build Instructions

> Prerequisites:
> - `clang`, `llvm`, `bpftool`, and `libbpf-dev`
> - Linux with kernel 5.x+ and XDP support
> - C++ compiler (`g++`)

```
### 🧩 Compile the eBPF Kernel Program

make xdp

⚙️ Compile the User-Space Controller

make all

🧽 Clean Build Files

make clean

🚀 Usage

Example commands:

# Block port 81 for 1 hour
sudo ./main port block add --port 81 --dur 1h

# Block IP for 10 minutes
sudo ./main ip block add --ip 192.168.1.10 --dur 10m

# Print active port blocks
sudo ./main port block print

# Print IP blocks
sudo ./main ip block print
```
---
📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
🙌 Acknowledgements

    libbpf

    XDP Tutorial by Cilium

    Linux community for XDP documentation and tooling
---
