<div align="center">

# 🔍 NetScan

**A fast, hybrid network scanner for Linux, written in pure Python.**

Scan a whole network block and instantly see which devices are **up**, which are **down**, what **ports** are open, and what **software versions** are running.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-informational?logo=linux&logoColor=white)
![Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

</div>

---

## ✨ Features

- 🌐 **Scan a full network block**: give it a CIDR range like `192.168.1.0/24` and it checks every address.
- 🟢 **Live vs. down hosts**: clearly shows which devices respond and which don't.
- 🧠 **Hybrid host discovery**: combines **ICMP ping**, **TCP probes** and the **ARP cache**, so even devices that block ping are found.
- 🚪 **Open port detection**: a fast async scanner with your choice of common ports, a custom list, a range, or all 65535.
- 🏷️ **Service and version detection**: grabs banners to identify software such as OpenSSH, Apache/nginx, FTP, SMTP, MySQL and more.
- 🔬 **Optional nmap engine**: add `--nmap` for deeper version detection.
- 🖥️ **Extra device info**: hostname, MAC address and an OS guess for every live host.
- 💾 **Export results** to JSON or CSV.
- 📦 **Zero pip dependencies**: uses only the Python standard library.

---

## 📥 Installation

```bash
# 1. Clone the repo
git clone https://github.com/YOUR-USERNAME/netscan.git
cd netscan

# 2. Install system requirements (Debian / Ubuntu / Kali)
sudo apt update && sudo apt install -y python3 iputils-ping nmap
```

> `nmap` is optional. It is only needed for the `--nmap` option.

---

## 🚀 Usage

Find your network block first:

```bash
ip -4 addr show      # e.g. inet 192.168.1.25/24  ->  scan 192.168.1.0/24
```

Run a basic scan:

```bash
python3 netscan.py 192.168.1.0/24
```

### Common examples

| Goal | Command |
|---|---|
| Scan ports 1-1024 | `python3 netscan.py 192.168.1.0/24 -p 1-1024` |
| Scan specific ports | `python3 netscan.py 192.168.1.0/24 -p 22,80,443,8080` |
| Scan all ports (slow) | `python3 netscan.py 192.168.1.0/24 -p all` |
| List the down hosts too | `python3 netscan.py 192.168.1.0/24 --show-down` |
| Deeper version detection | `python3 netscan.py 192.168.1.0/24 --nmap` |
| Save results | `python3 netscan.py 192.168.1.0/24 --json out.json --csv out.csv` |
| Skip ping (ping-blocking hosts) | `python3 netscan.py 192.168.1.0/24 --no-ping` |
| Slower but more reliable | `python3 netscan.py 192.168.1.0/24 -t 2 -c 200` |

### Options

| Option | Description |
|---|---|
| `target` | Network block in CIDR form, e.g. `192.168.1.0/24` |
| `-p, --ports` | `top` (default), `all`, or a list/range like `22,80,8000-9000` |
| `-t, --timeout` | Connection timeout in seconds (default `1.0`) |
| `-c, --concurrency` | Parallel connections (default `500`) |
| `--nmap` | Use nmap `-sV` for deeper version detection |
| `--no-ping` | Skip ICMP; rely on TCP probes and ARP |
| `--show-down` | List the IPs that did not respond |
| `--json FILE` | Save full results as JSON |
| `--csv FILE` | Save results as CSV |
| `--force` | Allow scanning more than 65,536 addresses |

---

## 📸 Example output

*(Illustrative sample. Your results will differ.)*

```
==============================================================================
 LIVE HOSTS (2)
==============================================================================

192.168.1.1  (router.lan)
  found via: icmp | MAC: aa:bb:cc:dd:ee:ff | OS guess: Linux/Unix/macOS/Android (ttl 64)
  PORT      SERVICE     VERSION / BANNER
  22/tcp    ssh         OpenSSH 8.9p1 Ubuntu
  80/tcp    http        nginx/1.18.0

192.168.1.20
  found via: tcp
  no open ports among scanned ports

==============================================================================
 NO RESPONSE / CLOSED HOSTS (252)
==============================================================================
 (use --show-down to list them)

Done: 2 up, 252 down, 2 open ports in 14.3s
```

---

## ⚙️ How it works

1. **Discovery**: each IP is checked with ping, then TCP probes, then the ARP cache. Any reply marks the host as up.
2. **Port scan**: live hosts are scanned with an async TCP connect scanner.
3. **Version detection**: open ports are probed for banners and parsed into software names and versions (optionally refined by nmap).
4. **Report**: results are printed in a clean summary and can be exported to JSON or CSV.

---

## ⚠️ Legal disclaimer

This tool is for **educational purposes and authorized security testing only**. Only scan networks and devices that you **own** or have **explicit written permission** to test. The author is not responsible for any misuse or damage caused by this tool.

---

## 🤝 Contributing

Ideas and pull requests are welcome. Feel free to open an issue for bugs or feature requests (IPv6 support, UDP scanning, MAC vendor lookup, and more).

## 📄 License

Released under the [MIT License](LICENSE).

---

<div align="center">

If you find this project useful, please give it a ⭐ on GitHub!

</div>
