<div align="center">

# 🔍 NetScan

**A fast, resilient hybrid network scanner for Linux, written in pure Python.**

Scan a whole network block and instantly see which devices are **up**, which are **down**, what **ports** are open, and what **software versions** are running. Version 3 adds **active ARP-assisted discovery**, **raw ICMP sockets**, **SYN half-open scanning**, **Markdown and XML export**, and fixes the silent host-loss bugs that made TCP-only mode under-count firewalled devices.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-informational?logo=linux&logoColor=white)
![Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen)
![Version](https://img.shields.io/badge/Version-3.1-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

</div>

---

## 📖 Table of contents

- [Features](#-features)
- [What's new in v3.1](#-whats-new-in-v31)
- [Installation](#-installation)
- [Quick start](#-quick-start)
- [Usage](#-usage)
  - [Discovery modes](#-discovery-modes)
  - [Common examples](#common-examples)
  - [Options](#options)
- [Example output](#-example-output)
- [Export formats](#-export-formats)
- [How it works](#-how-it-works)
- [Performance tuning](#-performance-tuning)
- [Research use](#-research-use)
- [Notes and limitations](#-notes-and-limitations)
- [Troubleshooting](#-troubleshooting)
- [Changelog](#-changelog)
- [Legal disclaimer](#️-legal-disclaimer)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

- 🌐 **Scan a full network block** — give it a CIDR range like `192.168.1.0/24` and it checks every address.
- 🟢 **Live vs. down hosts** — clearly shows which devices respond and which don't.
- 🧠 **Hybrid host discovery** — combines an **active ARP sweep**, **raw ICMP**, **TCP probes** and **UDP probes**, so even devices that block ping and drop TCP are still found.
- 🎛️ **Six selectable discovery modes** — `icmp`, `tcp`, `arp`, `udp`, `hybrid` (default) or `all`, plus a `--tcp-arp` assist flag.
- 📡 **Active ARP sweep** — forces the kernel to ARP-resolve every address. On a local subnet, this is the only discovery method firewalls cannot hide from.
- ⚡ **Raw ICMP socket** — no `ping` subprocess fork storm; 512 concurrent pings with millisecond precision and per-probe nonces (no false TTLs from sequence collisions).
- ⚡ **SYN half-open scan** (`--syn`, root only) — faster and quieter than full connect scanning; falls back to connect automatically when not root.
- 🚪 **Open port detection** — async TCP scanner with `top`, custom list, range, or all 65535 port selection.
- 🏷️ **Service and version detection** — banner grab + TLS handshake for SSH, HTTP/HTTPS, FTP, SMTP, POP3, IMAP, VNC, MySQL, Redis, MongoDB and more.
- 🔬 **Optional nmap engine** — add `--nmap` for deeper version detection, with a 30 s per-host timeout so one stuck host can't stall the run.
- 🖥️ **Extra device info** — hostname, MAC address and TTL-based OS guess for every live host.
- 💾 **Four export formats** — JSON, CSV, nmap-compatible XML, and a human-readable Markdown report. JSON includes run settings, discovery time and error stats.
- 🛡️ **Resilient** — FD-exhaustion retried with exponential backoff, per-host errors counted and reported, ARP table re-read mid-scan so late replies aren't lost.
- 📦 **Zero pip dependencies** — uses only the Python standard library.

---

## 🆕 What's new in v3.1

### Accuracy fixes

- **TCP-only discovery under-counted firewalled hosts.** On a local subnet, `-m tcp` could report 4 hosts while ARP reported 6. The two missing hosts were alive but silently **dropping** (not refusing) every TCP probe. Fixed by adding `--tcp-arp` (ARP assist for TCP mode) and making `hybrid` the recommended default.
- **Wrong TTLs from ICMP sequence collision.** With 254 concurrent pings reusing a 16-bit sequence space, a late reply from one probe could complete the wrong future and report the wrong TTL. Each probe now carries a 32-bit nonce that is verified on reply; stale replies are discarded.
- **Mid-scan ARP read didn't mark hosts alive.** Hosts whose ARP entry appeared mid-scan had their MAC recorded but were not counted as alive until the final read, by which time the kernel may have expired the entry. Fixed: the mid-scan read now sets `alive` and appends `"arp"` to `via`.
- **Double ARP sweep in `arp` mode.** A leftover `(args.mode != "arp" or True)` always-true condition caused the sweep to run twice. Removed.
- **MySQL misidentification.** The old check `data[4] == 0x0A` was too loose. Now requires `data[3] == 0x00` (handshake sequence id) and `data[4] in {0x09, 0x0A}` (protocol version).
- **`tcp_dropped` not counted during port scan.** Only discovery counted FD-exhaustion drops; the port-scan phase silently swallowed them. Now both paths increment the counter.
- **Raw-socket leaks across repeated runs.** `_ICMP` and `_SYN` were module globals never closed. Re-running `asyncio.run(run(args))` in the same process (tests, wrappers) hung on the second run. Both are now closed and reset in a `finally` block.
- **10-minute nmap hang on filtered hosts.** The subprocess timeout was 600 s. Now uses `-T4 --host-timeout 30s` with a 90 s subprocess cap.

### Speed improvements

- **`_local_ip_for` opened a socket per SYN probe** — about 250,000 socket open/close pairs on a `/24 × 1000 ports` scan. Memoized per target IP.
- **Port scan now parallelizes across hosts** (bounded by `--concurrency`), not just across ports of one host.
- **Single ARP sweep** instead of two in `arp` mode.

### New flags

- `--xml FILE` — nmap-compatible XML export (includes `<state>` for every scanned port, not just open ones).
- `--md FILE` — human-readable Markdown report.
- `--tcp-arp` — run the ARP sweep in `tcp` mode. **This is the fix for the "only 4 hosts" problem.**
- `--discovery-ports SPEC` — override the built-in 25-port TCP discovery set.
- `--rate-limit N` — ARP packets per 50 ms burst (default 200).
- `--retries N` — retries on transient errors (default 1).
- `--verbose` — extra diagnostics (fd-limit reduction, etc.).

---

## 📥 Installation

```bash
# 1. Clone the repo
git clone https://github.com/awaiskhan1231919/NetScan-Hybrid.git
cd NetScan-Hybrid

# 2. Install system requirements (Debian / Ubuntu / Kali)
sudo apt update && sudo apt install -y python3 iputils-ping nmap iproute2
```

> **`nmap`** is optional — only needed for `--nmap`.  
> **`iproute2`** provides `ip neigh`, used to flush the ARP cache.  
> **`iputils-ping`** is a fallback for non-root ICMP. Root users get the faster raw-socket path automatically.

### Root requirements

| Feature | Root required? | Fallback if not root |
|---|---|---|
| `-m arp`, `hybrid`, `all`, `--tcp-arp` | Yes (for ARP flush) | ARP sweep still runs, but stale entries may cause ghosts |
| `-m icmp` | No | Falls back to the `ping` binary (slower, integer `-W`) |
| `--syn` | Yes | Falls back to connect scan |
| `--nmap` | No | nmap handles its own privileges |

Run as root for clean results:

```bash
sudo python3 netscan.py 192.168.1.0/24
```

---

## 🚀 Quick start

Find your network block first:

```bash
ip -4 addr show      # e.g. inet 192.168.1.25/24  ->  scan 192.168.1.0/24
```

Run a basic scan (hybrid mode, the default):

```bash
sudo python3 netscan.py 192.168.1.0/24
```

Just find live hosts, skip port scan:

```bash
sudo python3 netscan.py 192.168.1.0/24 --discovery-only --show-down
```

---

## 🚀 Usage

### 🎛️ Discovery modes

| Mode | How it finds hosts | Root? |
|---|---|---|
| `icmp` | Raw ICMP echo (millisecond precision, per-probe nonce); falls back to the `ping` binary if not root | No |
| `tcp` | TCP connect probes to 25 ports. An open port **or** a refusal (RST) both prove the host is up. Add `--tcp-arp` to also run the ARP sweep | No |
| `arp` | Forces the kernel to send real ARP requests to every address, then reads the ARP table. Firewalls can't hide from this on a local subnet | **Yes** (for flush) |
| `udp` | Protocol probes (DNS, NTP, NetBIOS, SNMP, SSDP, mDNS) + two closed-port probes. A reply **or** an ICMP port-unreachable proves the host is up | No |
| `hybrid` | **Active ARP sweep**, then ICMP, then TCP — the recommended default | No (root improves ARP) |
| `all` | `hybrid` + UDP — maximum coverage, slowest | No |

#### Why `-m tcp` alone misses hosts

A host whose firewall is set to **DROP** (silently discard) on all 25 discovery ports looks dead to TCP discovery: no SYN/ACK, no RST, just timeouts. This is not a bug — it is the structural limit of TCP probing. Two fixes:

1. **`--tcp-arp`** — adds the active ARP sweep to TCP mode. On a local subnet this recovers every host ARP can see.
2. **`-m hybrid`** (default) — ARP + ICMP + TCP together.

On a local subnet, `-m tcp --tcp-arp` and `-m hybrid` should report the same count as `-m arp`.

### Common examples

| Goal | Command |
|---|---|
| Ground-truth LAN sweep | `sudo python3 netscan.py 192.168.1.0/24 -m arp --discovery-only` |
| ICMP-only discovery | `python3 netscan.py 192.168.1.0/24 -m icmp --discovery-only` |
| TCP-only discovery | `python3 netscan.py 192.168.1.0/24 -m tcp --discovery-only` |
| **TCP + ARP assist** (recommended for TCP-only users) | `sudo python3 netscan.py 192.168.1.0/24 -m tcp --tcp-arp --discovery-only` |
| UDP-only discovery | `python3 netscan.py 192.168.1.0/24 -m udp --udp-timeout 2 --discovery-only` |
| Hybrid (recommended default) | `sudo python3 netscan.py 192.168.1.0/24 -m hybrid --discovery-only` |
| Wide TCP discovery ports | `python3 netscan.py 192.168.1.0/24 -m tcp --discovery-ports 22,80,443,445,3389,5000,8000,8080,8888,9000,9100,32400 --discovery-only` |
| Save a run for later analysis | `sudo python3 netscan.py 192.168.1.0/24 -m icmp --discovery-only --json icmp_run1.json` |
| Scan ports 1–1024 | `python3 netscan.py 192.168.1.0/24 -p 1-1024` |
| Scan specific ports | `python3 netscan.py 192.168.1.0/24 -p 22,80,443,8080` |
| Scan all ports (slow) | `python3 netscan.py 192.168.1.0/24 -p all` |
| **SYN half-open scan** (fast, root) | `sudo python3 netscan.py 192.168.1.0/24 -p 1-1024 --syn` |
| List the down hosts too | `python3 netscan.py 192.168.1.0/24 --show-down` |
| Deeper version detection | `python3 netscan.py 192.168.1.0/24 --nmap` |
| Save all four formats | `sudo python3 netscan.py 192.168.1.0/24 --nmap --json out.json --csv out.csv --xml out.xml --md report.md` |
| Skip ping (ping-blocking hosts) | `python3 netscan.py 192.168.1.0/24 --no-ping` |
| Slower but more reliable | `python3 netscan.py 192.168.1.0/24 -t 2 -c 200` |
| Lower ARP burst on large ranges | `sudo python3 netscan.py 10.0.0.0/22 -m arp --rate-limit 50 --arp-wait 4 --discovery-only` |
| Full audit of one host | `sudo python3 netscan.py 192.168.1.50/32 -p all --syn --nmap --json host.json --md host.md` |
| Routed subnet (not on-link) | `python3 netscan.py 10.20.0.0/24 -m icmp -p top --nmap` |

### Options

| Option | Description |
|---|---|
| `target` | Network block in CIDR form, e.g. `192.168.1.0/24` |
| `-m, --mode` | Discovery method: `icmp`, `tcp`, `arp`, `udp`, `hybrid` (default) or `all` |
| `-p, --ports` | `top` (default), `all`, or a list/range like `22,80,8000-9000` |
| `--discovery-ports SPEC` | Override the built-in 25-port TCP discovery set |
| `-t, --timeout` | ICMP/TCP timeout in seconds (default `1.0`) |
| `--udp-timeout` | UDP probe timeout in seconds (default `1.5`) |
| `--arp-wait` | Seconds to wait for ARP replies (default `2.0`) |
| `-c, --concurrency` | Parallel connections (default `500`) |
| `--rate-limit N` | ARP packets per 50 ms burst (default `200`) |
| `--retries N` | Retries on transient errors (default `1`) |
| `--discovery-only` | Only find live hosts: skip port scan and version detection |
| `--nmap` | Use nmap `-sV` for deeper version detection (`-T4 --host-timeout 30s`) |
| `--syn` | SYN half-open scan (root only; falls back to connect if not root) |
| `--tcp-arp` | Also run the ARP sweep in `tcp` mode (fixes the "only 4 hosts" problem) |
| `--no-ping` | Skip ICMP in `hybrid`/`all`; rely on the other methods |
| `--no-flush` | Do not flush the ARP cache before `arp`/`hybrid`/`all` |
| `--show-down` | List the IPs that did not respond |
| `--json FILE` | Save full results and run settings as JSON |
| `--csv FILE` | Save results as CSV (includes a `found_via` column) |
| `--xml FILE` | Save as nmap-compatible XML (includes `<state>` for every scanned port) |
| `--md FILE` | Save as a human-readable Markdown report |
| `--force` | Allow scanning more than 65,536 addresses |
| `--verbose` | Extra diagnostics (fd-limit reduction, etc.) |

---

## 📸 Example output

*(Illustrative sample. Your results will differ.)*

```
==============================================================================
 LIVE HOSTS (2)   mode: hybrid   discovery: 3.11s
==============================================================================

192.168.1.1  (router.lan)
  found via: arp,icmp | MAC: aa:bb:cc:dd:ee:ff | OS guess: Network device/Solaris (ttl 255)
  PORT      SERVICE     VERSION / BANNER
  22/tcp    ssh         OpenSSH 8.9p1 Ubuntu
  80/tcp    http        nginx/1.18.0

192.168.1.20
  found via: arp | MAC: 11:22:33:44:55:66
  no open ports among scanned ports

==============================================================================
 NO RESPONSE / CLOSED HOSTS (252)
==============================================================================
 (use --show-down to list them)

Done: 2 up, 252 down, 2 open ports in 11.8s (discovery 3.11s)
```

### How to read the output

- **`found via:`** — which probe(s) proved the host alive. If a host is only found via `arp`, its firewall is dropping everything else — exactly the case that made v2's `-m tcp` under-count.
- **`MAC:`** — from the kernel ARP table (only for on-link hosts).
- **`OS guess:`** — inferred from TTL (≤64 Linux/Unix/macOS, ≤128 Windows, >128 network gear).
- **`PORT / SERVICE / VERSION`** — one row per open TCP port.

If the run had FD-exhaustion or transient errors, the summary adds a line:

```
[!] dropped due to errors: tcp=12 udp=0 fd=3 (results may be incomplete)
```

If you see this, lower `-c` or raise `ulimit -n`.

### Evidence screenshots

- `NO RESPONSE / CLOSED HOSTS` section for a `/24` subnet, showing NetScan distinguishing reachable hosts from non-responding devices.  
  ![Closed hosts screenshot](./closed-hosts.png)

- `LIVE HOSTS` section listing active devices with their discovery method, MAC address, and OS guess.  
  ![Live hosts screenshot](./live-hosts.png)

- Live host scan with open ports and detected services (`53/tcp`, etc.).  
  ![Ports scan screenshot](./ports-scan.png)

---

## 💾 Export formats

All four formats are optional and can be combined in a single run.

| Format | Flag | What it contains | Best for |
|---|---|---|---|
| **JSON** | `--json out.json` | `meta` (target, mode, timeouts, concurrency, discovery time, timestamp, `stats`, `scanned_ports`) + `hosts` (full dataclass, including `errors`) | Machine processing, research reproducibility |
| **CSV** | `--csv out.csv` | `ip, hostname, mac, os_guess, found_via, port, service, version` — one row per open port, or one row per host if no ports | Spreadsheets, grep, diff across runs |
| **XML** | `--xml out.xml` | nmap-compatible `<nmaprun>` with `<host>`, `<address>`, `<ports>`, `<state state="open|closed">` for every scanned port | Import into other scanners, nmap tooling |
| **Markdown** | `--md report.md` | Per-host sections with `found via`, MAC, OS, and a port table | Paste into docs, wiki, PR descriptions |

Example — save everything in one run:

```bash
sudo python3 netscan.py 192.168.1.0/24 --nmap \
     --json scan.json --csv scan.csv --xml scan.xml --md scan.md
```

The JSON `meta.stats` block records `emfile`, `retries`, `tcp_dropped`, `udp_dropped`, so you can audit whether a run was complete.

---

## ⚙️ How it works

### 1. Discovery (depends on `--mode`)

- **`arp`** — a one-byte UDP datagram is sent to every address, forcing the kernel to ARP-resolve it. Hosts that reply get a completed entry in the ARP table, which NetScan reads before, during and after discovery. On a local subnet, this is ground truth: firewalls cannot filter ARP.
- **`icmp`** — one raw ICMP echo per address, carrying a 32-bit nonce so stale replies from reused sequence numbers are discarded. Falls back to the `ping` binary if not root.
- **`tcp`** — connect probes to 25 ports (configurable via `--discovery-ports`). An open port or a refusal (RST) means the host is up. Ports are rotated per host (`offset = sum(ord(c) for c in ip) % len(ports)`) so a per-port filter can't pattern-block the whole set.
- **`udp`** — protocol probes to ports 53, 123, 137, 161, 1900 and 5353, plus two closed-port probes. Any reply, or an ICMP port-unreachable, marks the host as up.
- **`hybrid`** — active ARP sweep first, then ICMP, then TCP for hosts still missing.
- **`all`** — `hybrid` + UDP.

After discovery, the ARP table is read a **second time** and any new entries are merged — including setting `alive = True` for hosts that appeared mid-scan, so kernel ARP expiry can't drop them from results.

### 2. Port scan

Live hosts are scanned in parallel (bounded by `--concurrency`) with either:

- an async TCP connect scanner (default), or
- a raw SYN scanner (`--syn`, root only) that interprets SYN/ACK and RST as "port open/closed" without completing the handshake.

Skipped entirely with `--discovery-only`.

### 3. Version detection

Open ports are probed for banners and parsed into software name + version. The native detector recognizes SSH, HTTP/HTTPS, FTP, SMTP, POP3, IMAP, VNC, MySQL, Redis, MongoDB and generic printable banners. `--nmap` layers `nmap -sV` on top, with a per-host timeout so one filtered host can't stall the run.

### 4. Enrichment

Reverse DNS, MAC from the ARP table, and TTL → OS guess.

### 5. Report

Console summary plus optional JSON / CSV / XML / Markdown exports.

---

## ⚡ Performance tuning

| Symptom | Fix |
|---|---|
| Scan very slow | Raise `-c 1000`, lower `-t 0.5` |
| `[!] N fd-exhaustion events` in summary | Lower `-c` to 200, or `ulimit -n 65535` |
| Many timeouts on congested Wi-Fi | Lower `-c 100`, raise `-t 2` |
| ARP sweep drops entries on large ranges | Lower `--rate-limit 50`, raise `--arp-wait 4` |
| Port scan of `all` on a `/24` takes hours | Use `--syn` (root) or narrow `-p` |
| `--nmap` dominates runtime | Use native detection only; nmap is per-host with a 30 s timeout |

**Recommended starting point for a `/24`:**

```bash
sudo python3 netscan.py 192.168.1.0/24 -m hybrid -p top -c 500 -t 1 --nmap
```

**For a `/16` or larger:**

```bash
sudo python3 netscan.py 10.0.0.0/16 -m hybrid -p top -c 1000 -t 1 \
     --discovery-only --force --json big.json
```

---

## 🔬 Research use

v3 was built to support a small research study that asks: **does hybrid discovery (active ARP + ICMP + TCP) find more hosts than ICMP-only, TCP-only, ARP-only or UDP-only discovery?**

Planned method:

- Build a ground-truth list of devices known to be online on a home network and in a VM lab.
- Run each mode against the same network, three times each, and compare against Nmap (Zenmap).
- Record true positives, false negatives, false positives and discovery time, then calculate precision, recall and average time per method.
- Repeat under a second condition (host firewall on, or a sleeping device) and test the effect of `--timeout`.

The v3 fixes matter here: v2's TCP-only mode silently under-counted firewalled hosts, which would have skewed recall. The `found via:` field now makes per-host attribution visible in every export, and JSON includes `stats` so drop counts are auditable.

Results will be added to this repository once the experiments are complete.

---

## 📝 Notes and limitations

- **Use `sudo` for `arp`, `hybrid`, `all`, `--tcp-arp` and `--syn`.** Root is required to flush the ARP cache and open raw sockets. Without it, the tool falls back to the `ping` binary and connect scanning.
- **TCP-only cannot see DROP-firewalled hosts.** A host that silently discards SYNs on all 25 discovery ports looks dead to `-m tcp`. This is not a bug — it is the nature of TCP discovery. Use `--tcp-arp`, `-m hybrid`, or widen `--discovery-ports`.
- **ARP works only on the local subnet.** NetScan detects routed targets and disables ARP automatically with a warning.
- **Large ARP sweeps.** The Linux neighbour table defaults to ~1024 entries (`gc_thresh3`), so keep ARP sweeps to a `/24` or lower `--rate-limit`.
- **Passive ARP entries.** A device that broadcasts its own ARP traffic can appear in the ARP table without being probed. `--no-flush` keeps stale entries; without root, flushing is impossible and ghosts are possible.
- **UDP is the least reliable method.** Many devices stay silent, and Linux rate-limits ICMP port-unreachable replies. Treat `-m udp` as a supplement, not a replacement.
- **OS guessing uses TTL only**, so treat it as a rough hint.
- **TCP scanning only** for open ports. UDP port scanning is not implemented.
- **`--nmap` runs per-host with a 30 s timeout.** On a very large live-host set, nmap dominates the runtime; the native detector is enough for most LANs.

---

## 🔧 Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| Only 4 hosts found with `-m tcp` | 25 ports probed; firewalls DROP them | Add `--tcp-arp` or use `-m hybrid` |
| 0 hosts found | Not on-link + ICMP blocked | Use `-m tcp` or `-m udp` with wide ports |
| `[!] Not root: ARP cache not flushed` | No sudo | Run with `sudo`, or ignore (stale entries possible) |
| `[!] Target not on a directly connected subnet; ARP disabled` | Routed target | Expected — use ICMP/TCP/UDP |
| `[!] --syn requires root; falling back to connect scan` | No sudo | Run with `sudo` or accept connect scan |
| `[!] N fd-exhaustion events` in summary | Concurrency too high for `ulimit -n` | `ulimit -n 65535` or `-c 200` |
| `[!] --nmap requested but nmap not installed` | Missing binary | `sudo apt install nmap` |
| Hosts alive but no ports listed | All scanned ports filtered | `-p all` or `-p top,8000-9000` |
| Scan takes forever on `-p all` | Full connect to 65535 ports | Use `--syn` (root) or narrow `-p` |

**Diagnostic: compare discovery methods**

```bash
# Ground truth on a local subnet
sudo python3 netscan.py 192.168.10.0/24 -m arp  --discovery-only --show-down > arp.txt

# Your failing case
python3 netscan.py 192.168.10.0/24 -m tcp  --discovery-only --show-down > tcp.txt

# What's in arp.txt but not tcp.txt = hosts TCP can't see
diff arp.txt tcp.txt
```

If the gap is non-empty, those hosts are alive but dropping TCP — that's the structural limit, not a bug.

---

## 🗒️ Changelog

### v3.1

**Accuracy fixes**
- Fixed: TCP-only discovery under-counted firewalled hosts. Added `--tcp-arp`; `hybrid` made the recommended default.
- Fixed: wrong TTLs from ICMP sequence collision (per-probe 32-bit nonce added, stale replies discarded).
- Fixed: mid-scan ARP read didn't mark hosts alive (now sets `alive` and appends `"arp"`).
- Fixed: double ARP sweep in `arp` mode (removed always-true `(X or True)` condition).
- Fixed: MySQL misidentification (strict `data[3]==0` and `data[4] in {0x09,0x0A}`).
- Fixed: `tcp_dropped` not counted during port scan.
- Fixed: raw-socket leaks across repeated runs (`_ICMP`/`_SYN` closed in `finally`).
- Fixed: 10-minute nmap hang on filtered hosts (`-T4 --host-timeout 30s`, 90 s subprocess cap).

**Speed**
- Memoized `_local_ip_for` (was ~250k socket open/close on a `/24 × 1000 ports` SYN scan).
- Parallel port scan across hosts, not just across ports.
- Single ARP sweep.
- Terminal-width-aware progress output.

**New features**
- `--xml FILE` — nmap-compatible XML with `<state>` for every scanned port.
- `--md FILE` — human-readable Markdown report.
- `--tcp-arp` — ARP assist for TCP mode.
- `--discovery-ports SPEC` — override the 25-port discovery set.
- `--rate-limit N`, `--retries N`, `--verbose`.

### v3.0
- Added active ARP sweep to `hybrid` and `all` modes.
- Added raw ICMP socket (no fork storm, 512 concurrent pings).
- Added SYN half-open scanning (`--syn`).
- Added expanded 25-port discovery set.
- Added mid-scan ARP re-read.
- Added exponential-backoff retry on FD exhaustion.
- Added `stats` block to JSON export.

### v2.0
- Added `--mode` with `icmp`, `tcp`, `arp`, `udp`, `hybrid` and `all`.
- ARP mode now sends real ARP requests instead of only reading the cache.
- Added UDP discovery with protocol probes and ICMP port-unreachable detection.
- Added `--discovery-only`, `--udp-timeout`, `--arp-wait` and `--no-flush`.
- JSON export includes run settings and discovery time; CSV has a `found_via` column.
- Report shows the mode and the discovery time.

### v1.0
- Hybrid discovery (ICMP, TCP, ARP cache), async port scan, banner-based version detection, optional nmap, JSON/CSV export.

---

## ⚠️ Legal disclaimer

This tool is for **educational purposes and authorized security testing only**. Only scan networks and devices that you **own** or have **explicit written permission** to test. The author is not responsible for misuse.

---

## 🤝 Contributing

Ideas and pull requests are welcome. Open an issue for bugs or features. On the roadmap:

- IPv6 support
- UDP port scanning
- MAC vendor lookup (OUI database)
- Parallel nmap workers across hosts
- Configurable OS fingerprinting (beyond TTL)

When filing a bug, please include:

- The command you ran
- The `--show-down` output for `-m arp` and the failing mode
- The summary line (including any `[!] dropped due to errors` line)
- Your `ulimit -n` and whether you used `sudo`

---

## 📄 License

Released under the [MIT License](LICENSE).

---

<div align="center">

If you find this project useful, please give it a ⭐ on GitHub!

</div>