#!/usr/bin/env python3
"""
netscan.py - Hybrid network block scanner for Linux (v2: selectable discovery modes).

Discovery modes (--mode)
  icmp    ICMP echo (ping) only
  tcp     TCP connect probes only (SYN/ACK or RST both prove the host is up)
  arp     ARP only: the kernel is forced to ARP every address, then the ARP table is read
  udp     UDP only: protocol probes (DNS, NTP, NetBIOS, SNMP, SSDP, mDNS) plus closed-port
          probes (ICMP port-unreachable proves the host is up)
  hybrid  ICMP, then TCP, then the ARP table (the original NetScan behaviour, default)
  all     hybrid + UDP

Port scanning and version detection run on live hosts afterwards (skip with --discovery-only).

Only scan networks you own or are explicitly authorised to test.

Examples
  python3 netscan.py 192.168.1.0/24
  python3 netscan.py 192.168.1.0/24 --mode icmp --discovery-only --json icmp.json
  sudo python3 netscan.py 192.168.1.0/24 --mode arp --discovery-only
  python3 netscan.py 192.168.1.0/24 --mode udp --udp-timeout 2 --discovery-only
  python3 netscan.py 10.0.0.0/24 --ports 1-1024 --nmap
"""
import argparse
import asyncio
import csv
import ipaddress
import json
import math
import os
import re
import resource
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 119, 123, 135, 137, 139, 143, 161,
    389, 443, 445, 465, 500, 514, 515, 548, 554, 587, 631, 636, 873, 993, 995,
    1080, 1194, 1433, 1521, 1723, 1883, 2049, 2375, 3000, 3128, 3306, 3389, 3690,
    4443, 5000, 5060, 5432, 5601, 5672, 5900, 5985, 6379, 6443, 7001, 8000, 8008,
    8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 27017, 32400, 51820,
]
DISCOVERY_PORTS = [80, 443, 22, 445, 139, 135, 3389, 53, 21, 23, 8080, 5900]
HTTP_PORTS = {80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 9200, 10000, 32400}
TLS_PORTS = {443, 465, 636, 993, 995, 4443, 5601, 6443, 8443}
MODES = ("hybrid", "icmp", "tcp", "arp", "udp", "all")

# UDP discovery probes: (port, payload). A reply, or an ICMP port-unreachable, proves the host is up.
UDP_PROBES = [
    (53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"),  # DNS
    (123, b"\x1b" + b"\x00" * 47),  # NTP client request
    (137, b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20" + b"CK" + b"A" * 30 + b"\x00\x00\x21\x00\x01"),  # NetBIOS
    (161, b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
          b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"),  # SNMP v1 get
    (1900, b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'),  # SSDP/UPnP
    (5353, b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x80\x01"),  # mDNS
    (33434, b"\x00"),  # closed-port probes: a live host usually answers with ICMP port-unreachable
    (40125, b"\x00"),
]


@dataclass
class PortInfo:
    port: int
    proto: str = "tcp"
    service: str = "unknown"
    version: str = ""
    tls: bool = False


@dataclass
class Host:
    ip: str
    alive: bool = False
    via: list = field(default_factory=list)
    hostname: str = ""
    mac: str = ""
    ttl: int = 0
    os_guess: str = ""
    ports: list = field(default_factory=list)


# ----------------------------------------------------------------- helpers
def raise_fd_limit():
    soft = 1024
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = 65535 if hard == resource.RLIM_INFINITY else min(hard, 65535)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        return target
    except (ValueError, OSError):
        return soft


def parse_ports(spec):
    if spec == "top":
        return list(COMMON_PORTS)
    if spec == "all":
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"invalid port(s): {bad[:5]}")
    return sorted(ports)


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def os_guess(ttl):
    if not ttl:
        return "unknown"
    if ttl <= 64:
        return "Linux/Unix/macOS/Android"
    if ttl <= 128:
        return "Windows"
    return "Network device/Solaris"


def read_arp():
    """Completed entries (flag 0x2) of the kernel ARP table."""
    table = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) >= 4 and p[2] == "0x2" and p[3] != "00:00:00:00:00:00":
                    table[p[0]] = p[3]
    except OSError:
        pass
    return table


def local_networks():
    """Directly connected IPv4 networks (no gateway) from /proc/net/route."""
    nets = []
    try:
        with open("/proc/net/route") as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) < 8:
                    continue
                dest, gw, flags, mask = int(p[1], 16), int(p[2], 16), int(p[3], 16), int(p[7], 16)
                if gw == 0 and flags & 1 and mask:
                    addr = socket.inet_ntoa(struct.pack("<L", dest))
                    nm = socket.inet_ntoa(struct.pack("<L", mask))
                    nets.append(ipaddress.ip_network(f"{addr}/{nm}", strict=False))
    except (OSError, ValueError):
        pass
    return nets


def flush_arp(net):
    """Empty the ARP/neighbour entries for the target so stale entries cannot count as live hosts."""
    if os.geteuid() != 0:
        return False
    try:
        subprocess.run(["ip", "neigh", "flush", "to", str(net)], capture_output=True, timeout=15)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


# --------------------------------------------------------------- discovery
async def ping(ip, timeout):
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", str(max(1, math.ceil(timeout))), ip,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout + 2)
    except FileNotFoundError:
        return False, 0
    except asyncio.TimeoutError:
        if proc:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        return False, 0
    if proc.returncode == 0:
        m = re.search(rb"ttl=(\d+)", out, re.I)
        return True, int(m.group(1)) if m else 0
    return False, 0


async def tcp_alive(ip, port, timeout):
    """True if the host answers on this port (open OR refused/RST => host is up)."""
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return True
    except ConnectionRefusedError:
        return True
    except (asyncio.TimeoutError, OSError):
        return False


class _UDPProbe(asyncio.DatagramProtocol):
    """Resolves to 'reply' on any answer, 'refused' on ICMP port-unreachable."""

    def __init__(self, fut):
        self.fut = fut

    def datagram_received(self, data, addr):
        if not self.fut.done():
            self.fut.set_result("reply")

    def error_received(self, exc):
        if not self.fut.done():
            self.fut.set_result("refused" if isinstance(exc, ConnectionRefusedError) else "error")


async def udp_probe(ip, port, payload, timeout):
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    try:
        transport, _ = await loop.create_datagram_endpoint(lambda: _UDPProbe(fut), remote_addr=(ip, port))
    except OSError:
        return False
    try:
        transport.sendto(payload)
        res = await asyncio.wait_for(fut, timeout)
        return res in ("reply", "refused")
    except (asyncio.TimeoutError, OSError):
        return False
    finally:
        transport.close()


async def udp_alive(ip, timeout):
    res = await asyncio.gather(*(udp_probe(ip, p, payload, timeout) for p, payload in UDP_PROBES))
    return any(res)


async def arp_sweep(ips, wait):
    """Force the kernel to ARP-resolve every address.

    Sending any datagram to an on-link address makes the kernel broadcast an ARP request.
    Hosts that answer get a completed entry in the ARP table, whatever their firewall
    does with ICMP/TCP/UDP. The payload itself is irrelevant to the result.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        for i, ip in enumerate(ips, 1):
            try:
                sock.sendto(b"\x00", (ip, 9))
            except OSError:
                pass
            if i % 64 == 0:
                await asyncio.sleep(0.05)
        await asyncio.sleep(wait)
    finally:
        sock.close()


async def discover(host, args, sem, ping_sem):
    mode = args.mode
    async with sem:
        if mode in ("icmp", "hybrid", "all") and not args.no_ping:
            async with ping_sem:
                ok, ttl = await ping(host.ip, args.timeout)
            if ok:
                host.alive = True
                host.via.append("icmp")
                host.ttl = ttl
        if mode in ("tcp", "hybrid", "all") and not host.alive:
            res = await asyncio.gather(*(tcp_alive(host.ip, p, args.timeout) for p in DISCOVERY_PORTS))
            if any(res):
                host.alive = True
                host.via.append("tcp")
        if mode in ("udp", "all") and not host.alive:
            if await udp_alive(host.ip, args.udp_timeout):
                host.alive = True
                host.via.append("udp")


# ------------------------------------------------------------ port scanning
async def check_port(ip, port, timeout, sem):
    async with sem:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            return port
        except (asyncio.TimeoutError, OSError):
            return None


# --------------------------------------------------------- service version
async def fetch_banner(ip, port, timeout):
    """Return (data, used_tls)."""
    modes = [True, False] if port in TLS_PORTS else [False]
    for tls in modes:
        ctx = None
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx), timeout * 3)
        except Exception:
            continue
        data = b""
        try:
            if not tls and port not in HTTP_PORTS:
                try:
                    data = await asyncio.wait_for(reader.read(512), 1.2)
                except asyncio.TimeoutError:
                    data = b""
            if not data:
                writer.write(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: netscan\r\n\r\n".encode())
                await writer.drain()
                try:
                    data = await asyncio.wait_for(reader.read(2048), 2.0)
                except asyncio.TimeoutError:
                    pass
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        return data, tls
    return b"", False


def identify(port, data, tls):
    """Turn raw banner bytes into (service, version)."""
    service = service_name(port)
    if not data:
        return ("https" if tls else service), ""
    text = data.decode("latin-1", "replace")
    first = text.splitlines()[0].strip() if text.splitlines() else ""

    if text.startswith("SSH-"):
        m = re.match(r"SSH-[\d.]+-(\S+)(?:\s+(.*))?", first)
        ver = (m.group(1).replace("_", " ") + (f" ({m.group(2)})" if m and m.group(2) else "")) if m else first
        return "ssh", ver
    if text.startswith("HTTP/"):
        headers = {}
        for line in text.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        ver = headers.get("server", "")
        if headers.get("x-powered-by"):
            ver = f"{ver} [{headers['x-powered-by']}]".strip()
        return ("https" if tls else "http"), (ver or f"({first})")
    if re.match(r"^220[ -]", first):
        low = first.lower()
        svc = "ftp" if ("ftp" in low or port == 21) else "smtp"
        return svc, first[4:].strip()[:90]
    if first.startswith("+OK"):
        return "pop3", first[3:].strip()[:90]
    if first.startswith("* OK"):
        return "imap", first[4:].strip()[:90]
    if first.startswith("RFB "):
        return "vnc", "protocol " + first[4:].strip()
    if len(data) > 5 and data[4] == 0x0A:  # MySQL/MariaDB handshake
        end = data.find(b"\x00", 5)
        if end > 5:
            return "mysql", data[5:end].decode("latin-1", "replace")
    printable = "".join(c if 32 <= ord(c) < 127 else " " for c in first).strip()
    return service, printable[:90]


async def detect_service(ip, port, timeout, sem):
    async with sem:
        data, tls = await fetch_banner(ip, port, timeout)
    svc, ver = identify(port, data, tls)
    return PortInfo(port=port, service=svc, version=ver, tls=tls)


def nmap_detect(ip, ports, nmap_path):
    cmd = [nmap_path, "-sV", "-Pn", "-n", "-p", ",".join(map(str, ports)), "-oX", "-", ip]
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=600).stdout
        root = ET.fromstring(out)
    except (subprocess.SubprocessError, ET.ParseError, OSError):
        return {}
    result = {}
    for p in root.iter("port"):
        svc = p.find("service")
        if svc is None:
            continue
        ver = " ".join(x for x in [svc.get("product"), svc.get("version"),
                                   f"({svc.get('extrainfo')})" if svc.get("extrainfo") else None] if x)
        result[int(p.get("portid"))] = (svc.get("name", "unknown"), ver)
    return result


async def resolve_name(ip):
    loop = asyncio.get_running_loop()
    try:
        name = await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), 2.0)
        return name[0]
    except Exception:
        return ""


# ------------------------------------------------------------------- main
def progress(msg):
    sys.stderr.write("\r" + msg.ljust(70))
    sys.stderr.flush()


async def run(args):
    net = ipaddress.ip_network(args.target, strict=False)
    if net.version != 4:
        sys.exit("Only IPv4 blocks are supported.")
    ips = [str(h) for h in net.hosts()] or [str(net.network_address)]
    if len(ips) > 65536 and not args.force:
        sys.exit(f"{len(ips)} addresses is large. Re-run with --force if you are sure.")
    ports = parse_ports(args.ports)

    fd_limit = raise_fd_limit()
    conc = max(10, min(args.concurrency, fd_limit - 200))
    sem = asyncio.Semaphore(conc)
    ping_sem = asyncio.Semaphore(64)
    hosts = {ip: Host(ip) for ip in ips}
    uses_arp = args.mode in ("arp", "hybrid", "all")

    print(f"[*] Mode: {args.mode} | target {net} ({len(ips)} addresses)", file=sys.stderr)
    if uses_arp:
        if args.no_flush:
            print("[!] ARP cache not flushed (--no-flush): stale entries may count as live hosts", file=sys.stderr)
        elif flush_arp(net):
            print("[*] ARP cache flushed for the target range", file=sys.stderr)
        else:
            print("[!] Not root: could not flush the ARP cache, so stale entries may count as live hosts. "
                  "Run with sudo for clean research results.", file=sys.stderr)
    if args.mode == "arp":
        if not any(net.overlaps(n) for n in local_networks()):
            print("[!] Target is not on a directly connected subnet; ARP only works on the local segment",
                  file=sys.stderr)
        if len(ips) > 1000:
            print("[!] Large range: the kernel neighbour table (gc_thresh3, default 1024) may drop entries",
                  file=sys.stderr)

    t0 = time.time()

    # 1. discovery
    if args.mode == "arp":
        progress(f"[discovery] ARP sweep of {len(ips)} addresses (waiting {args.arp_wait}s)")
        await arp_sweep(ips, args.arp_wait)
    else:
        tasks = [asyncio.create_task(discover(h, args, sem, ping_sem)) for h in hosts.values()]
        done = 0
        for t in asyncio.as_completed(tasks):
            await t
            done += 1
            if done % 8 == 0 or done == len(tasks):
                progress(f"[discovery] {done}/{len(tasks)}")
    arp = read_arp()
    for ip, mac in arp.items():
        if ip in hosts:
            h = hosts[ip]
            h.mac = mac
            if uses_arp and not h.alive:
                h.alive = True
                h.via.append("arp")
    sys.stderr.write("\n")
    disc_time = time.time() - t0
    live = [h for h in hosts.values() if h.alive]
    print(f"[*] {len(live)} live host(s) found in {disc_time:.2f}s", file=sys.stderr)

    if not args.discovery_only:
        # 2. port scan
        for i, h in enumerate(live, 1):
            progress(f"[ports] {h.ip} ({i}/{len(live)})")
            res = await asyncio.gather(*(check_port(h.ip, p, args.timeout, sem) for p in ports))
            h.ports = [PortInfo(port=p) for p in res if p]
        sys.stderr.write("\n")

        # 3. service/version detection
        dsem = asyncio.Semaphore(min(conc, 200))
        for h in live:
            if h.ports:
                progress(f"[versions] {h.ip}")
                h.ports = list(await asyncio.gather(
                    *(detect_service(h.ip, p.port, args.timeout, dsem) for p in h.ports)))
        sys.stderr.write("\n")

        nmap_path = shutil.which("nmap") if args.nmap else None
        if args.nmap and not nmap_path:
            print("[!] --nmap requested but nmap is not installed; using native detection only", file=sys.stderr)
        if nmap_path:
            for h in live:
                if h.ports:
                    progress(f"[nmap -sV] {h.ip}")
                    info = await asyncio.to_thread(nmap_detect, h.ip, [p.port for p in h.ports], nmap_path)
                    for p in h.ports:
                        if p.port in info:
                            name, ver = info[p.port]
                            p.service = name or p.service
                            if ver:
                                p.version = ver
            sys.stderr.write("\n")

    # 4. enrich
    names = await asyncio.gather(*(resolve_name(h.ip) for h in live))
    for h, n in zip(live, names):
        h.hostname = n
        h.os_guess = os_guess(h.ttl)

    report(net, hosts, args, time.time() - t0, disc_time)
    export(net, hosts, args, disc_time)


def report(net, hosts, args, elapsed, disc_time):
    live = [h for h in hosts.values() if h.alive]
    down = [h for h in hosts.values() if not h.alive]
    bar = "=" * 78
    print(f"\n{bar}\n LIVE HOSTS ({len(live)})   mode: {args.mode}   discovery time: {disc_time:.2f}s\n{bar}")
    for h in live:
        title = h.ip + (f"  ({h.hostname})" if h.hostname else "")
        print(f"\n{title}")
        meta = [f"found via: {','.join(h.via)}"]
        if h.mac:
            meta.append(f"MAC: {h.mac}")
        if h.ttl:
            meta.append(f"OS guess: {h.os_guess} (ttl {h.ttl})")
        print("  " + " | ".join(meta))
        if args.discovery_only:
            continue
        if h.ports:
            print(f"  {'PORT':<10}{'SERVICE':<12}VERSION / BANNER")
            for p in h.ports:
                print(f"  {str(p.port) + '/tcp':<10}{p.service:<12}{p.version}")
        else:
            print("  no open ports among scanned ports")
    print(f"\n{bar}\n NO RESPONSE / CLOSED HOSTS ({len(down)})\n{bar}")
    if args.show_down:
        line = ""
        for h in down:
            if len(line) + len(h.ip) + 2 > 78:
                print(line)
                line = ""
            line += h.ip + ", "
        if line:
            print(line.rstrip(", "))
    else:
        print(" (use --show-down to list them)")
    total_open = sum(len(h.ports) for h in live)
    print(f"\nDone: {len(live)} up, {len(down)} down, {total_open} open ports in {elapsed:.1f}s "
          f"(discovery {disc_time:.2f}s)")


def export(net, hosts, args, disc_time):
    live = [h for h in hosts.values() if h.alive]
    if args.json:
        meta = {
            "target": str(net), "mode": args.mode, "timeout": args.timeout,
            "udp_timeout": args.udp_timeout, "arp_wait": args.arp_wait,
            "concurrency": args.concurrency, "discovery_seconds": round(disc_time, 3),
            "live_hosts": len(live), "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        with open(args.json, "w") as f:
            json.dump({"meta": meta, "hosts": [asdict(h) for h in hosts.values()]}, f, indent=2)
        print(f"JSON saved to {args.json}")
    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ip", "hostname", "mac", "os_guess", "found_via", "port", "service", "version"])
            for h in live:
                via = "+".join(h.via)
                if h.ports:
                    for p in h.ports:
                        w.writerow([h.ip, h.hostname, h.mac, h.os_guess, via, p.port, p.service, p.version])
                else:
                    w.writerow([h.ip, h.hostname, h.mac, h.os_guess, via, "", "", ""])
        print(f"CSV saved to {args.csv}")


def main():
    ap = argparse.ArgumentParser(description="Hybrid Linux network block scanner")
    ap.add_argument("target", help="network block in CIDR form, e.g. 192.168.1.0/24")
    ap.add_argument("-m", "--mode", choices=MODES, default="hybrid",
                    help="host discovery method: icmp, tcp, arp, udp, hybrid (default) or all")
    ap.add_argument("-p", "--ports", default="top",
                    help="'top' (default), 'all', or list/ranges like 22,80,8000-9000")
    ap.add_argument("-t", "--timeout", type=float, default=1.0, help="ICMP/TCP timeout seconds (default 1.0)")
    ap.add_argument("--udp-timeout", type=float, default=1.5, help="UDP probe timeout seconds (default 1.5)")
    ap.add_argument("--arp-wait", type=float, default=2.0,
                    help="seconds to wait for ARP replies in arp mode (default 2.0)")
    ap.add_argument("-c", "--concurrency", type=int, default=500, help="parallel connections (default 500)")
    ap.add_argument("--discovery-only", action="store_true",
                    help="only find live hosts: skip port scan and version detection")
    ap.add_argument("--nmap", action="store_true", help="use nmap -sV for deeper version detection if installed")
    ap.add_argument("--no-ping", action="store_true", help="skip ICMP in hybrid/all; rely on the other methods")
    ap.add_argument("--no-flush", action="store_true", help="do not flush the ARP cache before arp/hybrid/all")
    ap.add_argument("--show-down", action="store_true", help="list the non-responding IPs")
    ap.add_argument("--json", metavar="FILE", help="save full results (with run settings) as JSON")
    ap.add_argument("--csv", metavar="FILE", help="save results as CSV")
    ap.add_argument("--force", action="store_true", help="allow scanning more than 65536 addresses")
    args = ap.parse_args()
    if args.no_ping and args.mode == "icmp":
        ap.error("--no-ping cannot be combined with --mode icmp")
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        sys.exit("\nInterrupted.")
    except ValueError as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()
