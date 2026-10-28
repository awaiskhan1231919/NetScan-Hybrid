#!/usr/bin/env python3
"""
netscan.py - Hybrid network block scanner for Linux.

Hybrid design
  * Host discovery : ICMP ping + TCP connect probes + ARP cache (any one proves a host is up)
  * Port scanning  : fast native asyncio TCP connect scanner
  * Version detect : native banner grabbing (SSH/HTTP/FTP/SMTP/MySQL/...) and,
                     optionally, the nmap engine (-sV) for deeper detection

Output: live hosts (IP, hostname, MAC, OS guess), their open ports with
service name + software version, and the list of hosts that did not respond.

Only scan networks you own or are explicitly authorised to test.

Examples
  python3 netscan.py 192.168.1.0/24
  python3 netscan.py 10.0.0.0/24 --ports 1-1024 --nmap
  python3 netscan.py 192.168.1.0/24 --ports all --json out.json --csv out.csv --show-down
"""
import argparse
import asyncio
import csv
import ipaddress
import json
import math
import re
import resource
import shutil
import socket
import ssl
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


async def discover(host, args, sem, ping_sem):
    async with sem:
        if not args.no_ping:
            async with ping_sem:
                ok, ttl = await ping(host.ip, args.timeout)
            if ok:
                host.alive = True
                host.via.append("icmp")
                host.ttl = ttl
        if not host.alive:
            res = await asyncio.gather(*(tcp_alive(host.ip, p, args.timeout) for p in DISCOVERY_PORTS))
            if any(res):
                host.alive = True
                host.via.append("tcp")


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
    t0 = time.time()

    # 1. discovery
    print(f"[*] Scanning {net} ({len(ips)} addresses), {len(ports)} ports per live host", file=sys.stderr)
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
            if not h.alive:
                h.alive = True
                h.via.append("arp")
    sys.stderr.write("\n")
    live = [h for h in hosts.values() if h.alive]
    print(f"[*] {len(live)} live host(s) found", file=sys.stderr)

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
            h.ports = list(await asyncio.gather(*(detect_service(h.ip, p.port, args.timeout, dsem) for p in h.ports)))
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

    report(net, hosts, args, time.time() - t0)
    export(hosts, args)


def report(net, hosts, args, elapsed):
    live = [h for h in hosts.values() if h.alive]
    down = [h for h in hosts.values() if not h.alive]
    bar = "=" * 78
    print(f"\n{bar}\n LIVE HOSTS ({len(live)})\n{bar}")
    for h in live:
        title = h.ip + (f"  ({h.hostname})" if h.hostname else "")
        print(f"\n{title}")
        meta = [f"found via: {','.join(h.via)}"]
        if h.mac:
            meta.append(f"MAC: {h.mac}")
        if h.ttl:
            meta.append(f"OS guess: {h.os_guess} (ttl {h.ttl})")
        print("  " + " | ".join(meta))
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
    print(f"\nDone: {len(live)} up, {len(down)} down, {total_open} open ports in {elapsed:.1f}s")


def export(hosts, args):
    live = [h for h in hosts.values() if h.alive]
    if args.json:
        with open(args.json, "w") as f:
            json.dump({"hosts": [asdict(h) for h in hosts.values()]}, f, indent=2)
        print(f"JSON saved to {args.json}")
    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ip", "hostname", "mac", "os_guess", "port", "service", "version"])
            for h in live:
                if h.ports:
                    for p in h.ports:
                        w.writerow([h.ip, h.hostname, h.mac, h.os_guess, p.port, p.service, p.version])
                else:
                    w.writerow([h.ip, h.hostname, h.mac, h.os_guess, "", "", ""])
        print(f"CSV saved to {args.csv}")


def main():
    ap = argparse.ArgumentParser(description="Hybrid Linux network block scanner")
    ap.add_argument("target", help="network block in CIDR form, e.g. 192.168.1.0/24")
    ap.add_argument("-p", "--ports", default="top",
                    help="'top' (default), 'all', or list/ranges like 22,80,8000-9000")
    ap.add_argument("-t", "--timeout", type=float, default=1.0, help="connect timeout seconds (default 1.0)")
    ap.add_argument("-c", "--concurrency", type=int, default=500, help="parallel connections (default 500)")
    ap.add_argument("--nmap", action="store_true", help="use nmap -sV for deeper version detection if installed")
    ap.add_argument("--no-ping", action="store_true", help="skip ICMP; rely on TCP probes and ARP")
    ap.add_argument("--show-down", action="store_true", help="list the non-responding IPs")
    ap.add_argument("--json", metavar="FILE", help="save full results as JSON")
    ap.add_argument("--csv", metavar="FILE", help="save results as CSV")
    ap.add_argument("--force", action="store_true", help="allow scanning more than 65536 addresses")
    args = ap.parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        sys.exit("\nInterrupted.")
    except ValueError as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()
