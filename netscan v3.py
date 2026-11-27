#!/usr/bin/env python3
"""
netscan.py - Hybrid network block scanner for Linux (v3.1: accuracy + speed).

Discovery modes (--mode)
  icmp    ICMP echo only (raw socket, falls back to ping binary)
  tcp     TCP connect/SYN probes only (default: 25 ports, --discovery-ports to override)
  arp     ARP only: force the kernel to ARP every address, then read the table
  udp     UDP protocol + closed-port probes only
  hybrid  ARP sweep + ICMP + TCP (default)
  all     hybrid + UDP

Port scanning and version detection run on live hosts afterwards (skip with --discovery-only).
SYN half-open scanning is available with --syn (requires root).

Only scan networks you own or are explicitly authorised to test.

Examples
  python3 netscan.py 192.168.1.0/24
  sudo python3 netscan.py 192.168.1.0/24 -m arp --discovery-only
  sudo python3 netscan.py 192.168.1.0/24 -m tcp --tcp-arp --discovery-only
  python3 netscan.py 10.0.0.0/24 --ports 1-1024 --syn --nmap --xml out.xml --md report.md
"""
import argparse
import asyncio
import csv
import errno
import ipaddress
import json
import math
import os
import random
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

# ---------------------------------------------------------------- constants
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 119, 123, 135, 137, 139, 143, 161,
    389, 443, 445, 465, 500, 514, 515, 548, 554, 587, 631, 636, 873, 993, 995,
    1080, 1194, 1433, 1521, 1723, 1883, 2049, 2375, 3000, 3128, 3306, 3389, 3690,
    4443, 5000, 5060, 5432, 5601, 5672, 5900, 5985, 6379, 6443, 7001, 8000, 8008,
    8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 27017, 32400, 51820,
]
DISCOVERY_PORTS = [
    80, 443, 22, 445, 139, 135, 3389, 53, 21, 23, 8080, 5900,
    25, 110, 143, 993, 995, 3306, 5432, 6379, 9100, 5000, 8000, 8888, 62078,
]
HTTP_PORTS = {80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 9200, 10000, 32400}
TLS_PORTS = {443, 465, 636, 993, 995, 4443, 5601, 6443, 8443}
MODES = ("hybrid", "icmp", "tcp", "arp", "udp", "all")

UDP_PROBES = [
    (53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"),
    (123, b"\x1b" + b"\x00" * 47),
    (137, b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20" + b"CK" + b"A" * 30 + b"\x00\x00\x21\x00\x01"),
    (161, b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
          b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"),
    (1900, b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'),
    (5353, b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x80\x01"),
    (33434, b"\x00"),
    (40125, b"\x00"),
]

# ---------------------------------------------------------------- dataclasses
@dataclass
class PortInfo:
    port: int
    proto: str = "tcp"
    state: str = "open"
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
    errors: list = field(default_factory=list)

# ---------------------------------------------------------------- globals / stats
STATS = {"emfile": 0, "retries": 0, "tcp_dropped": 0, "udp_dropped": 0}
_LOCAL_IP_CACHE = {}

def _terminal_width(default=90):
    try:
        return shutil.get_terminal_size().columns or default
    except OSError:
        return default

def raise_fd_limit():
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = 65535 if hard == resource.RLIM_INFINITY else min(hard, 65535)
        if soft < target:
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            except (ValueError, OSError):
                pass
        return resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    except (ValueError, OSError):
        return 1024

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
        try:
            if "-" in part:
                a, b = part.split("-", 1)
                a, b = int(a), int(b)
                if a > b:
                    a, b = b, a
                ports.update(range(a, b + 1))
            else:
                ports.add(int(part))
        except ValueError:
            raise ValueError(f"invalid port spec: {part!r} (expected N or N-M)")
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"invalid port(s) out of range: {bad[:5]}")
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
                if len(p) >= 4 and p[3] != "00:00:00:00:00:00" and p[2] in ("0x2", "0x6"):
                    table[p[0]] = p[3]
    except OSError:
        pass
    return table

def local_networks():
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

def is_local(net):
    return any(net.overlaps(n) for n in local_networks())

def flush_arp(net):
    if os.geteuid() != 0:
        return False
    try:
        subprocess.run(["ip", "neigh", "flush", "to", str(net)], capture_output=True, timeout=15)
        return True
    except (OSError, subprocess.SubprocessError):
        return False

def is_fd_error(exc):
    return isinstance(exc, OSError) and exc.errno in (errno.EMFILE, errno.ENFILE, errno.EADDRNOTAVAIL)

def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

# ---------------------------------------------------------------- ICMP (raw)
class ICMPProbe:
    """Shared raw socket for all in-flight pings. Requires root."""
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.sock.setblocking(False)
        self.pending = {}   # (ident, seq) -> (future, nonce)
        self._loop = None
        self._ident = os.getpid() & 0xFFFF

    def _start_reader(self, loop):
        if self._loop is not None:
            return
        self._loop = loop
        loop.add_reader(self.sock.fileno(), self._on_readable)

    def _on_readable(self):
        try:
            data, addr = self.sock.recvfrom(2048)
        except OSError:
            return
        if len(data) < 28:
            return
        ihl = (data[0] & 0x0F) * 4
        icmp = data[ihl:]
        if len(icmp) < 8:
            return
        typ = icmp[0]
        if typ != 0:               # only echo replies
            return
        ident, seq = struct.unpack("!HH", icmp[4:8])
        entry = self.pending.pop((ident, seq), None)
        if not entry:
            return
        fut, nonce = entry
        payload = icmp[8:12]
        if payload != nonce:       # stale reply from a reused seq
            self.pending[(ident, seq)] = entry   # put back? no - discard
            return
        ttl = data[8]
        if not fut.done():
            fut.set_result((True, ttl))

    async def ping(self, ip, timeout):
        loop = asyncio.get_running_loop()
        self._start_reader(loop)
        seq = random.getrandbits(16)
        nonce = struct.pack("!I", random.getrandbits(32))
        pkt = struct.pack("!BBHHH", 8, 0, 0, self._ident, seq) + nonce + b"netscan" + b"\x00" * 4
        pkt = pkt[:2] + struct.pack("!H", _checksum(pkt)) + pkt[4:]
        fut = loop.create_future()
        self.pending[(self._ident, seq)] = (fut, nonce)
        try:
            self.sock.sendto(pkt, (ip, 0))
        except OSError:
            self.pending.pop((self._ident, seq), None)
            return False, 0
        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            self.pending.pop((self._ident, seq), None)
            return False, 0

    def close(self):
        try:
            if self._loop:
                self._loop.remove_reader(self.sock.fileno())
        except (OSError, ValueError):
            pass
        try:
            self.sock.close()
        except OSError:
            pass

_ICMP = None

async def icmp_ping(ip, timeout):
    global _ICMP
    if os.geteuid() == 0:
        try:
            if _ICMP is None:
                _ICMP = ICMPProbe()
            return await _ICMP.ping(ip, timeout)
        except OSError:
            pass
    # fallback: ping binary (no fork storm control here; 512 sems upstream)
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
            try: proc.kill()
            except ProcessLookupError: pass
        return False, 0
    if proc.returncode == 0:
        m = re.search(rb"ttl=(\d+)", out, re.I)
        return True, int(m.group(1)) if m else 0
    return False, 0

# ---------------------------------------------------------------- TCP (connect)
async def tcp_alive(ip, port, timeout, retries=1):
    for attempt in range(retries + 1):
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
            w.close()
            try: await w.wait_closed()
            except Exception: pass
            return True
        except ConnectionRefusedError:
            return True
        except asyncio.TimeoutError:
            return False
        except OSError as e:
            if is_fd_error(e):
                STATS["emfile"] += 1
                await asyncio.sleep(0.05 * (2 ** attempt))
                continue
            return False
    STATS["tcp_dropped"] += 1
    return False

async def check_port(ip, port, timeout, retries=1):
    for attempt in range(retries + 1):
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
            w.close()
            try: await w.wait_closed()
            except Exception: pass
            return port
        except (asyncio.TimeoutError, ConnectionRefusedError):
            return None
        except OSError as e:
            if is_fd_error(e):
                STATS["emfile"] += 1
                await asyncio.sleep(0.05 * (2 ** attempt))
                continue
            return None
    STATS["tcp_dropped"] += 1
    return None

# ---------------------------------------------------------------- SYN (root)
class SynScanner:
    """Raw TCP socket. Matches SYN/ACK or RST on (host, dport, sport)."""
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.sock.setblocking(False)
        self.pending = {}   # (ip, dport, sport) -> future
        self._loop = None

    def _start_reader(self, loop):
        if self._loop is not None:
            return
        self._loop = loop
        loop.add_reader(self.sock.fileno(), self._on_readable)

    def _on_readable(self):
        try:
            data, addr = self.sock.recvfrom(2048)
        except OSError:
            return
        if len(data) < 40:
            return
        ihl = (data[0] & 0x0F) * 4
        tcp = data[ihl:]
        if len(tcp) < 20:
            return
        sport, dport = struct.unpack("!HH", tcp[0:4])
        flags = tcp[13]
        if not (flags & 0x04 or (flags & 0x12) == 0x12):
            return
        fut = self.pending.pop((addr[0], sport, dport), None)
        if fut and not fut.done():
            fut.set_result(True)

    async def scan(self, ip, port, timeout, sport, src):
        loop = asyncio.get_running_loop()
        self._start_reader(loop)
        fut = loop.create_future()
        self.pending[(ip, port, sport)] = fut
        pkt = _build_syn(src, ip, sport, port, 64)
        try:
            self.sock.sendto(pkt, (ip, 0))
        except OSError:
            self.pending.pop((ip, port, sport), None)
            return False
        try:
            await asyncio.wait_for(fut, timeout)
            return True
        except asyncio.TimeoutError:
            self.pending.pop((ip, port, sport), None)
            return False

    def close(self):
        try:
            if self._loop:
                self._loop.remove_reader(self.sock.fileno())
        except (OSError, ValueError):
            pass
        try:
            self.sock.close()
        except OSError:
            pass

def _local_ip_for(ip):
    if ip in _LOCAL_IP_CACHE:
        return _LOCAL_IP_CACHE[ip]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((ip, 80))
        _LOCAL_IP_CACHE[ip] = s.getsockname()[0]
    except OSError:
        _LOCAL_IP_CACHE[ip] = None
    finally:
        s.close()
    return _LOCAL_IP_CACHE[ip]

def _build_syn(src, dst, sport, dport, ttl):
    tcp = struct.pack("!HHIIBBHHH",
                      sport, dport, random.getrandbits(32), 0,
                      5 << 4, 0x02, 1024, 0, 0)
    iph = struct.pack("!BBHHHBBH4s4s",
                      0x45, 0, 20 + len(tcp), random.getrandbits(16), 0, ttl, 6, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    iph = iph[:10] + struct.pack("!H", _checksum(iph)) + iph[12:]
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcpc = tcp[:16] + b"\x00\x00" + tcp[18:]
    csum = _checksum(pseudo + tcpc)
    tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]
    return iph + tcp

_SYN = None

async def syn_check(ip, port, timeout, sem):
    global _SYN
    if os.geteuid() == 0:
        try:
            if _SYN is None:
                _SYN = SynScanner()
            src = _local_ip_for(ip)
            if src is None:
                return await check_port(ip, port, timeout)
            sport = random.randint(40000, 60000)
            ok = await _SYN.scan(ip, port, timeout, sport, src)
            return port if ok else None
        except OSError:
            pass
    return await check_port(ip, port, timeout)

# ---------------------------------------------------------------- UDP
class _UDPProbe(asyncio.DatagramProtocol):
    def __init__(self, fut):
        self.fut = fut
    def datagram_received(self, data, addr):
        if not self.fut.done():
            self.fut.set_result("reply")
    def error_received(self, exc):
        if not self.fut.done():
            self.fut.set_result("refused" if isinstance(exc, ConnectionRefusedError) else "error")

async def udp_probe(ip, port, payload, timeout, retries=1):
    for attempt in range(retries + 1):
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPProbe(fut), remote_addr=(ip, port))
        except OSError as e:
            if is_fd_error(e):
                STATS["emfile"] += 1
                await asyncio.sleep(0.05 * (2 ** attempt))
                continue
            return False
        try:
            transport.sendto(payload)
            res = await asyncio.wait_for(fut, timeout)
            return res in ("reply", "refused")
        except (asyncio.TimeoutError, OSError):
            return False
        finally:
            transport.close()
    STATS["udp_dropped"] += 1
    return False

async def udp_alive(ip, timeout, retries=1):
    res = await asyncio.gather(*(udp_probe(ip, p, pl, timeout, retries) for p, pl in UDP_PROBES))
    return any(res)

# ---------------------------------------------------------------- ARP
async def arp_sweep(ips, wait, rate_limit=200):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        n = 0
        for ip in ips:
            try:
                sock.sendto(b"\x00", (ip, 9))
            except OSError:
                pass
            n += 1
            if n % rate_limit == 0:
                await asyncio.sleep(0.05)
        await asyncio.sleep(wait)
    finally:
        sock.close()

# ---------------------------------------------------------------- discovery
async def discover(host, args, sem, ping_sem, ports):
    mode = args.mode
    retries = args.retries
    async with sem:
        if mode in ("icmp", "hybrid", "all") and not args.no_ping:
            async with ping_sem:
                ok, ttl = await icmp_ping(host.ip, args.timeout)
            if ok:
                host.alive = True
                host.via.append("icmp")
                host.ttl = ttl
        if mode in ("tcp", "hybrid", "all") and not host.alive:
            results = await asyncio.gather(*(tcp_alive(host.ip, p, args.timeout, retries) for p in ports))
            if any(results):
                host.alive = True
                host.via.append("tcp")
        if mode in ("udp", "all") and not host.alive:
            if await udp_alive(host.ip, args.udp_timeout, retries):
                host.alive = True
                host.via.append("udp")

# ---------------------------------------------------------------- service / version
async def fetch_banner(ip, port, timeout):
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
    if first.startswith("$-1") or text.startswith("-ERR"):
        return "redis", first[:90]
    # MySQL: [3B len][1B seq=0][1B proto 0x0A]...
    if len(data) > 5 and data[3] == 0x00 and data[4] in (0x09, 0x0A):
        end = data.find(b"\x00", 5)
        if end > 5:
            return "mysql", data[5:end].decode("latin-1", "replace")
    if text.strip().startswith("{"):
        return service, first[:120]
    printable = "".join(c if 32 <= ord(c) < 127 else " " for c in first).strip()
    return service, printable[:90]

async def detect_service(ip, port, timeout, sem):
    async with sem:
        data, tls = await fetch_banner(ip, port, timeout)
    svc, ver = identify(port, data, tls)
    return PortInfo(port=port, service=svc, version=ver, tls=tls)

def nmap_detect(ip, ports, nmap_path):
    cmd = [nmap_path, "-sV", "-Pn", "-n", "-T4", "--host-timeout", "30s",
           "-p", ",".join(map(str, ports)), "-oX", "-", ip]
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=90).stdout
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

# ---------------------------------------------------------------- main
def progress(msg):
    w = _terminal_width()
    sys.stderr.write("\r" + msg[:w - 1].ljust(w - 1))
    sys.stderr.flush()

async def run(args):
    global _ICMP, _SYN
    net = ipaddress.ip_network(args.target, strict=False)
    if net.version != 4:
        sys.exit("Only IPv4 blocks are supported.")
    ips = [str(h) for h in net.hosts()] or [str(net.network_address)]
    if len(ips) > 65536 and not args.force:
        sys.exit(f"{len(ips)} addresses is large. Re-run with --force if you are sure.")
    ports = parse_ports(args.ports)

    fd_limit = raise_fd_limit()
    conc = max(10, min(args.concurrency, fd_limit - 200))
    if conc < args.concurrency and args.verbose:
        print(f"[!] Concurrency reduced to {conc} (fd limit {fd_limit})", file=sys.stderr)
    sem = asyncio.Semaphore(conc)
    ping_sem = asyncio.Semaphore(512)
    hosts = {ip: Host(ip) for ip in ips}
    uses_arp = args.mode in ("arp", "hybrid", "all") or args.tcp_arp
    on_link = is_local(net)

    print(f"[*] Mode: {args.mode} | target {net} ({len(ips)} addresses) | "
          f"concurrency {conc} | on-link {on_link}", file=sys.stderr)
    if uses_arp:
        if not on_link:
            print("[!] Target not on a directly connected subnet; ARP disabled", file=sys.stderr)
            uses_arp = False
        else:
            if args.no_flush:
                print("[!] ARP cache not flushed (--no-flush)", file=sys.stderr)
            elif flush_arp(net):
                print("[*] ARP cache flushed", file=sys.stderr)
            else:
                print("[!] Not root: ARP cache not flushed", file=sys.stderr)

    t0 = time.time()
    disc_ports = DISCOVERY_PORTS
    if args.discovery_ports:
        disc_ports = parse_ports(args.discovery_ports)

    # 1. ARP sweep (once)
    if uses_arp:
        progress(f"[discovery] ARP sweep of {len(ips)} addresses (wait {args.arp_wait}s)")
        await arp_sweep(ips, args.arp_wait, args.rate_limit)

    # 2. non-ARP discovery (or nothing if mode == arp)
    if args.mode != "arp":
        tasks = [asyncio.create_task(discover(h, args, sem, ping_sem, disc_ports))
                 for h in hosts.values()]
        done = 0
        mid_every = max(1, len(tasks) // 4)
        for t in asyncio.as_completed(tasks):
            await t
            done += 1
            if done % 32 == 0:
                progress(f"[discovery] {done}/{len(tasks)}")
            if done % mid_every == 0:
                # mid-scan ARP merge — also marks alive
                for ip, mac in read_arp().items():
                    if ip in hosts:
                        h = hosts[ip]
                        if not h.mac:
                            h.mac = mac
                        if uses_arp and not h.alive:
                            h.alive = True
                            h.via.append("arp")

    # 3. final ARP merge
    for ip, mac in read_arp().items():
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
    if STATS["emfile"]:
        print(f"[!] {STATS['emfile']} fd-exhaustion events (results may be incomplete)", file=sys.stderr)

    if not args.discovery_only:
        use_syn = args.syn and os.geteuid() == 0
        if args.syn and not use_syn:
            print("[!] --syn requires root; falling back to connect scan", file=sys.stderr)

        # 4. port scan — bounded parallelism across hosts AND ports
        scan_sem = asyncio.Semaphore(conc)
        async def scan_host(h, idx):
            progress(f"[ports] {h.ip} ({idx}/{len(live)}) {'SYN' if use_syn else 'connect'}")
            if use_syn:
                res = await asyncio.gather(*(syn_check(h.ip, p, args.timeout, scan_sem) for p in ports))
            else:
                res = await asyncio.gather(*(check_port(h.ip, p, args.timeout, args.retries) for p in ports))
            h.ports = [PortInfo(port=p) for p in res if p]
            return h
        await asyncio.gather(*(scan_host(h, i) for i, h in enumerate(live, 1)))
        sys.stderr.write("\n")

        # 5. service / version
        dsem = asyncio.Semaphore(min(conc, 200))
        for h in live:
            if h.ports:
                progress(f"[versions] {h.ip}")
                h.ports = list(await asyncio.gather(
                    *(detect_service(h.ip, p.port, args.timeout, dsem) for p in h.ports)))
        sys.stderr.write("\n")

        nmap_path = shutil.which("nmap") if args.nmap else None
        if args.nmap and not nmap_path:
            print("[!] --nmap requested but nmap not installed; native detection only", file=sys.stderr)
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

    # 6. enrich
    names = await asyncio.gather(*(resolve_name(h.ip) for h in live))
    for h, n in zip(live, names):
        h.hostname = n
        h.os_guess = os_guess(h.ttl)

    report(net, hosts, args, time.time() - t0, disc_time, ports)
    export(net, hosts, args, disc_time, ports)

def report(net, hosts, args, elapsed, disc_time, scanned_ports):
    live = [h for h in hosts.values() if h.alive]
    down = [h for h in hosts.values() if not h.alive]
    bar = "=" * 78
    print(f"\n{bar}\n LIVE HOSTS ({len(live)})   mode: {args.mode}   discovery: {disc_time:.2f}s\n{bar}")
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
    suffix = " (discovery only)" if args.discovery_only else ""
    print(f"\nDone: {len(live)} up, {len(down)} down, {total_open} open ports in {elapsed:.1f}s "
          f"(discovery {disc_time:.2f}s){suffix}")
    if STATS["emfile"] or STATS["tcp_dropped"] or STATS["udp_dropped"]:
        print(f"[!] dropped due to errors: tcp={STATS['tcp_dropped']} udp={STATS['udp_dropped']} "
              f"fd={STATS['emfile']} (results may be incomplete)")

def export(net, hosts, args, disc_time, scanned_ports):
    live = [h for h in hosts.values() if h.alive]
    if args.json:
        meta = {
            "target": str(net), "mode": args.mode, "timeout": args.timeout,
            "udp_timeout": args.udp_timeout, "arp_wait": args.arp_wait,
            "concurrency": args.concurrency, "discovery_seconds": round(disc_time, 3),
            "live_hosts": len(live), "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "stats": STATS, "scanned_ports": len(scanned_ports),
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
    if args.xml:
        root = ET.Element("nmaprun", scanner="netscan")
        for h in live:
            host = ET.SubElement(root, "host")
            ET.SubElement(host, "address", addr=h.ip, addrtype="ipv4")
            if h.mac:
                ET.SubElement(host, "address", addr=h.mac, addrtype="mac")
            ports = ET.SubElement(host, "ports")
            open_map = {p.port: p for p in h.ports}
            for pnum in scanned_ports:
                pe = ET.SubElement(ports, "port", protocol="tcp", portid=str(pnum))
                if pnum in open_map:
                    p = open_map[pnum]
                    ET.SubElement(pe, "state", state="open")
                    ET.SubElement(pe, "service", name=p.service, version=p.version)
                else:
                    ET.SubElement(pe, "state", state="closed")
        ET.ElementTree(root).write(args.xml, encoding="utf-8", xml_declaration=True)
        print(f"XML saved to {args.xml}")
    if args.md:
        with open(args.md, "w") as f:
            f.write(f"# netscan report\n\n**Target:** `{net}`  \n**Mode:** `{args.mode}`  \n"
                    f"**Live hosts:** {len(live)}  \n**Discovery time:** {disc_time:.2f}s\n\n")
            for h in live:
                f.write(f"## {h.ip}" + (f" ({h.hostname})" if h.hostname else "") + "\n\n")
                f.write(f"- found via: {', '.join(h.via)}\n")
                if h.mac: f.write(f"- MAC: `{h.mac}`\n")
                if h.ttl: f.write(f"- OS: {h.os_guess}\n")
                if h.ports:
                    f.write("\n| Port | Service | Version |\n|---|---|---|\n")
                    for p in h.ports:
                        f.write(f"| {p.port} | {p.service} | {p.version} |\n")
                f.write("\n")
        print(f"Markdown saved to {args.md}")

def main():
    ap = argparse.ArgumentParser(description="Hybrid network block scanner (v3.1)")
    ap.add_argument("target", help="network block in CIDR form, e.g. 192.168.1.0/24")
    ap.add_argument("-m", "--mode", choices=MODES, default="hybrid")
    ap.add_argument("-p", "--ports", default="top")
    ap.add_argument("--discovery-ports", metavar="SPEC",
                    help="override TCP discovery ports (default: built-in 25-port set)")
    ap.add_argument("-t", "--timeout", type=float, default=1.0)
    ap.add_argument("--udp-timeout", type=float, default=1.5)
    ap.add_argument("--arp-wait", type=float, default=2.0)
    ap.add_argument("-c", "--concurrency", type=int, default=500)
    ap.add_argument("--rate-limit", type=int, default=200)
    ap.add_argument("--retries", type=int, default=1)
    ap.add_argument("--discovery-only", action="store_true")
    ap.add_argument("--nmap", action="store_true")
    ap.add_argument("--syn", action="store_true")
    ap.add_argument("--no-ping", action="store_true")
    ap.add_argument("--no-flush", action="store_true")
    ap.add_argument("--tcp-arp", action="store_true")
    ap.add_argument("--show-down", action="store_true")
    ap.add_argument("--json", metavar="FILE")
    ap.add_argument("--csv", metavar="FILE")
    ap.add_argument("--xml", metavar="FILE")
    ap.add_argument("--md", metavar="FILE")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    if args.no_ping and args.mode == "icmp":
        ap.error("--no-ping cannot be combined with --mode icmp")
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        sys.exit("\nInterrupted.")
    except ValueError as e:
        sys.exit(f"Error: {e}")
    finally:
        global _ICMP, _SYN
        if _ICMP:
            _ICMP.close(); _ICMP = None
        if _SYN:
            _SYN.close(); _SYN = None

if __name__ == "__main__":
    main()