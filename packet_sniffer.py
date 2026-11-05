#!/usr/bin/env python3
"""
Network Packet Sniffer
======================
Command-line packet sniffer that reads raw network socket buffers, parses
IPv4 / TCP / UDP / ICMP headers, shows payload bytes, and logs traffic
summary statistics to a file.

Works on:
  * Linux   (AF_PACKET raw socket, needs root)        -> sudo python3 packet_sniffer.py
  * Windows (AF_INET raw socket + SIO_RCVALL, needs
             an Administrator terminal)               -> python packet_sniffer.py --bind-ip <your-LAN-IP>

Only use on networks / machines you own or are authorised to monitor.
"""

import argparse
import ctypes
import os
import socket
import struct
import sys
import time
from collections import Counter
from datetime import datetime

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
IS_WINDOWS = os.name == "nt"
ETH_HEADER_LEN = 14
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
PACKET_OUTGOING = 4  # Linux sockaddr_ll pkttype

PROTOCOLS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP"}

TCP_FLAGS = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
]

WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    1900: "SSDP", 3306: "MySQL", 3389: "RDP", 5353: "mDNS", 8080: "HTTP-alt",
}


# --------------------------------------------------------------------------
# Privilege check + socket creation
# --------------------------------------------------------------------------
def is_admin() -> bool:
    """True if the process has root (Linux) / Administrator (Windows) rights."""
    try:
        if IS_WINDOWS:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def get_local_ip() -> str:
    """Best-effort guess of the primary LAN IP (used on Windows)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no packet is actually sent for UDP connect
        return s.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())
    finally:
        s.close()


def create_raw_socket(bind_ip=None, interface=None):
    """Create and return the raw socket listener."""
    if IS_WINDOWS:
        ip = bind_ip or get_local_ip()
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # promiscuous-style capture
        return sock, ip

    # Linux: AF_PACKET gives us whole Ethernet frames for every protocol.
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    if interface:
        sock.bind((interface, 0))
    return sock, interface or "all interfaces"


def close_raw_socket(sock):
    if IS_WINDOWS:
        try:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except OSError:
            pass
    sock.close()


# --------------------------------------------------------------------------
# Header parsers
# --------------------------------------------------------------------------
def parse_ipv4(data: bytes):
    """Parse an IPv4 header. Returns dict or None if not valid IPv4."""
    if len(data) < 20:
        return None
    (ver_ihl, tos, total_len, ident, flags_frag,
     ttl, proto, checksum, src, dst) = struct.unpack("!BBHHHBBH4s4s", data[:20])
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(data) < ihl:
        return None
    return {
        "version": version,
        "header_len": ihl,
        "tos": tos,
        "total_len": total_len,
        "id": ident,
        "flags": flags_frag >> 13,
        "frag_offset": flags_frag & 0x1FFF,
        "ttl": ttl,
        "proto": proto,
        "proto_name": PROTOCOLS.get(proto, f"OTHER({proto})"),
        "checksum": checksum,
        "src": socket.inet_ntoa(src),
        "dst": socket.inet_ntoa(dst),
        "payload": data[ihl:total_len] if total_len >= ihl else data[ihl:],
    }


def parse_tcp(data: bytes):
    if len(data) < 20:
        return None
    (sport, dport, seq, ack, off_res, flags,
     window, checksum, urg) = struct.unpack("!HHLLBBHHH", data[:20])
    offset = (off_res >> 4) * 4
    if offset < 20:
        return None
    flag_names = [name for bit, name in TCP_FLAGS if flags & bit]
    return {
        "sport": sport,
        "dport": dport,
        "seq": seq,
        "ack": ack,
        "flags": ",".join(flag_names) or "NONE",
        "window": window,
        "payload": data[offset:],
    }


def parse_udp(data: bytes):
    if len(data) < 8:
        return None
    sport, dport, length, checksum = struct.unpack("!HHHH", data[:8])
    return {"sport": sport, "dport": dport, "length": length, "payload": data[8:]}


def parse_icmp(data: bytes):
    if len(data) < 4:
        return None
    icmp_type, code, checksum = struct.unpack("!BBH", data[:4])
    return {"type": icmp_type, "code": code, "payload": data[4:]}


def parse_packet(raw: bytes):
    """
    Parse a raw buffer into a dict of decoded fields.
    On Linux the buffer starts with a 14-byte Ethernet header; on Windows it
    starts directly at the IP header.
    """
    if not IS_WINDOWS:
        if len(raw) < ETH_HEADER_LEN:
            return None
        eth_type = struct.unpack("!H", raw[12:14])[0]
        if eth_type != ETH_P_IP:  # ignore ARP / IPv6 / etc. in this exercise
            return None
        raw = raw[ETH_HEADER_LEN:]

    ip = parse_ipv4(raw)
    if ip is None:
        return None

    pkt = {"ip": ip, "transport": None, "sport": None, "dport": None, "payload": b""}

    # Non-first fragments carry no transport header.
    if ip["frag_offset"] != 0:
        pkt["payload"] = ip["payload"]
        return pkt

    if ip["proto"] == 6:
        tcp = parse_tcp(ip["payload"])
        if tcp:
            pkt.update(transport=tcp, sport=tcp["sport"], dport=tcp["dport"],
                       payload=tcp["payload"])
    elif ip["proto"] == 17:
        udp = parse_udp(ip["payload"])
        if udp:
            pkt.update(transport=udp, sport=udp["sport"], dport=udp["dport"],
                       payload=udp["payload"])
    elif ip["proto"] == 1:
        icmp = parse_icmp(ip["payload"])
        if icmp:
            pkt.update(transport=icmp, payload=icmp["payload"])
    else:
        pkt["payload"] = ip["payload"]
    return pkt


# --------------------------------------------------------------------------
# Formatting helpers
# --------------------------------------------------------------------------
def hex_dump(data: bytes, max_bytes: int = 48) -> str:
    """Return 'hex  |ascii|' preview of the first `max_bytes` payload bytes."""
    chunk = data[:max_bytes]
    hex_part = " ".join(f"{b:02x}" for b in chunk)
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    more = f" ... (+{len(data) - max_bytes} bytes)" if len(data) > max_bytes else ""
    return f"{hex_part}  |{ascii_part}|{more}"


def port_label(port):
    if port is None:
        return "-"
    name = WELL_KNOWN_PORTS.get(port)
    return f"{port}({name})" if name else str(port)


def format_packet(num: int, pkt: dict, show_payload: bool, payload_bytes: int) -> str:
    ip = pkt["ip"]
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] #{num:<5} {ip['proto_name']:<5} "
    if pkt["sport"] is not None:
        line += (f"{ip['src']}:{pkt['sport']} -> {ip['dst']}:{pkt['dport']}")
    else:
        line += f"{ip['src']} -> {ip['dst']}"
    line += f"  len={ip['total_len']} ttl={ip['ttl']}"

    t = pkt["transport"]
    if t:
        if ip["proto"] == 6:
            line += f" flags=[{t['flags']}] seq={t['seq']} ack={t['ack']}"
        elif ip["proto"] == 17:
            line += f" udp_len={t['length']}"
        elif ip["proto"] == 1:
            line += f" icmp_type={t['type']} code={t['code']}"
    line += f" payload={len(pkt['payload'])}B"

    if show_payload and pkt["payload"]:
        line += f"\n           payload: {hex_dump(pkt['payload'], payload_bytes)}"
    return line


# --------------------------------------------------------------------------
# Statistics
# --------------------------------------------------------------------------
class Stats:
    def __init__(self):
        self.start = time.time()
        self.total_packets = 0
        self.total_bytes = 0
        self.proto_packets = Counter()
        self.proto_bytes = Counter()
        self.src_ips = Counter()
        self.dst_ips = Counter()
        self.tcp_ports = Counter()
        self.udp_ports = Counter()
        self.tcp_flags = Counter()

    def update(self, pkt: dict):
        ip = pkt["ip"]
        size = ip["total_len"]
        self.total_packets += 1
        self.total_bytes += size
        self.proto_packets[ip["proto_name"]] += 1
        self.proto_bytes[ip["proto_name"]] += size
        self.src_ips[ip["src"]] += 1
        self.dst_ips[ip["dst"]] += 1
        if ip["proto"] == 6 and pkt["transport"]:
            self.tcp_ports[pkt["dport"]] += 1
            self.tcp_flags[pkt["transport"]["flags"]] += 1
        elif ip["proto"] == 17 and pkt["transport"]:
            self.udp_ports[pkt["dport"]] += 1

    def summary(self, top_n: int = 5) -> str:
        elapsed = max(time.time() - self.start, 0.001)
        out = []
        out.append("=" * 70)
        out.append("TRAFFIC SUMMARY STATISTICS")
        out.append("=" * 70)
        out.append(f"Generated        : {datetime.now():%Y-%m-%d %H:%M:%S}")
        out.append(f"Capture duration : {elapsed:.1f} s")
        out.append(f"Total packets    : {self.total_packets}")
        out.append(f"Total bytes      : {self.total_bytes}")
        out.append(f"Avg rate         : {self.total_packets / elapsed:.1f} pkt/s, "
                   f"{self.total_bytes / elapsed:.1f} B/s")
        out.append("")
        out.append("Protocol distribution:")
        for proto, cnt in self.proto_packets.most_common():
            pct = 100 * cnt / max(self.total_packets, 1)
            out.append(f"  {proto:<10} {cnt:>6} pkts  {self.proto_bytes[proto]:>9} bytes  ({pct:5.1f}%)")
        out.append("")
        out.append(f"Top {top_n} source IPs:")
        for ip, cnt in self.src_ips.most_common(top_n):
            out.append(f"  {ip:<18} {cnt:>6} pkts")
        out.append(f"Top {top_n} destination IPs:")
        for ip, cnt in self.dst_ips.most_common(top_n):
            out.append(f"  {ip:<18} {cnt:>6} pkts")
        out.append(f"Top {top_n} TCP destination ports:")
        for port, cnt in self.tcp_ports.most_common(top_n):
            out.append(f"  {port_label(port):<18} {cnt:>6} pkts")
        out.append(f"Top {top_n} UDP destination ports:")
        for port, cnt in self.udp_ports.most_common(top_n):
            out.append(f"  {port_label(port):<18} {cnt:>6} pkts")
        out.append("TCP flag combinations:")
        for flags, cnt in self.tcp_flags.most_common(top_n):
            out.append(f"  {flags:<18} {cnt:>6} pkts")
        out.append("=" * 70)
        return "\n".join(out)


# --------------------------------------------------------------------------
# CLI + main loop
# --------------------------------------------------------------------------
def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Raw-socket network packet sniffer (IP / TCP / UDP / ICMP) "
                    "with traffic statistics logging.")
    p.add_argument("-i", "--interface", help="Linux: interface to sniff, e.g. eth0, wlan0, lo "
                                             "(default: all)")
    p.add_argument("-b", "--bind-ip", help="Windows: local IP address to bind to "
                                           "(default: auto-detect)")
    p.add_argument("-c", "--count", type=int, default=0,
                   help="Stop after N packets (0 = unlimited, Ctrl+C to stop)")
    p.add_argument("-t", "--timeout", type=int, default=0,
                   help="Stop after N seconds (0 = unlimited)")
    p.add_argument("-p", "--protocol", choices=["tcp", "udp", "icmp"],
                   help="Only capture this protocol")
    p.add_argument("--port", type=int, help="Only capture packets using this TCP/UDP port")
    p.add_argument("-l", "--log", default="network_log.txt",
                   help="Log file path (default: network_log.txt)")
    p.add_argument("--no-payload", action="store_true", help="Hide payload bytes in output")
    p.add_argument("--payload-bytes", type=int, default=48,
                   help="Number of payload bytes to show per packet (default: 48)")
    p.add_argument("--stats-every", type=int, default=0,
                   help="Print running stats every N packets (0 = only at the end)")
    return p


def matches_filter(pkt, args) -> bool:
    if args.protocol:
        wanted = {"tcp": 6, "udp": 17, "icmp": 1}[args.protocol]
        if pkt["ip"]["proto"] != wanted:
            return False
    if args.port is not None and args.port not in (pkt["sport"], pkt["dport"]):
        return False
    return True


def main():
    args = build_arg_parser().parse_args()

    if not is_admin():
        hint = ("Open an *Administrator* Command Prompt / PowerShell."
                if IS_WINDOWS else "Re-run with sudo:  sudo python3 packet_sniffer.py")
        sys.exit(f"[!] Raw sockets need elevated privileges. {hint}")

    try:
        sock, where = create_raw_socket(args.bind_ip, args.interface)
    except (PermissionError, OSError) as exc:
        sys.exit(f"[!] Could not create raw socket: {exc}")

    stats = Stats()
    start_msg = (f"Sniffer started on {where} at {datetime.now():%Y-%m-%d %H:%M:%S} "
                 f"(platform: {'Windows' if IS_WINDOWS else 'Linux'})")
    print(start_msg)
    print("Press Ctrl+C to stop.\n")

    sock.settimeout(1.0)  # lets the loop notice Ctrl+C / --timeout
    deadline = time.time() + args.timeout if args.timeout else None
    shown = 0

    with open(args.log, "w", encoding="utf-8") as log:
        log.write(start_msg + "\n")
        log.write("-" * 70 + "\nPACKET LOG\n" + "-" * 70 + "\n")
        try:
            while True:
                if deadline and time.time() >= deadline:
                    break
                if args.count and shown >= args.count:
                    break
                try:
                    raw, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue

                # On Linux loopback every packet is delivered twice (an
                # "outgoing" and an "incoming" copy). Keep only one.
                if not IS_WINDOWS and addr[0] == "lo" and addr[2] == PACKET_OUTGOING:
                    continue

                pkt = parse_packet(raw)
                if pkt is None or not matches_filter(pkt, args):
                    continue

                shown += 1
                stats.update(pkt)
                line = format_packet(shown, pkt, not args.no_payload, args.payload_bytes)
                print(line)
                log.write(line + "\n")

                if args.stats_every and shown % args.stats_every == 0:
                    print("\n" + stats.summary() + "\n")
        except KeyboardInterrupt:
            print("\n[*] Stopped by user.")
        finally:
            close_raw_socket(sock)
            summary = stats.summary()
            print("\n" + summary)
            log.write("\n" + summary + "\n")
            log.flush()
    print(f"\n[+] Log saved to: {os.path.abspath(args.log)}")


if __name__ == "__main__":
    main()
