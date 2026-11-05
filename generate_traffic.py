#!/usr/bin/env python3
"""
Harmless traffic generator used to produce demo output for packet_sniffer.py.
Sends a few HTTP (TCP), DNS (UDP) and UDP packets so the sniffer has
something to capture. Run it in a SECOND terminal while the sniffer runs.

    python generate_traffic.py
"""
import socket
import time
import urllib.request


def http_request():
    print("[traffic] HTTP GET http://example.com  (TCP/80)")
    try:
        urllib.request.urlopen("http://example.com", timeout=5).read(200)
    except Exception as exc:
        print(f"[traffic] HTTP request failed: {exc}")


def dns_query(name="example.com"):
    """Hand-built DNS A-record query sent over UDP/53 to Google DNS."""
    print(f"[traffic] DNS query for {name}  (UDP/53)")
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    packet = header + qname + b"\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(packet, ("8.8.8.8", 53))
        s.recvfrom(512)
    except OSError as exc:
        print(f"[traffic] DNS query failed: {exc}")
    finally:
        s.close()


def udp_message():
    print("[traffic] UDP datagram to 8.8.8.8:9999")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"hello from generate_traffic.py", ("8.8.8.8", 9999))
    s.close()


if __name__ == "__main__":
    for _ in range(2):
        http_request()
        dns_query()
        udp_message()
        time.sleep(1)
    print("[traffic] done.")
