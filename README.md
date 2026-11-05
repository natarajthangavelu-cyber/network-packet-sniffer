# Network Packet Sniffer (Python)

A command-line packet sniffer built with Python's standard library only (`socket`, `struct`).
It listens on a **raw socket**, parses **IPv4, TCP, UDP and ICMP** headers, decodes
ports and payload bytes, and writes a packet log plus **traffic summary statistics** to a file.

> ⚠️ For learning only. Run it only on networks/computers you own or are authorised to monitor.

## Features

| Task step | Where it is implemented |
|-----------|-------------------------|
| 1. Raw socket listener (needs root/admin) | `create_raw_socket()`, `is_admin()` |
| 2. Parse IP header (src IP, dst IP, protocol, TTL, length) | `parse_ipv4()` |
| 3. Decode TCP/UDP ports + payload bytes | `parse_tcp()`, `parse_udp()`, `hex_dump()` |
| 4. Log traffic summary statistics to file | `Stats` class → `network_log.txt` |

Extras: ICMP parsing, TCP flag decoding (SYN/ACK/FIN…), filters by protocol/port,
running stats, works on Linux and Windows.

## Requirements

* Python 3.8+ (no pip packages needed)
* Linux/macOS-style root (`sudo`) **or** an Administrator terminal on Windows

## Usage

### Linux
```bash
sudo python3 packet_sniffer.py                 # all interfaces, Ctrl+C to stop
sudo python3 packet_sniffer.py -i wlan0 -c 50  # 50 packets on wlan0
sudo python3 packet_sniffer.py -p tcp --port 80
```

### Windows (run Command Prompt / PowerShell **as Administrator**)
```bat
python packet_sniffer.py
python packet_sniffer.py --bind-ip 192.168.1.10 -c 50
```
Find your IP with `ipconfig` (IPv4 Address of your Wi-Fi/Ethernet adapter).
Windows raw sockets cannot capture loopback (127.0.0.1) traffic, so use your LAN IP.

### Options

| Flag | Meaning |
|------|---------|
| `-i, --interface` | Linux interface (eth0, wlan0, lo …) |
| `-b, --bind-ip` | Windows local IP to bind to |
| `-c, --count N` | Stop after N packets |
| `-t, --timeout N` | Stop after N seconds |
| `-p, --protocol` | `tcp`, `udp` or `icmp` |
| `--port N` | Only packets using port N |
| `-l, --log FILE` | Log file (default `network_log.txt`) |
| `--no-payload` | Hide payload bytes |
| `--payload-bytes N` | Payload bytes to display (default 48) |
| `--stats-every N` | Print running stats every N packets |

## Generate traffic for a demo

Open a **second** terminal and run:
```bash
python3 generate_traffic.py      # (Windows: python generate_traffic.py)
```
It sends a few harmless HTTP, DNS and UDP packets for the sniffer to capture.
Browsing any website or running `ping 8.8.8.8` also works.

## Example output

```
Sniffer started on lo at 2026-11-05 13:10:02 (platform: Linux)
[13:10:03.512] #1     TCP   127.0.0.1:41908 -> 127.0.0.1:8080  len=60 ttl=64 flags=[SYN] seq=... ack=0 payload=0B
[13:10:03.514] #7     TCP   127.0.0.1:41908 -> 127.0.0.1:8080  len=129 ttl=64 flags=[PSH,ACK] ... payload=77B
           payload: 47 45 54 20 2f 20 48 54 54 50 ...  |GET / HTTP/1.1..Host: 127.0.0.1:8080..User-Agent|
```
See `sample_network_log.txt` for a full log including the summary statistics section.

## Files

* `packet_sniffer.py` – the sniffer
* `generate_traffic.py` – optional demo traffic generator
* `sample_network_log.txt` – sample log produced by the sniffer
* `README.md`, `.gitignore`
