# sniffer

A simple packet sniffer (Python 3.10+) that decodes Ethernet, IPv4/IPv6, TCP, UDP and ICMP/ICMPv6 headers by hand with `struct`.

- **Raw socket backend (default, stdlib only):**
  - Windows: `AF_INET` raw socket + `SIO_RCVALL`. IPv4 only, no Ethernet header. Needs an **Administrator** terminal.
  - Linux: `AF_PACKET` socket, full Ethernet frames including VLAN tags. Needs **root** or `CAP_NET_RAW`.
- **Scapy backend (`-b scapy`):** works on any OS Scapy supports and accepts BPF filters. Scapy only captures the packets; the decoding is still done by this script. On Windows it also needs [Npcap](https://npcap.com).
- **Decodes:** TCP flags/seq/ack/window, UDP lengths, ICMP echo id/seq, unreachable reasons, and the original packet quoted inside ICMP errors (e.g. traceroute replies). IPv6 extension headers are skipped and fragments are flagged.
- **pcap in/out:** `-r` reads a classic `.pcap` file, so you can test without capture privileges. `-w` saves the packets shown, which you can open in Wireshark.

> Only sniff networks you own or have permission to monitor.

## Usage

```bash
python sniffer.py
```

```bash
python sniffer.py -p tcp --port 443 -c 20
```

```bash
python sniffer.py -p icmp -v -x
```

```bash
python sniffer.py -b scapy -i eth0 -f "udp port 53" -x
```

```bash
python sniffer.py -r capture.pcap --host 10.0.0.5
```

Sample output:

```
07:00:00.000  TCP    192.168.1.10:51544 > 93.184.216.34:443  [S] seq=1000 ack=0 win=65535 len=0
07:00:00.200  UDP    192.168.1.10:5353 > 93.184.216.34:53  len=7
07:00:00.400  ICMP   192.168.1.10 > 93.184.216.34  time-exceeded [orig 192.168.1.10:40000 > 93.184.216.34:33434 UDP]
```

| Flag | Description |
|---|---|
| `-b, --backend` | `raw` (default) or `scapy` |
| `-i, --iface` | Interface (Linux raw backend, Scapy backend) |
| `--bind` | Local IPv4 to capture on (Windows raw backend; defaults to the default-route interface) |
| `-f, --bpf` | BPF capture filter (Scapy only) |
| `-r, --read` | Decode a `.pcap` file instead of capturing (pcapng isn't supported; convert with `editcap -F pcap`) |
| `-p, --proto` | Show only `tcp`, `udp` and/or `icmp` |
| `--host` / `--port` | Show only packets to or from this IP or port |
| `-c, --count` | Stop after N shown packets |
| `-v, --verbose` | Print every decoded header field |
| `-x, --hex` | Hex dump payloads (`--max-bytes`, default 256) |
| `-w, --write` | Save shown IP packets to a pcap (raw-IP link type) |

Press Ctrl+C to stop. Packets go to stdout and the summary line goes to stderr.

## Tests

The tests build packets byte by byte, so they need no privileges and no Scapy:

```bash
python -m unittest discover -s tests -v
```

## Windows raw-socket caveats

`SIO_RCVALL` sees the IPv4 traffic of the one interface it is bound to. Depending on the NIC driver and firewall it may miss some outbound packets. For full Ethernet-level capture on Windows, use `-b scapy` with Npcap.
