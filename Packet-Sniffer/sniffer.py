#!/usr/bin/env python3
"""Simple packet sniffer: raw sockets (stdlib) or Scapy, decoding TCP/UDP/ICMP.

Capture backends:
  raw    stdlib only. Windows: AF_INET raw socket + SIO_RCVALL (IPv4, needs Administrator).
         Linux: AF_PACKET (full Ethernet frames, needs root / CAP_NET_RAW).
  scapy  any OS Scapy supports (Windows needs Npcap). Supports BPF filters.

Either way, Scapy is only used to capture: all header decoding is done here with struct.
"""

import argparse
import ipaddress
import queue
import socket
import struct
import sys
import time
from collections import Counter
from dataclasses import dataclass

LINK_ETHERNET = "ethernet"
LINK_IP = "ip"

ETH_P_ALL = 0x0003
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
VLAN_ETHERTYPES = (0x8100, 0x88A8)
ETHERTYPES = {0x0806: "ARP", 0x8035: "RARP", 0x888E: "EAPOL", 0x88CC: "LLDP", 0x8899: "RRCP"}

PROTO_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6", 89: "OSPF", 132: "SCTP"}
IPV6_EXT_HEADERS = (0, 43, 60)  # hop-by-hop, routing, destination options
IPV6_FRAGMENT = 44

ICMP_TYPES = {
    0: "echo-reply", 3: "dest-unreachable", 4: "source-quench", 5: "redirect", 8: "echo-request",
    9: "router-advert", 10: "router-solicit", 11: "time-exceeded", 12: "param-problem",
    13: "timestamp", 14: "timestamp-reply",
}
ICMP_UNREACH_CODES = {
    0: "net", 1: "host", 2: "protocol", 3: "port", 4: "frag-needed", 5: "source-route-failed",
    9: "net-prohibited", 10: "host-prohibited", 13: "admin-prohibited",
}
ICMP6_TYPES = {
    1: "dest-unreachable", 2: "packet-too-big", 3: "time-exceeded", 4: "param-problem",
    128: "echo-request", 129: "echo-reply", 133: "router-solicit", 134: "router-advert",
    135: "neighbor-solicit", 136: "neighbor-advert",
}
ICMP_ECHO = {0, 8}
ICMP6_ECHO = {128, 129}
ICMP_ERRORS = {3, 4, 5, 11, 12}
ICMP6_ERRORS = {1, 2, 3, 4}

# (bit, letter) in tcpdump-ish display order
TCP_FLAGS = ((0x02, "S"), (0x10, "A"), (0x01, "F"), (0x04, "R"), (0x08, "P"), (0x20, "U"), (0x40, "E"), (0x80, "C"))

PCAP_MAGIC = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
PCAP_LINKTYPES = {1: LINK_ETHERNET, 101: LINK_IP, 228: LINK_IP, 229: LINK_IP}


class Truncated(ValueError):
    pass


@dataclass
class Packet:
    ts: float
    length: int
    eth: dict | None = None
    ip_version: int = 0
    ip: dict | None = None
    proto: str = ""
    l4: dict | None = None
    payload: bytes = b""
    ip_bytes: bytes = b""
    note: str = ""


# --------------------------------------------------------------------------- decoding

def _unpack(fmt, data, offset=0):
    size = struct.calcsize(fmt)
    if len(data) < offset + size:
        raise Truncated(f"need {offset + size} bytes, have {len(data)}")
    return struct.unpack_from(fmt, data, offset)


def _addr(raw):
    return str(ipaddress.ip_address(raw))


def _mac(raw):
    return ":".join(f"{b:02x}" for b in raw)


def decode_ethernet(frame):
    """Return (header dict, ethertype, payload). Skips 802.1Q / 802.1ad VLAN tags."""
    dst, src, ethertype = _unpack("!6s6sH", frame)
    offset = 14
    vlans = []
    while ethertype in VLAN_ETHERTYPES:
        tci, ethertype = _unpack("!HH", frame, offset)
        vlans.append(tci & 0x0FFF)
        offset += 4
    hdr = {"src": _mac(src), "dst": _mac(dst), "type": f"0x{ethertype:04x}"}
    if vlans:
        hdr["vlan"] = ",".join(map(str, vlans))
    return hdr, ethertype, frame[offset:]


def decode_ipv4(data):
    """Return (header dict, protocol number, L4 bytes, whole IP packet bytes)."""
    vihl, tos, total_len, ident, flags_frag, ttl, proto, _csum, src, dst = _unpack("!BBHHHBBH4s4s", data)
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        raise Truncated(f"bad IPv4 header length {ihl}")
    # total_len is 0 for TSO-offloaded outbound packets; fall back to what we got
    end = min(total_len, len(data)) if total_len >= ihl else len(data)
    flags = flags_frag >> 13
    hdr = {
        "src": _addr(src), "dst": _addr(dst), "ttl": ttl, "id": ident, "tos": tos, "len": total_len,
        "flags": "+".join(n for bit, n in ((0x2, "DF"), (0x1, "MF")) if flags & bit) or "none",
        "frag": (flags_frag & 0x1FFF) * 8,
    }
    return hdr, proto, data[ihl:end], data[:end]


def decode_ipv6(data):
    """Return (header dict, next header after extension headers, L4 bytes, whole IP packet bytes)."""
    vtcfl, plen, nxt, hlim, src, dst = _unpack("!IHBB16s16s", data)
    end = min(40 + plen, len(data)) if plen else len(data)
    hdr = {"src": _addr(src), "dst": _addr(dst), "hlim": hlim, "flow": vtcfl & 0xFFFFF, "plen": plen, "frag": 0}
    offset = 40
    while nxt in IPV6_EXT_HEADERS or nxt == IPV6_FRAGMENT:
        h_nxt, h_len = _unpack("!BB", data, offset)
        if nxt == IPV6_FRAGMENT:
            (frag_field,) = _unpack("!H", data, offset + 2)
            hdr["frag"] = (frag_field >> 3) * 8
            offset += 8
        else:
            offset += (h_len + 1) * 8
        nxt = h_nxt
    return hdr, nxt, data[offset:end], data[:end]


def decode_tcp(data):
    sport, dport, seq, ack, off_flags, win, _csum, urg = _unpack("!HHIIHHHH", data)
    hlen = (off_flags >> 12) * 4
    if hlen < 20:
        raise Truncated(f"bad TCP header length {hlen}")
    flags = off_flags & 0xFF
    hdr = {
        "sport": sport, "dport": dport, "seq": seq, "ack": ack,
        "flags": "".join(letter for bit, letter in TCP_FLAGS if flags & bit) or ".",
        "win": win,
    }
    if flags & 0x20:
        hdr["urg"] = urg
    return hdr, data[hlen:]


def decode_udp(data):
    sport, dport, length, _csum = _unpack("!HHHH", data)
    payload = data[8:length] if length >= 8 else data[8:]
    return {"sport": sport, "dport": dport, "len": length}, payload


def _describe_inner(data, v6):
    """Summarise the original packet quoted inside an ICMP error message."""
    try:
        hdr, proto, l4, _ = decode_ipv6(data) if v6 else decode_ipv4(data)
    except Truncated:
        return None
    name = PROTO_NAMES.get(proto, str(proto))
    if proto in (6, 17) and len(l4) >= 4:
        sport, dport = struct.unpack_from("!HH", l4)
        return f"{_hostport(hdr['src'], sport)} > {_hostport(hdr['dst'], dport)} {name}"
    return f"{hdr['src']} > {hdr['dst']} {name}"


def decode_icmp(data, v6=False):
    icmp_type, code, _csum = _unpack("!BBH", data)
    names = ICMP6_TYPES if v6 else ICMP_TYPES
    hdr = {"type": icmp_type, "code": code, "name": names.get(icmp_type, "unknown")}
    if icmp_type in (ICMP6_ECHO if v6 else ICMP_ECHO):
        hdr["id"], hdr["seq"] = _unpack("!HH", data, 4)
    if not v6 and icmp_type == 3:
        hdr["reason"] = ICMP_UNREACH_CODES.get(code, str(code))
    if not v6 and icmp_type == 5:
        hdr["gateway"] = _addr(_unpack("!4s", data, 4)[0])
    if icmp_type in (ICMP6_ERRORS if v6 else ICMP_ERRORS):
        inner = _describe_inner(data[8:], v6)
        if inner:
            hdr["orig"] = inner
    return hdr, data[8:]


def decode(raw, link, ts=None):
    """Decode one captured frame/packet into a Packet. Never raises on malformed input."""
    pkt = Packet(ts if ts is not None else time.time(), len(raw))
    try:
        data = raw
        if link == LINK_ETHERNET:
            pkt.eth, ethertype, data = decode_ethernet(raw)
            if ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
                pkt.note = ETHERTYPES.get(ethertype, f"ethertype 0x{ethertype:04x}")
                return pkt
        if not data:
            raise Truncated("empty packet")
        pkt.ip_version = data[0] >> 4
        if pkt.ip_version == 4:
            pkt.ip, proto, l4, pkt.ip_bytes = decode_ipv4(data)
        elif pkt.ip_version == 6:
            pkt.ip, proto, l4, pkt.ip_bytes = decode_ipv6(data)
        else:
            pkt.note = f"not IP (version {pkt.ip_version})"
            pkt.ip_version = 0
            return pkt

        pkt.proto = PROTO_NAMES.get(proto, f"proto-{proto}")
        if pkt.ip["frag"]:
            pkt.note = f"fragment offset={pkt.ip['frag']}"
            pkt.payload = l4
            return pkt
        if proto == 6:
            pkt.l4, pkt.payload = decode_tcp(l4)
        elif proto == 17:
            pkt.l4, pkt.payload = decode_udp(l4)
        elif proto == 1 and pkt.ip_version == 4:
            pkt.l4, pkt.payload = decode_icmp(l4)
        elif proto == 58 and pkt.ip_version == 6:
            pkt.l4, pkt.payload = decode_icmp(l4, v6=True)
        else:
            pkt.payload = l4
    except Truncated as exc:
        pkt.note = f"truncated: {exc}"
    return pkt


# --------------------------------------------------------------------------- output

def _hostport(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _timestamp(ts):
    sec, ms = divmod(round(ts * 1000), 1000)
    return time.strftime("%H:%M:%S", time.localtime(sec)) + f".{ms:03d}"


def summary(pkt):
    t = _timestamp(pkt.ts)
    if not pkt.ip:
        return f"{t}  {pkt.note or 'unknown':<8} len={pkt.length}"
    src, dst = pkt.ip["src"], pkt.ip["dst"]
    l4 = pkt.l4
    if l4 is None:
        detail = pkt.note or f"len={len(pkt.payload)}"
    elif pkt.proto == "TCP":
        src, dst = _hostport(src, l4["sport"]), _hostport(dst, l4["dport"])
        detail = f"[{l4['flags']}] seq={l4['seq']} ack={l4['ack']} win={l4['win']} len={len(pkt.payload)}"
    elif pkt.proto == "UDP":
        src, dst = _hostport(src, l4["sport"]), _hostport(dst, l4["dport"])
        detail = f"len={len(pkt.payload)}"
    else:  # ICMP / ICMPv6
        detail = l4["name"]
        if "reason" in l4:
            detail += f" ({l4['reason']})"
        elif l4["code"]:
            detail += f" code={l4['code']}"
        if "seq" in l4:
            detail += f" id={l4['id']} seq={l4['seq']}"
        if "orig" in l4:
            detail += f" [orig {l4['orig']}]"
    return f"{t}  {pkt.proto:<6} {src} > {dst}  {detail}"


def details(pkt):
    lines = []
    ip_name = f"ipv{pkt.ip_version}" if pkt.ip_version else "ip"
    for name, layer in (("eth", pkt.eth), (ip_name, pkt.ip), (pkt.proto.lower(), pkt.l4)):
        if layer:
            lines.append(f"    {name:<7}" + " ".join(f"{k}={v}" for k, v in layer.items()))
    return "\n".join(lines)


def hexdump(data, limit=256, indent="    "):
    lines = []
    shown = data[:limit]
    for off in range(0, len(shown), 16):
        chunk = shown[off:off + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}{off:04x}  {hex_part:<47}  {text}")
    if len(data) > limit:
        lines.append(f"{indent}... {len(data) - limit} more bytes")
    return "\n".join(lines)


def matches(pkt, args):
    if args.proto and pkt.proto.lower().removesuffix("v6") not in args.proto:
        return False
    if args.host and (not pkt.ip or args.host not in (pkt.ip["src"], pkt.ip["dst"])):
        return False
    if args.port is not None:
        if not pkt.l4 or args.port not in (pkt.l4.get("sport"), pkt.l4.get("dport")):
            return False
    return True


# --------------------------------------------------------------------------- pcap

class PcapWriter:
    """Writes IP-layer packets (LINKTYPE_RAW) so files from every backend look the same."""

    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, 101))

    def write(self, ts, data):
        sec = int(ts)
        self.f.write(struct.pack("<IIII", sec, int((ts - sec) * 1_000_000), len(data), len(data)) + data)

    def close(self):
        self.f.close()


def read_pcap(path):
    """Yield (raw, link, ts) from a classic libpcap file (not pcapng)."""
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            raise ValueError("file too short to be a pcap")
        for endian in ("<", ">"):
            (magic,) = struct.unpack(endian + "I", header[:4])
            if magic in (PCAP_MAGIC, PCAP_MAGIC_NS):
                break
        else:
            raise ValueError("not a libpcap file (pcapng is not supported; convert with editcap -F pcap)")
        divisor = 1e9 if magic == PCAP_MAGIC_NS else 1e6
        linktype = struct.unpack(endian + "I", header[20:24])[0] & 0x0FFFFFFF
        link = PCAP_LINKTYPES.get(linktype)
        if link is None:
            raise ValueError(f"unsupported pcap link type {linktype}")
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl_len, _orig_len = struct.unpack(endian + "IIII", rec)
            yield f.read(incl_len), link, sec + frac / divisor


# --------------------------------------------------------------------------- capture backends

def default_ipv4():
    """IPv4 address of the interface holding the default route (no packets are sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1; connect() on UDP just picks a route
        return s.getsockname()[0]


def capture_raw(args):
    windows = sys.platform == "win32"
    if windows:
        host = args.bind or default_ipv4()
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((host, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        print(f"[*] raw socket on {host} (Windows SIO_RCVALL: IPv4 only, no Ethernet header)", file=sys.stderr)
    elif hasattr(socket, "AF_PACKET"):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        if args.iface:
            s.bind((args.iface, 0))
        print(f"[*] AF_PACKET socket on {args.iface or 'all interfaces'}", file=sys.stderr)
    else:
        sys.exit("error: the raw backend needs Windows or Linux; use --backend scapy on this OS")

    s.settimeout(1.0)  # so Ctrl+C is noticed even when the network is quiet
    try:
        while True:
            try:
                raw, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            if windows:
                link = LINK_IP
            else:
                # addr = (ifname, proto, pkttype, hatype, hwaddr); ARPHRD_NONE (tun etc.) has no L2 header
                link = LINK_IP if addr[3] in (0xFFFE, 0xFFFF) else LINK_ETHERNET
            yield raw, link, time.time()
    finally:
        if windows:
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
        s.close()


def capture_scapy(args):
    try:
        from scapy.all import IP, AsyncSniffer, Ether, IPv6
    except ImportError:
        sys.exit("error: Scapy is not installed (pip install scapy; on Windows also install Npcap)")

    q = queue.Queue()
    sniffer = AsyncSniffer(iface=args.iface, filter=args.bpf, prn=q.put, store=False)
    sniffer.start()
    print(f"[*] scapy sniffing on {args.iface or 'default interface'}"
          + (f" with BPF '{args.bpf}'" if args.bpf else ""), file=sys.stderr)
    try:
        while True:
            try:
                p = q.get(timeout=0.5)
            except queue.Empty:
                if not sniffer.running:
                    err = getattr(sniffer, "exception", None)
                    if err:
                        raise err
                    return
                continue
            if Ether in p:
                yield bytes(p[Ether]), LINK_ETHERNET, float(p.time)
            elif IP in p:
                yield bytes(p[IP]), LINK_IP, float(p.time)
            elif IPv6 in p:
                yield bytes(p[IPv6]), LINK_IP, float(p.time)
    finally:
        if sniffer.running:
            sniffer.stop()


# --------------------------------------------------------------------------- main

def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="Simple packet sniffer decoding TCP/UDP/ICMP.")
    src = ap.add_argument_group("source")
    src.add_argument("-b", "--backend", choices=("raw", "scapy"), default="raw",
                     help="capture with stdlib raw sockets (default) or Scapy")
    src.add_argument("-i", "--iface", help="interface name (Linux raw backend, scapy backend)")
    src.add_argument("--bind", metavar="IP", help="local IPv4 to capture on (Windows raw backend)")
    src.add_argument("-f", "--bpf", metavar="FILTER", help="BPF capture filter, e.g. 'tcp port 443' (scapy only)")
    src.add_argument("-r", "--read", metavar="PCAP", help="decode a .pcap file instead of capturing live")

    flt = ap.add_argument_group("display filters")
    flt.add_argument("-p", "--proto", nargs="+", choices=("tcp", "udp", "icmp"),
                     help="only show these protocols (icmp includes ICMPv6)")
    flt.add_argument("--host", help="only packets to/from this IP")
    flt.add_argument("--port", type=int, help="only TCP/UDP packets to/from this port")
    flt.add_argument("-c", "--count", type=int, default=0, help="stop after N shown packets")

    out = ap.add_argument_group("output")
    out.add_argument("-v", "--verbose", action="store_true", help="print every header field")
    out.add_argument("-x", "--hex", action="store_true", help="hex dump payloads")
    out.add_argument("--max-bytes", type=int, default=256, help="hex dump limit per packet (default 256)")
    out.add_argument("-w", "--write", metavar="PCAP", help="save shown IP packets to a pcap file")
    args = ap.parse_args(argv)
    if args.bpf and args.backend != "scapy" and not args.read:
        ap.error("--bpf needs --backend scapy (use -p/--host/--port with the raw backend)")
    return args


def main(argv=None):
    args = parse_args(argv)
    sys.stdout.reconfigure(line_buffering=True)  # show packets live even when piped
    if args.read:
        source = read_pcap(args.read)
    elif args.backend == "scapy":
        source = capture_scapy(args)
    else:
        source = capture_raw(args)

    writer = PcapWriter(args.write) if args.write else None
    stats = Counter()
    seen = 0
    started = time.time()
    try:
        for raw, link, ts in source:
            pkt = decode(raw, link, ts)
            stats[pkt.proto or pkt.note.split(":")[0] or "other"] += 1
            if not matches(pkt, args):
                continue
            seen += 1
            print(summary(pkt))
            if args.verbose:
                print(details(pkt))
            if args.hex and pkt.payload:
                print(hexdump(pkt.payload, args.max_bytes))
            if writer and pkt.ip_bytes:
                writer.write(pkt.ts, pkt.ip_bytes)
            if args.count and seen >= args.count:
                break
    except KeyboardInterrupt:
        pass
    except PermissionError:
        need = "an Administrator terminal" if sys.platform == "win32" else "root (or CAP_NET_RAW)"
        sys.exit(f"error: raw capture needs {need}")
    except (OSError, ValueError) as exc:
        sys.exit(f"error: {exc}")
    finally:
        source.close()
        if writer:
            writer.close()

    total = sum(stats.values())
    breakdown = ", ".join(f"{k} {v}" for k, v in stats.most_common())
    print(f"\n[*] {total} packets captured, {seen} shown in {time.time() - started:.1f}s"
          + (f"  ({breakdown})" if breakdown else ""), file=sys.stderr)


if __name__ == "__main__":
    main()
