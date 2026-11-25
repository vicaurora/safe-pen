"""Shared helpers for the lab services: configuration, JSONL event logging, dual-stack servers."""

import json
import os
import socket
import struct
import threading
import time
from http.server import ThreadingHTTPServer

CONFIG_PATH = os.environ.get("GT_CONFIG", "/gt/config.json")
LOG_DIR = os.environ.get("GT_LOG_DIR", "/gt/logs")


def load_config():
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return json.load(f)


class Logger:
    """Append-only JSONL logger, one file per service."""

    def __init__(self, svc):
        self.svc = svc
        self.path = os.path.join(LOG_DIR, f"{svc}.jsonl")
        self.lock = threading.Lock()
        os.makedirs(LOG_DIR, exist_ok=True)
        new = not os.path.exists(self.path)
        self.fh = open(self.path, "a", encoding="utf-8")
        if new:
            self._chown()

    def _chown(self):
        # Services run as root in their container; give the files back to the host user.
        uid, gid = os.environ.get("GT_UID"), os.environ.get("GT_GID")
        os.chmod(self.path, 0o600)  # not readable by a shell obtained on the target
        if uid and gid:
            try:
                os.chown(self.path, int(uid), int(gid))
            except OSError:
                pass

    def log(self, kind, **fields):
        rec = {"ts": round(time.time(), 4), "svc": self.svc, "kind": kind}
        rec.update(fields)
        line = json.dumps(rec, ensure_ascii=False)
        with self.lock:
            self.fh.write(line + "\n")
            self.fh.flush()


def norm_ip(addr):
    """'::ffff:10.0.0.1' -> '10.0.0.1' for IPv4 clients of a dual-stack socket."""
    return addr[7:] if addr.startswith("::ffff:") else addr


def listen_socket(port, backlog=64):
    """TCP socket listening on IPv6 and IPv4 when possible, IPv4 only otherwise."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("::", port))
    except OSError:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
    s.listen(backlog)
    return s


class DualStackHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port, handler):
        super().__init__(("0.0.0.0", port), handler, bind_and_activate=False)
        self.socket.close()
        self.socket = listen_socket(port, self.request_queue_size)
        self.address_family = self.socket.family
        self.server_address = self.socket.getsockname()[:2]
        self.server_port = port
        self.server_name = "localhost"


def sniff(my_ips, callback):
    """Call callback(proto, src, dport, family) for each packet addressed to one of my_ips.

    TCP: SYN without ACK only. UDP: every datagram. ICMP / ICMPv6: echo requests.
    Needs CAP_NET_RAW.
    """
    targets4 = {socket.inet_pton(socket.AF_INET, ip) for ip in my_ips if ":" not in ip}
    targets6 = {socket.inet_pton(socket.AF_INET6, ip) for ip in my_ips if ":" in ip}
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    while True:
        frame, meta = s.recvfrom(65535)
        if meta[2] == socket.PACKET_OUTGOING:
            continue
        ethertype = struct.unpack("!H", frame[12:14])[0]
        pkt = frame[14:]
        if ethertype == 0x0800 and len(pkt) >= 20:
            if pkt[16:20] not in targets4:
                continue
            ihl = (pkt[0] & 0x0F) * 4
            proto, src, seg = pkt[9], socket.inet_ntop(socket.AF_INET, pkt[12:16]), pkt[ihl:]
            fam, icmp_proto, echo = 4, 1, 8
        elif ethertype == 0x86DD and len(pkt) >= 40:
            if pkt[24:40] not in targets6:
                continue
            proto, src, seg = pkt[6], socket.inet_ntop(socket.AF_INET6, pkt[8:24]), pkt[40:]
            fam, icmp_proto, echo = 6, 58, 128
        else:
            continue
        if proto == 6 and len(seg) >= 14:
            flags = seg[13]
            if flags & 0x02 and not flags & 0x10:
                callback("tcp", src, struct.unpack("!H", seg[2:4])[0], fam)
        elif proto == 17 and len(seg) >= 8:
            callback("udp", src, struct.unpack("!H", seg[2:4])[0], fam)
        elif proto == icmp_proto and seg and seg[0] == echo:
            callback("icmp", src, None, fam)
