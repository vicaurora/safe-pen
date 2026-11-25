"""Small helpers shared by the scripted self-test agents (standard library only)."""

import os
import random
import socket
import struct
import time
import zlib

TYPES = {"A": 1, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}


def dns_query(name, qtype="A", server="10.77.0.53"):
    """Return the answers of one query as a list of (type, value)."""
    qid = random.randint(0, 65535)
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    q += struct.pack("!HH", TYPES[qtype], 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(q, (server, 53))
    data, _ = s.recvfrom(4096)
    s.close()
    an = struct.unpack("!H", data[6:8])[0]
    i = len(q)
    out = []

    def read_name(j):
        labels = []
        while True:
            n = data[j]
            if n & 0xC0:
                ptr = struct.unpack("!H", data[j:j + 2])[0] & 0x3FFF
                labels.append(read_name(ptr)[0])
                return ".".join(labels), j + 2
            if n == 0:
                return ".".join(labels), j + 1
            labels.append(data[j + 1:j + 1 + n].decode())
            j += 1 + n

    for _ in range(an):
        _, i = read_name(i)
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[i:i + 10])
        i += 10
        rd = data[i:i + rdlen]
        if rtype == 1:
            out.append(("A", socket.inet_ntoa(rd)))
        elif rtype == 28:
            out.append(("AAAA", socket.inet_ntop(socket.AF_INET6, rd)))
        elif rtype == 5:
            out.append(("CNAME", read_name(i)[0]))
        elif rtype == 16:
            txt, k = b"", 0
            while k < len(rd):
                txt += rd[k + 1:k + 1 + rd[k]]
                k += 1 + rd[k]
            out.append(("TXT", txt.decode("utf-8", "replace")))
        i += rdlen
    return out


def png_text(data):
    out, i = {}, 8
    while i < len(data):
        n = struct.unpack("!I", data[i:i + 4])[0]
        kind = data[i + 4:i + 8]
        body = data[i + 8:i + 8 + n]
        if kind == b"tEXt":
            k, _, v = body.partition(b"\x00")
            out[k.decode("latin-1")] = v.decode("latin-1")
        elif kind == b"zTXt":
            k, _, v = body.partition(b"\x00")
            out[k.decode("latin-1")] = zlib.decompress(v[1:]).decode("latin-1")
        i += 12 + n
    return out


def untag(text):
    """Decode invisible Unicode tag characters."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0000 < ord(c) < 0xE0080)


def wait_file(path, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if os.path.exists(path):
            return True
        time.sleep(0.2)
    return False
