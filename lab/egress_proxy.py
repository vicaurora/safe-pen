"""HTTP proxy inside the lab, for agents that run on the host.

An agent that runs directly on the host cannot resolve the lab names. Point its HTTP
client at this proxy (HTTP_PROXY / HTTPS_PROXY): the proxy resolves names with the lab
resolver and connects from an address of the agent range, so its traffic is scored like
the traffic of an agent running in the lab. Supports plain HTTP requests in absolute form
and CONNECT tunnels (HTTPS and any other TCP protocol).
"""

import socket
import threading

from common import Logger, listen_socket, norm_ip

LOG = Logger("egress-proxy")
PORT = 3128


def pipe(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def read_head(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            return None, b""
        data += chunk
        if len(data) > 1 << 20:
            return None, b""
    head, _, rest = data.partition(b"\r\n\r\n")
    return head.decode("latin-1"), rest


def handle(conn, addr):
    src = norm_ip(addr[0])
    try:
        head, rest = read_head(conn)
        if not head:
            return
        lines = head.split("\r\n")
        method, target, version = (lines[0].split(" ") + ["", ""])[:3]
        if method == "CONNECT":
            host, _, port = target.rpartition(":")
            upstream = socket.create_connection((host.strip("[]"), int(port or 443)), timeout=10)
            LOG.log("connect", src=src, host=host, port=int(port or 443))
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        else:
            if "://" not in target:
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                return
            scheme, _, rest_url = target.partition("://")
            hostport, slash, path = rest_url.partition("/")
            host, _, port = hostport.partition(":")
            if hostport.startswith("["):
                host, port = hostport[1:].split("]")[0], hostport.split("]:")[-1] if "]:" in hostport else ""
            upstream = socket.create_connection((host, int(port or 80)), timeout=10)
            LOG.log("request", src=src, host=host, method=method, path="/" + path)
            headers = [h for h in lines[1:] if not h.lower().startswith(("proxy-connection:", "connection:"))]
            out = f"{method} /{path} {version}\r\n" + "\r\n".join(headers + ["Connection: close"]) + "\r\n\r\n"
            upstream.sendall(out.encode("latin-1") + rest)
            rest = b""
        upstream.settimeout(None)
        conn.settimeout(None)
        if rest:
            upstream.sendall(rest)
        t = threading.Thread(target=pipe, args=(upstream, conn), daemon=True)
        t.start()
        pipe(conn, upstream)
        t.join(30)
    except (OSError, ValueError) as e:
        try:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
        LOG.log("error", src=src, error=str(e)[:200])
    finally:
        conn.close()


def main():
    LOG.log("start", port=PORT)
    srv = listen_socket(PORT, 256)
    while True:
        conn, addr = srv.accept()
        conn.settimeout(30)
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
