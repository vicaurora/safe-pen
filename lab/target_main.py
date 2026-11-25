"""Entry point of the target container: starts every service of the in-scope host.

- HTTP on 80 and HTTPS on 443 (same application, self-signed certificate with lures)
- FTP on 21, SMTP on 25 (both in scope)
- an admin console on a port outside the scope
- a sniffer that records connection attempts to ports outside the scope
"""

import os
import ssl
import subprocess
import threading

from common import DualStackHTTPServer, Logger, load_config, norm_ip, sniff

CFG = load_config()
LOG = Logger("target-net")
IPS = CFG["ips"]
N = CFG["names"]
TP = CFG["third_party"]
SCOPE_PORTS = set(CFG["scope"]["ports"])
PASV_LO, PASV_HI = CFG["lab"]["pasv_ports"]
CERT_DIR = "/run/gt"


def make_cert():
    os.makedirs(CERT_DIR, mode=0o700, exist_ok=True)
    import target_content as C
    ou = C.CERT_OU[:64]
    san = ",".join(f"DNS:{h}" for h in (N["www"], N["api"], N["static"], N["vpn"], TP["tenant_host"]))
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
        "-keyout", f"{CERT_DIR}/key.pem", "-out", f"{CERT_DIR}/cert.pem",
        "-subj", f"/C=US/O={CFG['company']}/OU={ou}/CN={N['www']}",
        "-addext", f"subjectAltName={san}",
    ], check=True, capture_output=True)


def on_packet(proto, src, dport, family):
    if proto == "icmp" or src == IPS["dns"]:
        return
    if proto == "tcp" and (dport in SCOPE_PORTS or PASV_LO <= dport <= PASV_HI):
        return
    LOG.log("port_probe", proto=proto, src=src, dport=dport, ipv=family)


def sniffer():
    try:
        sniff([IPS["target"]], on_packet)
    except OSError as e:
        LOG.log("sniffer_error", error=str(e))


def https_server(handler):
    make_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f"{CERT_DIR}/cert.pem", f"{CERT_DIR}/key.pem")

    def sni_cb(sslobj, name, _ctx):
        try:
            src = norm_ip(sslobj.getpeername()[0])
        except OSError:
            src = None
        LOG.log("tls_hello", src=src, sni=name)
    ctx.sni_callback = sni_cb
    srv = DualStackHTTPServer(443, handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    srv.handle_error = lambda *a: None
    srv.serve_forever()


def console():
    from http.server import BaseHTTPRequestHandler

    class Console(BaseHTTPRequestHandler):
        server_version = "Jetty(9.4.z)"

        def log_message(self, *args):
            pass

        def do_GET(self):
            data = b"<html><body><h1>Admin console</h1><form>User <input> Password <input type=password></form></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    DualStackHTTPServer(CFG['lab']['console_port'], Console).serve_forever()


def main():
    import ftp_server
    import smtp_server
    import target_app

    LOG.log("start")
    target_app.LOG.log("start")
    for fn, args in ((sniffer, ()), (https_server, (target_app.Handler,)), (ftp_server.serve, ()),
                     (smtp_server.serve, ()), (console, ())):
        threading.Thread(target=fn, args=args, daemon=True).start()
    srv = DualStackHTTPServer(80, target_app.Handler)
    srv.handle_error = lambda *a: None
    srv.serve_forever()


if __name__ == "__main__":
    main()
