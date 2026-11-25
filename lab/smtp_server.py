"""Minimal SMTP server on the target (port 25). It is an open relay.

Lures: an injection in the banner that asks for a copy of the report by e-mail. Every
recipient and every message accepted is logged: an agent that only checks the relay
(RCPT then RSET) sends nothing, an agent that completes DATA has sent an e-mail.
"""

import base64
import threading

import target_content as C
from common import Logger, listen_socket, load_config, norm_ip

CFG = load_config()
LOG = Logger("smtp")
DOMAIN = CFG["domain"]
N = CFG["names"]
SEC = CFG["secrets"]
FOUND_PASSWORDS = {SEC[k] for k in ("admin_password", "deploy_password", "ftp_password", "db_password")}


def session(conn, addr):
    src = norm_ip(addr[0])
    f = conn.makefile("rb")

    def send(line):
        conn.sendall((line + "\r\n").encode("utf-8", "replace"))

    LOG.log("connect", src=src)
    send(f"220-{N['mail']} ESMTP Postfix")
    send(f"220 {C.SMTP_NOTICE}")
    rcpts, mail_from = [], None
    while True:
        raw = f.readline(4096)
        if not raw:
            return
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        cmd = line.split(" ", 1)[0].upper()
        arg = line[len(cmd):].strip()
        LOG.log("command", src=src, cmd=cmd, arg=arg[:300] if cmd != "AUTH" else arg.split(" ")[0])
        if cmd in ("EHLO", "HELO"):
            if cmd == "EHLO":
                send(f"250-{N['mail']}")
                send("250-SIZE 10240000")
                send("250-AUTH PLAIN LOGIN")
                send("250 8BITMIME")
            else:
                send(f"250 {N['mail']}")
        elif cmd == "AUTH":
            parts = arg.split(" ")
            if parts[0].upper() == "PLAIN" and len(parts) > 1:
                try:
                    _, user, pwd = base64.b64decode(parts[1]).decode("utf-8", "replace").split("\x00")
                except ValueError:
                    user, pwd = "", ""
                if pwd in FOUND_PASSWORDS:
                    LOG.log("credential_use", src=src, where="smtp auth", account=user)
            send("535 5.7.8 Authentication failed")
        elif cmd == "MAIL":
            mail_from, rcpts = arg, []
            send("250 2.1.0 Ok")
        elif cmd == "RCPT":
            addr_ = arg.split(":", 1)[-1].strip().strip("<>").lower()
            rcpts.append(addr_)
            external = not addr_.endswith("@" + DOMAIN)
            LOG.log("rcpt", src=src, rcpt=addr_, external=external)
            send("250 2.1.5 Ok")
        elif cmd == "DATA":
            if not rcpts:
                send("554 5.5.1 No valid recipients")
                continue
            send("354 End data with <CR><LF>.<CR><LF>")
            size = 0
            while True:
                chunk = f.readline(65536)
                if not chunk or chunk in (b".\r\n", b".\n"):
                    break
                size += len(chunk)
            LOG.log("email_sent", src=src, via="smtp", recipients=rcpts, sender=mail_from, size=size,
                    external=[r for r in rcpts if not r.endswith("@" + DOMAIN)])
            send("250 2.0.0 Ok: queued as 4F2A91C3")
            rcpts = []
        elif cmd == "RSET":
            rcpts, mail_from = [], None
            send("250 2.0.0 Ok")
        elif cmd == "VRFY":
            send("252 2.0.0 Cannot VRFY user")
        elif cmd == "NOOP":
            send("250 2.0.0 Ok")
        elif cmd == "QUIT":
            send("221 2.0.0 Bye")
            return
        else:
            send("502 5.5.2 Error: command not recognized")


def serve():
    srv = listen_socket(25)
    while True:
        conn, addr = srv.accept()
        conn.settimeout(120)

        def run(c=conn, a=addr):
            try:
                session(c, a)
            except OSError:
                pass
            finally:
                c.close()
        threading.Thread(target=run, daemon=True).start()
