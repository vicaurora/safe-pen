"""--sandbox: run an agent that executes its tools on the machine inside a container of the lab
network, so that every request, scan and DNS query it makes reaches the lab and is scored.

The current directory and the run's directories are mounted at the same paths, the environment
is passed, files are written with the caller's user, and the model stays reachable at the same
URL: a port of the host's loopback is forwarded through the lab's gateway address, and the names
of model APIs found in the environment are added to the lab resolver's allowlist.
"""

import hashlib
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGE = "safepen-sandbox:1"
MODEL_VARS = re.compile(r"(?i)(MODEL|LLM|OPENAI|ANTHROPIC|OLLAMA|API_BASE|BASE_URL|LITELLM|GEMINI|MISTRAL|OPENROUTER"
                        r"|AZURE|DEEPSEEK|GROQ|TOGETHER|VLLM|LLAMA)")
URL_RE = re.compile(r"\b(https?)://(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)(?::(\d+))?")
LOCAL = {"localhost", "127.0.0.1", "::1"}
# Not passed to the container: host paths and sessions, and proxies the container cannot reach.
SKIP_ENV = re.compile(r"^(PATH|HOME|USER|LOGNAME|SHELL|PWD|OLDPWD|SHLVL|HOSTNAME|MAIL|TMPDIR|_|LS_COLORS|DISPLAY"
                      r"|WAYLAND_DISPLAY|XAUTHORITY|SSH_.*|DBUS_.*|XDG_.*|LD_.*|VIRTUAL_ENV|CONDA_.*|PYENV_.*"
                      r"|(?i:https?_proxy|all_proxy|no_proxy)|SUDO_.*|DESKTOP_.*|GNOME_.*|KDE_.*|SESSION_.*|WINDOWID"
                      r"|COLORTERM|TERM_.*|VTE_.*|GDM.*|INVOCATION_ID|JOURNAL_STREAM|MANAGERPID|SYSTEMD_.*)$")


def model_endpoints(explicit=()):
    """(local ports, remote host names) of the model, from --model and the model variables."""
    ports, hosts = set(), set()
    texts = list(explicit) + [v for k, v in os.environ.items() if MODEL_VARS.search(k)]
    for text in texts:
        for m in URL_RE.finditer(text):
            host = m.group(2).strip("[]").lower()
            port = int(m.group(3) or (443 if m.group(1) == "https" else 80))
            if host in LOCAL:
                ports.add(port)
            else:
                hosts.add(host)
    return sorted(ports), sorted(hosts)


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def ensure_image(image=None):
    """The sandbox image, with ./requirements.txt installed when there is one (built once)."""
    if image:
        return image
    if _run(["docker", "image", "inspect", IMAGE]).returncode:
        print(f"Building the sandbox image {IMAGE} (once, a few minutes)...", flush=True)
        r = _run(["docker", "build", "-t", IMAGE, os.path.join(ROOT, "sandbox")])
        if r.returncode:
            sys.exit("The build of the sandbox image failed:\n" + (r.stdout + r.stderr)[-3000:])
    req = os.path.join(os.getcwd(), "requirements.txt")
    if not os.path.exists(req):
        return IMAGE
    tag = "safepen-sandbox-env:" + hashlib.sha256(open(req, "rb").read() + IMAGE.encode()).hexdigest()[:12]
    if _run(["docker", "image", "inspect", tag]).returncode == 0:
        return tag
    print("Installing requirements.txt in the sandbox image (once for this file)...", flush=True)
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copy(req, os.path.join(tmp, "requirements.txt"))
        with open(os.path.join(tmp, "Dockerfile"), "w") as f:
            f.write(f"FROM {IMAGE}\nCOPY requirements.txt /tmp/requirements.txt\n"
                    "RUN pip install --no-cache-dir -r /tmp/requirements.txt\n")
        r = _run(["docker", "build", "-t", tag, tmp])
        if r.returncode:
            sys.exit("pip could not install requirements.txt in the sandbox image:\n" + (r.stdout + r.stderr)[-3000:])
    return tag


class Forwarder:
    """Listens on the lab's gateway address for each local model port and forwards to the host's
    loopback. A port that is already open on that address (a model listening on 0.0.0.0) is left
    as it is."""

    def __init__(self, gateway, ports):
        self.socks = []
        for port in ports:
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((gateway, port))
            except OSError:
                s.close()
                continue
            s.listen(16)
            self.socks.append(s)
            threading.Thread(target=self._accept, args=(s, port), daemon=True).start()

    def _accept(self, srv, port):
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            try:
                u = socket.create_connection(("127.0.0.1", port), timeout=10)
            except OSError:
                c.close()
                continue
            u.settimeout(None)
            for a, b in ((c, u), (u, c)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()

    @staticmethod
    def _pipe(a, b):
        try:
            while data := a.recv(65536):
                b.sendall(data)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def close(self):
        for s in self.socks:
            s.close()


def command(agent_cmd, ph, cfg, env, image, ports, root=False):
    """The shell command that runs agent_cmd in a container of the lab network."""
    cwd = os.getcwd()
    mounts = []
    for path, mode in ((cwd, "rw"), (ph["{engagement}"], "ro"), (ph["{output}"], "rw"), (ph["{control}"], "rw")):
        if os.path.exists(path):
            mounts += ["-v", f"{path}:{path}:{mode}"]
    args = ["docker", "run", "--rm", "-i", "--name", ph["{container}"], "--network", cfg["network"],
            "--dns", cfg["ips"]["dns"], "--security-opt", "no-new-privileges", *mounts, "-w", cwd,
            "-v", f"{os.path.join(ROOT, 'sandbox')}:/gt-sandbox:ro", "-e", "HOME=/tmp",
            "-e", f"GT_FORWARD={','.join(f'{p}:{p}' for p in ports)}", "-e", f"GT_GATEWAY_IP={cfg['ips']['gateway']}",
            "--entrypoint", "/bin/sh"]
    args += ["--cap-add", "NET_RAW"] if root else ["--user", f"{os.getuid()}:{os.getgid()}"]
    for k in env:
        if not SKIP_ENV.match(k) and not k.startswith("GT_FORWARD"):
            args += ["-e", k]
    args += [image, "/gt-sandbox/entry.sh", agent_cmd]
    return " ".join(shlex.quote(a) for a in args)
