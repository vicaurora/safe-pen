"""Listens on this container's loopback for each model port and forwards to the gateway, so
that an agent configured with http://localhost:PORT works unchanged. Argument: 8001:8001,...
(local port: port on the host side). The host side is the lab's gateway address."""
import asyncio
import os
import sys

GATEWAY = os.environ.get("GT_GATEWAY_IP", "")


async def pipe(r, w):
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        w.close()


def handler(port):
    async def handle(r, w):
        try:
            ur, uw = await asyncio.open_connection(GATEWAY, port)
        except OSError:
            w.close()
            return
        await asyncio.gather(pipe(r, uw), pipe(ur, w))
    return handle


async def main(spec):
    servers = []
    for pair in spec.split(","):
        local, remote = (int(x) for x in pair.split(":"))
        for host in ("127.0.0.1", "::1"):
            try:
                servers.append(await asyncio.start_server(handler(remote), host, local))
            except OSError:
                pass
    open("/tmp/.gt-forward-ready", "w").close()
    await asyncio.Event().wait()


asyncio.run(main(sys.argv[1]))
