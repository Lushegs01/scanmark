"""
A slow, unreliable mobile link, in front of a real browser.

WHY NOT DEVTOOLS THROTTLING
---------------------------
Chrome's built-in throttling (CDP ``Network.emulateNetworkConditions``) adds
a fixed latency to each *request* of the page it is attached to. It does not
model connection setup, so it hides exactly the cost that dominates on a
high-latency network — a new TCP connection plus TLS is two round trips
before the first byte of a request, and every extra origin a page uses pays
it again. It also does not apply to the service worker's own fetches, which
is where a scan is retried.

This is a TCP relay instead. Everything the browser sends goes through it, so
everything pays the same link: page, service worker, and third-party CDNs.

  * latency   each chunk is delivered one-way-latency after it was sent
  * bandwidth one FIFO link per direction, SHARED by every connection, so a
              background download competes with the scan for the radio the
              way it does on a phone
  * setup     a new connection to the app waits ``--setup-rtts`` round trips
              (2 = TCP + TLS 1.3) before its first byte moves
  * stall     everything in flight is held, connections stay open — the
              2G cell that stops answering for a while
  * drop      every connection is reset and new ones are refused — no signal

Two listeners:

  --app-listen   -> --app-target     the ScanMark server (plain HTTP locally;
                                     setup-rtts models the TLS it has in
                                     production)
  --proxy-listen -> --proxy-target   an HTTP proxy for third-party origins.
                                     The browser's CONNECT goes through the
                                     link, so the CONNECT exchange models the
                                     TCP handshake and the real TLS handshake
                                     inside the tunnel pays real round trips.

Control (JSON), on --control:
  GET /set?rtt=800&down=250&up=100   profile (ms, kbit/s, kbit/s)
  GET /set?stall=1 | stall=0         hold / release everything in flight
  GET /set?drop=1 | drop=0           reset everything and refuse new
  GET /reset                         close every open connection (an idle
                                     phone whose connections were reaped)
  GET /stats                         bytes and connections so far
"""

import argparse
import asyncio
import json
import time
from urllib.parse import parse_qs, urlsplit


class Link:
    """One direction of the radio: a FIFO serialiser plus propagation delay."""

    def __init__(self, kbps):
        self.set_rate(kbps)
        self._free_at = 0.0
        self.bytes = 0

    def set_rate(self, kbps):
        self.bytes_per_s = max(1.0, float(kbps) * 1000 / 8)

    async def transmit(self, size):
        loop = asyncio.get_running_loop()
        now = loop.time()
        start = max(now, self._free_at)
        self._free_at = start + size / self.bytes_per_s
        self.bytes += size
        wait = self._free_at - now
        if wait > 0:
            await asyncio.sleep(wait)


class Network:
    def __init__(self, rtt_ms, down_kbps, up_kbps):
        self.rtt = rtt_ms / 1000
        self.down = Link(down_kbps)
        self.up = Link(up_kbps)
        self.stalled = asyncio.Event()
        self.stalled.set()            # set == flowing
        self.dropped = False
        self.connections = set()
        self.opened = {'app': 0, 'proxy': 0}

    async def wait_flowing(self):
        await self.stalled.wait()

    def close_all(self):
        for writer in list(self.connections):
            try:
                writer.transport.abort()
            except Exception:         # noqa: BLE001
                pass
        self.connections.clear()


async def pump(network, reader, writer, link, label_stats):
    """Relay one direction: read, serialise on the shared link, delay, write."""
    loop = asyncio.get_running_loop()
    deliveries = asyncio.Queue()

    async def deliver():
        while True:
            due, chunk = await deliveries.get()
            if chunk is None:
                break
            delay = due - loop.time()
            if delay > 0:
                await asyncio.sleep(delay)
            await network.wait_flowing()
            writer.write(chunk)
            await writer.drain()
        try:
            writer.write_eof()
        except (OSError, RuntimeError):
            pass

    deliverer = asyncio.create_task(deliver())
    try:
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            await network.wait_flowing()
            await link.transmit(len(chunk))
            label_stats[0] += len(chunk)
            deliveries.put_nowait((loop.time() + network.rtt / 2, chunk))
    except (ConnectionError, OSError):
        pass
    finally:
        deliveries.put_nowait((0, None))
        try:
            await deliverer
        except (ConnectionError, OSError):
            pass


def handler(network, label, target_host, target_port, setup_rtts):
    async def handle(client_reader, client_writer):
        if network.dropped:
            client_writer.transport.abort()
            return
        network.opened[label] += 1
        network.connections.add(client_writer)
        opened = [client_writer]
        try:
            if setup_rtts:
                await asyncio.sleep(network.rtt * setup_rtts)
            await network.wait_flowing()
            if network.dropped:
                return
            server_reader, server_writer = await asyncio.open_connection(
                target_host, target_port)
            opened.append(server_writer)
            network.connections.add(server_writer)
            up_stats, down_stats = [0], [0]
            await asyncio.gather(
                pump(network, client_reader, server_writer, network.up, up_stats),
                pump(network, server_reader, client_writer, network.down, down_stats),
            )
        except (ConnectionError, OSError):
            pass
        finally:
            for writer in opened:
                network.connections.discard(writer)
                try:
                    writer.close()
                except Exception:     # noqa: BLE001
                    pass
    return handle


def control_handler(network):
    async def handle(reader, writer):
        try:
            request_line = (await reader.readline()).decode()
            while (await reader.readline()) not in (b'\r\n', b'\n', b''):
                pass
            target = request_line.split(' ')[1]
            parts = urlsplit(target)
            query = {key: values[-1] for key, values in parse_qs(parts.query).items()}
            if parts.path == '/set':
                if 'rtt' in query:
                    network.rtt = float(query['rtt']) / 1000
                if 'down' in query:
                    network.down.set_rate(query['down'])
                if 'up' in query:
                    network.up.set_rate(query['up'])
                if 'stall' in query:
                    if query['stall'] == '1':
                        network.stalled.clear()
                    else:
                        network.stalled.set()
                if 'drop' in query:
                    network.dropped = query['drop'] == '1'
                    if network.dropped:
                        network.close_all()
            elif parts.path == '/reset':
                network.close_all()
            body = json.dumps({
                'rtt_ms': round(network.rtt * 1000),
                'down_bytes': network.down.bytes,
                'up_bytes': network.up.bytes,
                'connections_opened': network.opened,
                'stalled': not network.stalled.is_set(),
                'dropped': network.dropped,
                'at': time.time(),
            }).encode()
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                         b'Content-Length: ' + str(len(body)).encode() +
                         b'\r\nConnection: close\r\n\r\n' + body)
            await writer.drain()
        finally:
            writer.close()
    return handle


def host_port(text):
    host, _, port = text.rpartition(':')
    return host or '127.0.0.1', int(port)


async def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--app-listen', required=True)
    parser.add_argument('--app-target', required=True)
    parser.add_argument('--proxy-listen')
    parser.add_argument('--proxy-target')
    parser.add_argument('--control', required=True)
    parser.add_argument('--rtt', type=float, default=0)
    parser.add_argument('--down', type=float, default=100000)
    parser.add_argument('--up', type=float, default=100000)
    parser.add_argument('--setup-rtts', type=float, default=2)
    args = parser.parse_args()

    network = Network(args.rtt, args.down, args.up)
    servers = []
    host, port = host_port(args.app_listen)
    servers.append(await asyncio.start_server(
        handler(network, 'app', *host_port(args.app_target), args.setup_rtts),
        host, port, backlog=512))
    if args.proxy_listen and args.proxy_target:
        host, port = host_port(args.proxy_listen)
        servers.append(await asyncio.start_server(
            handler(network, 'proxy', *host_port(args.proxy_target), 0),
            host, port, backlog=512))
    host, port = host_port(args.control)
    servers.append(await asyncio.start_server(control_handler(network), host, port))
    print('throttle proxy ready', flush=True)
    await asyncio.gather(*(server.serve_forever() for server in servers))


if __name__ == '__main__':
    asyncio.run(main())
