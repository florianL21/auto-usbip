from __future__ import annotations
from multiprocessing.connection import PipeConnection
from pathlib import Path
import socket
import subprocess
import time
import re
import os
import pystray
from PIL import Image
import threading
from multiprocessing import Pipe
import logging
import sys
from serial.tools import list_ports
from serial.tools.list_ports_common import ListPortInfo
from typing import TypeVar

USB_ID_REGEX = re.compile(r"^\s+([A-Za-z0-9.\-_]+)\:.*$")

# Port to use for pinging usbip servers
PORT = 3240

# Seconds to wait between polling the server for available connections
POLLING_TIME = 2

# How long to keep a connected port alive after the server has gone offline
PORT_KEEPALIVE_TIMEOUT = 5

# Seconds since last ping after a server connection is rechecked
SERVER_PING_CHECK = 10


class ImportedDevice:
    USB_PORT_REGEX = re.compile(
        r"^Port\s([A-Za-z0-9.\-_]+)\:\s+(.*)$\n\s+(.*)$", re.MULTILINE
    )
    BRACKET_REGEX = re.compile(r"^.*\((.*)\)$", re.MULTILINE)

    def __init__(
        self, match: tuple[str, str, str], serial_connections: list[ListPortInfo]
    ) -> None:
        port, kind, desc = match
        self.port = port.strip()
        self.kind = kind.strip()
        self.desc = desc.strip()
        self.speed: str | None = None
        re_match = ImportedDevice.BRACKET_REGEX.match(self.desc)
        if re_match:
            vid_pid = re_match.group(1)
            vid, pid = vid_pid.split(":")
            self._vid = int(vid, 16)
            self._pid = int(pid, 16)
        self._com_port = self.try_get_com_port(serial_connections)
        re_match = ImportedDevice.BRACKET_REGEX.match(self.kind)
        if re_match:
            self.speed = re_match.group(1)

    def try_get_com_port(self, serial_connections: list[ListPortInfo] | None = None):
        if serial_connections is None:
            serial_connections = list_ports.comports()
        if self.has_vid_pid:
            potential_matches = [
                conn.device
                for conn in serial_connections
                if conn.vid == self._vid and conn.pid == self._pid
            ]
            if len(potential_matches) == 1:
                return potential_matches[0]
        return None

    @property
    def com_port(self):
        if self._com_port is None and self.has_vid_pid:
            self._com_port = self.try_get_com_port()
        return self._com_port

    @property
    def has_vid_pid(self):
        return self._vid is not None and self._pid is not None

    def detach(self):
        detach_device(str(self.port))
        logger.info(f"Detached device {self.desc}")

    def __str__(self) -> str:
        if self.com_port is not None:
            return f"[{self.com_port}] Port {self.port}: {self.speed} -> {self.desc}"
        else:
            return f"Port {self.port}: {self.kind} -> {self.desc}"

    def connection(self) -> str:
        if self.com_port is not None:
            return self.com_port
        else:
            return f"Port {self.port}"

    def __hash__(self) -> int:
        if self.has_vid_pid:
            return hash(f"{self._vid}:{self._pid}")
        else:
            return hash(self.desc)


class ServerConnection:
    def __init__(self, ip: str, port: int) -> None:
        self.ip = ip
        self.port = port
        self._ping_result = (time.time(), self._ping())

    def _ping(self, timeout=3):
        try:
            socket.setdefaulttimeout(timeout)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.ip, self.port))
        except OSError:
            return False
        else:
            s.close()
            return True

    @property
    def is_alive(self):
        last_time, _ = self._ping_result
        current_time = time.time()
        if time.time() - last_time > SERVER_PING_CHECK:
            self._ping_result = (current_time, self._ping())
        return self._ping_result[1]


T = TypeVar("T")


def diff(old: set[T], new: set[T]):
    added: set[T] = set()
    removed: set[T] = set()
    diffs = set(old) ^ set(new)
    for item in diffs:
        if item in old:
            removed.add(item)
        else:
            added.add(item)
    return added, removed


def get_remote_usb_devices(ip: str):
    p = subprocess.run(["usbip", "list", "-p", "-r", ip], capture_output=True)
    usbids: list[str] = []
    if p.returncode != 0:
        logger.error(f"Error getting list of remote usb devices: {p.stderr.decode()}")
        return usbids
    output = p.stdout.decode()
    for line in output.split("\n"):
        match = USB_ID_REGEX.match(line)
        if match:
            usbids.append(match.group(1))
    return usbids


def get_imported_devices():
    p = subprocess.run(["usbip", "port"], capture_output=True)
    ports: list[ImportedDevice] = []
    if p.returncode != 0:
        logger.error(f"Error getting list of attached ports: {p.stderr.decode()}")
        return ports
    output = p.stdout.decode()
    serial_connections = list_ports.comports()
    matches = ImportedDevice.USB_PORT_REGEX.findall(output)
    for match in matches:
        ports.append(ImportedDevice(match, serial_connections))
    return ports


# trying to capture the command output seems to cause an endless loop in usbip for some reason
def attach_device(server: str, usbid: str):
    result = subprocess.run(["usbip", "attach", "-r", server, "-b", usbid, "-t"])
    if result.returncode != 0:
        logger.error("Error attaching usb device")
        return False
    return True


def detach_device(port: str):
    p = subprocess.run(["usbip", "detach", "-p", port], capture_output=True)
    if p.returncode != 0:
        logger.error(f"Error detaching usb device: {p.stderr.decode()}")
        return False
    return True


def detach_all_ports():
    for device in get_imported_devices():
        device.detach()


def main(
    servers: list[ServerConnection],
    kill_signal: PipeConnection,
    try_icon: pystray.Icon,
    server_list_lock: threading.Lock,
):
    os.environ["KEEPALIVE_TIMEOUT"] = str(PORT_KEEPALIVE_TIMEOUT)
    # detach all preexisting devices to start clean
    logger.info("cleaning up preexisting connections")
    detach_all_ports()
    try:
        while kill_signal.poll() == False:
            available_devices: list[tuple[str, str]] = []
            if server_list_lock.acquire():
                for server in servers:
                    if server.is_alive:
                        available_devices += [
                            (server.ip, id) for id in get_remote_usb_devices(server.ip)
                        ]
                server_list_lock.release()
            for server, available_device in available_devices:
                attach_device(server, available_device)
            try_icon.update_menu()
            time.sleep(POLLING_TIME)
    finally:
        detach_all_ports()


last_server_connections: set[ServerConnection] = set()
last_device_connections: set[ImportedDevice] = set()


def build_menu(
    icon: pystray.Icon,
    kill_signal: PipeConnection,
    servers: list[ServerConnection],
    server_list_lock: threading.Lock,
):
    global last_server_connections
    global last_device_connections

    def stop():
        icon.stop()
        kill_signal.send(True)

    current_server_connections: set[ServerConnection] = set()
    current_device_connections: set[ImportedDevice] = set()
    yield pystray.MenuItem("Servers:", action=lambda: None)
    yield pystray.Menu.SEPARATOR
    if server_list_lock.acquire(timeout=2):
        for server in servers:
            if server.is_alive:
                current_server_connections.add(server)
                yield pystray.MenuItem(f"[ONLINE] {server.ip}", action=lambda: None)
            else:
                yield pystray.MenuItem(
                    f"[OFFLINE] {server.ip}", action=lambda: None, enabled=False
                )
        server_list_lock.release()
    yield pystray.Menu.SEPARATOR
    yield pystray.MenuItem("Attached devices:", action=lambda: None)
    yield pystray.Menu.SEPARATOR
    for device in get_imported_devices():
        current_device_connections.add(device)
        yield pystray.MenuItem(str(device), action=lambda: None)
    yield pystray.Menu.SEPARATOR
    yield pystray.MenuItem("Exit", action=stop)

    new_servers, removed_servers = diff(
        last_server_connections, current_server_connections
    )
    new_devices, removed_devices = diff(
        set([hash(device) for device in last_device_connections]),
        set([hash(device) for device in current_device_connections]),
    )
    all_devices = current_device_connections.union(last_device_connections)
    device_map = {hash(device): device for device in all_devices}
    new_devices = [device_map[h] for h in new_devices]
    removed_devices = [device_map[h] for h in removed_devices]

    for server in new_servers:
        icon.notify(f"Server {server.ip} came online", "Online")

    for server in removed_servers:
        icon.notify(f"Server {server.ip} went offline", "Offline")

    for device in new_devices:
        icon.notify(
            f"Device connected: {device.desc}", f"Attached {device.connection()}"
        )

    for device in removed_devices:
        icon.notify(
            f"Device disconnected: {device.desc}", f"Removed {device.connection()}"
        )

    last_server_connections = current_server_connections
    last_device_connections = current_device_connections


if __name__ == "__main__":
    global logger
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("auto-usbip-client")
    if len(sys.argv) <= 1:
        logger.error(
            "Please provide a list of server IP addresses as command line arguments"
        )
    servers = [ServerConnection(ip, PORT) for ip in sys.argv[1:]]
    server_list_lock = threading.Lock()
    logo = Path("systray-logo.png")
    image = Image.open(logo)
    attached_devices: list[str] = []
    list_lock = threading.Lock()
    (kill_signal_rx, kill_signal_tx) = Pipe(False)
    tray_icon = pystray.Icon(
        "auto-usbip",
        icon=image,
        title="Auto USB IP",
        menu=pystray.Menu(
            lambda: build_menu(tray_icon, kill_signal_tx, servers, server_list_lock)
        ),
    )
    threading.Thread(
        target=lambda: main(servers, kill_signal_rx, tray_icon, server_list_lock)
    ).start()
    tray_icon.run()
