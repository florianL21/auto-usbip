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
from urllib3 import Retry

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
        self.vid = None
        self.pid = None
        self.com_port = None
        re_match = ImportedDevice.BRACKET_REGEX.match(self.kind)
        if re_match:
            self.speed = re_match.group(1)
        re_match = ImportedDevice.BRACKET_REGEX.match(self.desc)

        if re_match:
            vid_pid = re_match.group(1)
            vid, pid = vid_pid.split(":")
            self.vid = int(vid, 16)
            self.pid = int(pid, 16)
            potential_matches = [
                conn.device
                for conn in serial_connections
                if conn.vid == self.vid and conn.pid == self.pid
            ]
            if len(potential_matches) == 1:
                self.com_port = potential_matches[0]

    def detach(self):
        detach_device(str(self.port))
        logger.info(f"Detached device {self.desc}")

    def __str__(self) -> str:
        if self.vid is not None and self.pid is not None:
            return f"[{self.com_port}] Port {self.port}: {self.speed} -> {self.desc}"
        else:
            return f"Port {self.port}: {self.kind} -> {self.desc}"


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


def build_menu(
    icon: pystray.Icon,
    kill_signal: PipeConnection,
    servers: list[ServerConnection],
    server_list_lock: threading.Lock,
):
    def stop():
        icon.stop()
        kill_signal.send(True)

    yield pystray.MenuItem("Servers:", action=lambda: None)
    yield pystray.Menu.SEPARATOR
    if server_list_lock.acquire(timeout=2):
        for server in servers:
            if server.is_alive:
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
        yield pystray.MenuItem(str(device), action=lambda: None)
    yield pystray.Menu.SEPARATOR
    yield pystray.MenuItem("Exit", action=stop)


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
