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

PORT = 3240
USB_ID_REGEX = re.compile(r"^\s+([A-Za-z0-9.\-_]+)\:.*$")
POLLING_TIME = 2
PORT_KEEPALIVE_TIMEOUT = 5


def ping_server(server: str, port: int, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server, port))
    except OSError as error:
        return False
    else:
        s.close()
        return True


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
    servers: list[str],
    kill_signal: PipeConnection,
    try_icon: pystray.Icon,
):
    os.environ["KEEPALIVE_TIMEOUT"] = str(PORT_KEEPALIVE_TIMEOUT)
    # detach all preexisting devices to start clean
    logger.info("cleaning up preexisting connections")
    detach_all_ports()
    try:
        while kill_signal.poll() == False:
            available_devices: list[tuple[str, str]] = []
            for server_ip in servers:
                if ping_server(server_ip, PORT):
                    available_devices += [
                        (server_ip, id) for id in get_remote_usb_devices(server_ip)
                    ]
            for server, available_device in available_devices:
                attach_device(server, available_device)
            try_icon.update_menu()
            time.sleep(POLLING_TIME)
    finally:
        detach_all_ports()


def build_menu(
    icon: pystray.Icon,
    kill_signal: PipeConnection,
):
    def stop():
        icon.stop()
        kill_signal.send(True)

    for device in get_imported_devices():
        yield pystray.MenuItem(str(device), action=lambda: None, enabled=False)
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
    servers = sys.argv[1:]
    logo = Path("systray-logo.png")
    image = Image.open(logo)
    attached_devices: list[str] = []
    list_lock = threading.Lock()
    (kill_signal_rx, kill_signal_tx) = Pipe(False)
    tray_icon = pystray.Icon(
        "auto-usbip",
        icon=image,
        title="Auto USB IP",
        menu=pystray.Menu(lambda: build_menu(tray_icon, kill_signal_tx)),
    )
    threading.Thread(target=lambda: main(servers, kill_signal_rx, tray_icon)).start()
    tray_icon.run()
