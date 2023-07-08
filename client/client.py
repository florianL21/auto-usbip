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

PORT = 3240
SERVERS = ["10.0.0.37"]
USB_ID_REGEX = re.compile(r"^\s+([A-Za-z0-9.\-_]+)\:.*$")
USB_PORT_REGEX = re.compile(
    r"^Port\s([A-Za-z0-9.\-_]+)\:\s+(.*)$\n\s+(.*)$", re.MULTILINE
)
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
        print(f"Error getting list of remote usb devices: {p.stderr.decode()}")
        return usbids
    output = p.stdout.decode()
    for line in output.split("\n"):
        match = USB_ID_REGEX.match(line)
        if match:
            usbids.append(match.group(1))
    return usbids


class ImportedDevice:
    def __init__(self, port: int, kind: str, desc: str) -> None:
        self.port = port
        self.kind = kind
        self.desc = desc

    def detach(self):
        detach_device(str(self.port))
        print(f"Detached device {self.desc}")

    def __str__(self) -> str:
        return f"Port {self.port}: {self.kind}\n{self.desc}"


def get_imported_devices():
    p = subprocess.run(["usbip", "port"], capture_output=True)
    ports: list[ImportedDevice] = []
    if p.returncode != 0:
        print(f"Error getting list of attached ports: {p.stderr.decode()}")
        return ports
    output = p.stdout.decode()
    matches = USB_PORT_REGEX.findall(output)
    for port, type, desc in matches:
        ports.append(ImportedDevice(int(port), type, desc))
    return ports


# trying to capture the command output seems to cause an endless loop in usbip for some reason
def attach_device(server: str, usbid: str):
    result = subprocess.run(["usbip", "attach", "-r", server, "-b", usbid, "-t"])
    if result.returncode != 0:
        print("Error attaching usb device")
        return False
    return True


def detach_device(port: str):
    p = subprocess.run(["usbip", "detach", "-p", port], capture_output=True)
    if p.returncode != 0:
        print(f"Error detaching usb device: {p.stderr.decode()}")
        return False
    return True


def detach_all_ports():
    for device in get_imported_devices():
        device.detach()


def main(
    kill_signal: PipeConnection,
    try_icon: pystray.Icon,
):
    os.environ["KEEPALIVE_TIMEOUT"] = str(PORT_KEEPALIVE_TIMEOUT)
    # detach all preexisting devices to start clean
    print("cleaning up preexisting connections")
    detach_all_ports()
    try:
        while kill_signal.poll() == False:
            available_devices: list[tuple[str, str]] = []
            for server_ip in SERVERS:
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
        yield pystray.MenuItem(str(device), action=lambda: None)
    yield pystray.Menu.SEPARATOR
    yield pystray.MenuItem("Exit", action=stop)


if __name__ == "__main__":
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
    threading.Thread(target=lambda: main(kill_signal_rx, tray_icon)).start()
    tray_icon.run()
