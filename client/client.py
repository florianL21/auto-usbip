import socket
import subprocess
import time
import re
import os

PORT = 3240
SERVERS = ["10.0.0.37"]
USB_ID_REGEX = re.compile(r"^\s+([A-Za-z0-9.\-_]+)\:.*$")
USB_PORT_REGEX = re.compile(r"^Port\s([A-Za-z0-9.\-_]+)\:.*$")
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


def get_imported_devices():
    p = subprocess.run(["usbip", "port"], capture_output=True)
    ports: list[int] = []
    if p.returncode != 0:
        print(f"Error getting list of attached ports: {p.stderr.decode()}")
        return ports
    output = p.stdout.decode()
    for line in output.split("\n"):
        match = USB_PORT_REGEX.match(line)
        if match:
            ports.append(int(match.group(1)))
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
        detach_device(str(device))
        print(f"Detached device {device}")


def main():
    os.environ["KEEPALIVE_TIMEOUT"] = str(PORT_KEEPALIVE_TIMEOUT)
    # detach all preexisting devices to start clean
    print("cleaning up preexisting connections")
    detach_all_ports()
    attached_devices: list[str] = []
    try:
        while True:
            available_devices: list[tuple[str, str]] = []
            for server_ip in SERVERS:
                if ping_server(server_ip, PORT):
                    available_devices += [
                        (server_ip, id) for id in get_remote_usb_devices(server_ip)
                    ]
            for server, available_device in available_devices:
                if attach_device(server, available_device):
                    attached_devices.append(available_device)
                    print(f"Attached {available_device}")

            time.sleep(POLLING_TIME)
    finally:
        detach_all_ports()


if __name__ == "__main__":
    main()
