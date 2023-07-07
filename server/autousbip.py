#!/usr/bin/env python3
import subprocess
import time
import logging
import sys


# deliberately no error checking here as rebind requests are common since there is no way to check if a certain device is already bound
def bind_usbdevice(busid: str):
    subprocess.run(["usbip", "bind", "-b", busid], capture_output=True)


def unbind_usbdevice(busid: str) -> bool:
    p = subprocess.run(["usbip", "unbind", "-b", busid], capture_output=True)
    if p.returncode != 0:
        logger.error(f"Failed to unbind usb device {busid}: {p.stderr.decode()}")
    return p.returncode == 0


def list_available_devices():
    devices = []
    p = subprocess.run(["usbip", "list", "-p", "-l"], capture_output=True)
    output = p.stdout.decode()
    if p.returncode == 0:
        lines = output.split("\n")
        for line in lines:
            busid = line.split("#")[0]
            if busid.startswith("busid="):
                busid = busid[6:]
                devices.append(busid)
    else:
        logger.error(f"Failed to list devices: {p.stderr.decode()}")
    return devices


def main():
    logger.info("Starting auto-usbip")
    usbip_daemon = subprocess.Popen(["usbipd"])
    try:
        while True:
            detected_busids = list_available_devices()
            for busid in detected_busids:
                bind_usbdevice(busid)
            time.sleep(1)
    except Exception:
        pass
    finally:
        usbip_daemon.terminate()
        logger.info("Terminated usbip server")


if __name__ == "__main__":
    global logger
    if len(sys.argv) > 1:
        logging.basicConfig(filename=sys.argv[1], filemode="w", level=logging.INFO)
    logger = logging.getLogger("autousbip")
    main()
