#!/usr/bin/env python3
import subprocess
import time

usbip_daemon = subprocess.Popen(["usbipd"])

bound_busids = []
detected_busids = []


def bind_usbdevice(busid: str) -> bool:
    p = subprocess.Popen(["usbip", "bind", "-b", busid], stderr=subprocess.PIPE)
    _, err = p.communicate()
    if p.returncode != 0:
        print(f"Failed to bind usb device {busid}: {err.decode()}")
    return p.returncode == 0


def unbind_usbdevice(busid: str) -> bool:
    p = subprocess.Popen(["usbip", "unbind", "-b", busid], stderr=subprocess.PIPE)
    _, err = p.communicate()
    if p.returncode != 0:
        print(f"Failed to unbind usb device {busid}: {err.decode()}")
    return p.returncode == 0


try:
    while True:
        p = subprocess.Popen(["usbip", "list", "-p", "-l"], stdout=subprocess.PIPE)
        output, _ = p.communicate()
        output = output.decode()
        if p.returncode == 0:
            lines = output.split("\n")
            for line in lines:
                busid = line.split("#")[0]
                if busid.startswith("busid="):
                    busid = busid[6:]
                    detected_busids.append(busid)
                    if busid not in bound_busids:
                        if bind_usbdevice(busid):
                            bound_busids.append(busid)
                        else:
                            unbind_usbdevice(
                                busid
                            )  # if binding failed try to unbind and rebind with next iteration

            ids_to_remove = []
            for binded_busid in bound_busids:
                if binded_busid not in detected_busids:
                    # assume that the device has been unplugged
                    ids_to_remove.append(binded_busid)
            for id in ids_to_remove:
                bound_busids.remove(id)
        else:
            print(f"Failed getting usb device list: {output}")
        time.sleep(1)
except Exception:
    pass
finally:
    usbip_daemon.terminate()
    print("Terminated usbip server")
