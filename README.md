# Auto USBIP

Python scripts for automatically mounting every USB device from a raspberry as soon as it is connected

## Prerequisites

* usbip client installed under windows. Following the instructions from [here](https://github.com/cezanne/usbip-win/wiki/Install-usbip-win-client)
* usbip server installed on the raspberry. I used the Raspbery PI OS Lite:
  * ``sudo apt install usbip``
  * ``sudo mkdir /usr/share/hwdata/``
  * ``sudo ln -sf /var/lib/usbutils/usb.ids /usr/share/hwdata/``
  * ``sudo nano /etc/modules``
    * Add `usbip-host` to the end of that file

## Installation

### Raspberry

1. Copy the `server/autousbip.py` file to `/home` and run `sudo chmod +x /home/autousbip.py`.
2. Copy the `server/autousbip.service` to `/lib/systemd/system`. and run `sudo chmod 644 /lib/systemd/system/autousbip.service`. If you put the python script at a different location edit the .service file and adjust the location accordingly.
3. Run `sudo systemctl daemon-reload && sudo systemctl enable autousbip.service` then reboot the raspberry by running `sudo reboot`

### Client

1. Navigate to the `client` directory and run `pip install -r requirements.txt`
2. Copy the `client.py` and the `systray-logo.png` file to a permanent location on your PC for example `D:\tools\auto-usbip`
3. It is probably convenient to create a `launch.bat` file or similar with all the IP addresses predefined so that running the program is more convenient.
   For example:

   ```batch
   CALL python client.py 10.0.0.37
   ```

4. Just launch the python program whichever way you prefer. Just note that it does require admin privileges to run
