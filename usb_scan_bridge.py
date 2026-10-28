#!/usr/bin/env python3
"""Host-side HZTZ USB-HID reader that forwards scans to ScanBase over HTTP.

Run as root on the Synology host (DSM Task Scheduler). The Docker container
then needs only its web port and /data volume; it does not need USB mounts.
"""
import ctypes
import errno
import glob
import json
import os
import queue
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request

VID, PID = "5131", "2007"
INTERFACE_NUMBER = 0
SCANBASE_URL = os.environ.get("SCANBASE_URL", "http://127.0.0.1:8081/api/ingest")
STOP = threading.Event()
SCANS = queue.Queue()
ACTIVE_LOCK = threading.Lock()
ACTIVE = {"fd": None, "urb": None, "pending": False}

# Linux USBFS ioctl encoding (DS218+ is x86_64).
def ioc(direction, letter, number, size):
    return (direction << 30) | (size << 16) | (ord(letter) << 8) | number


class URB(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_ubyte), ("endpoint", ctypes.c_ubyte),
        ("status", ctypes.c_int), ("flags", ctypes.c_uint),
        ("buffer", ctypes.c_void_p), ("buffer_length", ctypes.c_int),
        ("actual_length", ctypes.c_int), ("start_frame", ctypes.c_int),
        ("number_of_packets", ctypes.c_int), ("error_count", ctypes.c_int),
        ("signr", ctypes.c_uint), ("usercontext", ctypes.c_void_p),
    ]


libc = ctypes.CDLL(None, use_errno=True)
libc.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
libc.ioctl.restype = ctypes.c_int
IO_SUBMIT = ioc(2, "U", 10, ctypes.sizeof(URB))
IO_DISCARD = (ord("U") << 8) | 11
IO_REAP = ioc(1, "U", 12, ctypes.sizeof(ctypes.c_void_p))
IO_REAP_NDELAY = ioc(1, "U", 13, ctypes.sizeof(ctypes.c_void_p))
IO_CLAIM = ioc(2, "U", 15, ctypes.sizeof(ctypes.c_uint))
IO_RELEASE = ioc(2, "U", 16, ctypes.sizeof(ctypes.c_uint))


def ioctl_ptr(fd, request, obj):
    ctypes.set_errno(0)
    if libc.ioctl(fd, request, ctypes.byref(obj)) < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def read_text(path):
    with open(path, "r", encoding="ascii") as f:
        return f.read().strip()


def ensure_hid_modules():
    modules = [
        ("hid", "/usr/lib/modules/hid.ko"),
        ("usbhid", "/usr/lib/modules/usbhid.ko"),
        ("hid_generic", "/usr/lib/modules/hid-generic.ko"),
    ]
    for module, path in modules:
        if os.path.isdir("/sys/module/" + module):
            continue
        insmod = next((candidate for candidate in ("/sbin/insmod", "/usr/sbin/insmod")
                       if os.path.exists(candidate)), "insmod")
        try:
            subprocess.run([insmod, path], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False)
        except FileNotFoundError:
            print("insmod niet gevonden; controleer of HID-modules geladen zijn.", flush=True)
            break


def find_scanner():
    for vp in glob.glob("/sys/bus/usb/devices/*/idVendor"):
        device_dir = os.path.dirname(vp)
        try:
            if read_text(vp).lower() != VID:
                continue
            if read_text(os.path.join(device_dir, "idProduct")).lower() != PID:
                continue
            name = os.path.basename(device_dir)
            interface = f"{name}:1.{INTERFACE_NUMBER}"
            interface_dir = f"/sys/bus/usb/devices/{interface}"
            if not os.path.isdir(interface_dir):
                raise RuntimeError("Scannerinterface 0 niet gevonden")
            endpoint = packet_size = None
            for ep in glob.glob(os.path.join(interface_dir, "ep_*")):
                address = int(read_text(os.path.join(ep, "bEndpointAddress")), 16)
                attributes = int(read_text(os.path.join(ep, "bmAttributes")), 16)
                if address & 0x80 and (attributes & 3) == 3:
                    endpoint = address
                    packet_size = int(read_text(os.path.join(ep, "wMaxPacketSize")), 16) & 0x7ff
                    break
            if endpoint is None or not packet_size:
                raise RuntimeError("USB interrupt-IN-endpoint niet gevonden")
            bus = int(read_text(os.path.join(device_dir, "busnum")))
            dev = int(read_text(os.path.join(device_dir, "devnum")))
            return interface, interface_dir, f"/dev/bus/usb/{bus:03d}/{dev:03d}", endpoint, packet_size
        except (OSError, ValueError):
            continue
    raise RuntimeError(f"Scanner {VID}:{PID} niet gevonden")


def key_text(code, shift):
    if 0x04 <= code <= 0x1D:
        ch = chr(ord("a") + code - 0x04)
        return ch.upper() if shift else ch
    if 0x1E <= code <= 0x27:
        plain, shifted = "1234567890", "!@#$%^&*()"
        i = code - 0x1E
        return shifted[i] if shift else plain[i]
    if code == 0x2C:
        return " "
    pairs = {
        0x2D: ("-", "_"), 0x2E: ("=", "+"), 0x2F: ("[", "{"),
        0x30: ("]", "}"), 0x31: ("\\", "|"), 0x33: (";", ":"),
        0x34: ("'", '"'), 0x35: ("`", "~"), 0x36: (",", "<"),
        0x37: (".", ">"), 0x38: ("/", "?"),
    }
    pair = pairs.get(code)
    return pair[1 if shift else 0] if pair else ""


def post_scans():
    while not STOP.is_set():
        try:
            code = SCANS.get(timeout=0.5)
        except queue.Empty:
            continue
        while not STOP.is_set():
            try:
                body = json.dumps({"code": code}).encode("utf-8")
                request = urllib.request.Request(
                    SCANBASE_URL, data=body,
                    headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(request, timeout=5) as response:
                    response.read()
                print(f"Naar ScanBase gestuurd: {code}", flush=True)
                break
            except Exception as exc:
                print(f"ScanBase nog niet bereikbaar ({exc}); opnieuw proberen.", flush=True)
                STOP.wait(3)
        SCANS.task_done()


def read_scanner():
    interface = interface_dir = None
    fd = None
    detached = claimed = pending = False
    urb = buf = None
    try:
        interface, interface_dir, node, endpoint, packet_size = find_scanner()
        print(f"Scanner gevonden: {node}, endpoint 0x{endpoint:02x}", flush=True)
        fd = os.open(node, os.O_RDWR)
        driver = os.path.basename(os.path.realpath(os.path.join(interface_dir, "driver"))) \
            if os.path.exists(os.path.join(interface_dir, "driver")) else ""
        if driver == "usbhid":
            with open("/sys/bus/usb/drivers/usbhid/unbind", "w", encoding="ascii") as f:
                f.write(interface)
            detached = True
            time.sleep(0.2)
        elif driver:
            raise RuntimeError(f"Onverwachte scannerdriver: {driver}")

        interface_no = ctypes.c_uint(INTERFACE_NUMBER)
        ioctl_ptr(fd, IO_CLAIM, interface_no)
        claimed = True

        buf = ctypes.create_string_buffer(packet_size)
        urb = URB()
        urb.type = 1
        urb.endpoint = endpoint
        urb.buffer = ctypes.addressof(buf)
        urb.buffer_length = packet_size
        ioctl_ptr(fd, IO_SUBMIT, urb)
        pending = True
        with ACTIVE_LOCK:
            ACTIVE.update(fd=fd, urb=urb, pending=True)

        print("Scannerbrug luistert. Scan een barcode; suffix Tab/Enter wordt herkend.", flush=True)
        previous = set()
        code = ""
        while not STOP.is_set():
            done = ctypes.c_void_p()
            try:
                ioctl_ptr(fd, IO_REAP, done)
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                if STOP.is_set():
                    break
                raise
            pending = False
            with ACTIVE_LOCK:
                ACTIVE["pending"] = False
            if urb.status:
                raise OSError(-urb.status, f"USB-transferstatus {urb.status}")
            report = bytes(buf.raw[:urb.actual_length])
            if len(report) >= 8:
                shift = bool(report[0] & 0x22)
                keys = {k for k in report[2:8] if k}
                for k in keys - previous:
                    if k in (0x28, 0x2B, 0x58):
                        if code:
                            code = code.strip()
                            if code:
                                print(f"Barcode gelezen: {code}", flush=True)
                                SCANS.put(code)
                            code = ""
                    else:
                        code += key_text(k, shift)
                        if len(code) > 512:
                            code = ""
                previous = keys
            if STOP.is_set():
                break
            urb.status = 0
            urb.actual_length = 0
            ioctl_ptr(fd, IO_SUBMIT, urb)
            pending = True
            with ACTIVE_LOCK:
                ACTIVE["pending"] = True
    finally:
        if fd is not None and pending and urb is not None:
            try:
                ioctl_ptr(fd, IO_DISCARD, urb)
                done = ctypes.c_void_p()
                try:
                    ioctl_ptr(fd, IO_REAP_NDELAY, done)
                except OSError:
                    pass
            except OSError:
                pass
        if fd is not None and claimed:
            try:
                ioctl_ptr(fd, IO_RELEASE, ctypes.c_uint(INTERFACE_NUMBER))
            except OSError:
                pass
        with ACTIVE_LOCK:
            ACTIVE.update(fd=None, urb=None, pending=False)
        if fd is not None:
            os.close(fd)
        if detached and interface:
            try:
                with open("/sys/bus/usb/drivers/usbhid/bind", "w", encoding="ascii") as f:
                    f.write(interface)
                print("Scannerdriver opnieuw aangekoppeld.", flush=True)
            except OSError as exc:
                print(f"WAARSCHUWING: usbhid kon niet worden teruggekoppeld: {exc}", flush=True)
                print(f"Herstel: sudo sh -c 'echo {interface} > /sys/bus/usb/drivers/usbhid/bind'", flush=True)


def request_stop(signum, frame):
    STOP.set()
    with ACTIVE_LOCK:
        fd, urb, pending = ACTIVE["fd"], ACTIVE["urb"], ACTIVE["pending"]
        if fd is not None and urb is not None and pending:
            try:
                ioctl_ptr(fd, IO_DISCARD, urb)
            except OSError:
                pass


def main():
    if os.geteuid() != 0:
        raise SystemExit("Start deze scannerbrug als root via DSM Taakplanner.")
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    threading.Thread(target=post_scans, name="scanbase-http", daemon=True).start()
    ensure_hid_modules()
    while not STOP.is_set():
        try:
            read_scanner()
            if not STOP.is_set():
                print("Scannerverbinding gestopt; opnieuw proberen over 5 seconden.", flush=True)
        except Exception as exc:
            print(f"Scannerbrug: {type(exc).__name__}: {exc}; nieuwe poging over 5 seconden.", flush=True)
        STOP.wait(5)
    print("Scannerbrug gestopt.", flush=True)


if __name__ == "__main__":
    main()
