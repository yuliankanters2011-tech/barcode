#!/usr/bin/env python3
"""Small Synology inventory web app with a raw USB-HID scanner reader.

The USB reader uses Linux usbfs directly (ctypes + USBDEVFS URBs), so it has
no pip dependencies. It temporarily unbinds only the scanner's keyboard
interface and attempts to rebind it on shutdown.
"""

import base64
import binascii
import ctypes
import errno
from contextlib import contextmanager
import glob
import json
import os
import signal
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlencode, urlparse
from urllib.request import Request, urlopen

DB_PATH = os.environ.get("DB_PATH", "/data/scanbase.db")
PORT = int(os.environ.get("PORT", "8080"))
LOOKUP_VERSION = 4
USB_SYSFS = os.environ.get("USB_SYSFS_DEVICES", "/sys/bus/usb/devices")
USB_HID_DRIVER = os.environ.get("USB_HID_DRIVER_DIR", "/host-usbhid")
SCANNER_MODE = os.environ.get("SCANNER_MODE", "external").lower()
VID, PID = "5131", "2007"
INTERFACE_NUMBER = 0

# Linux ioctl encoding and USBDEVFS structures (DS218+ is x86_64).
_IOC_READ = 2
_IOC_WRITE = 1

def ioc(direction, kind, number, size):
    return (direction << 30) | (size << 16) | (ord(kind) << 8) | number


class UsbDevfsUrb(ctypes.Structure):
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
URB_SIZE = ctypes.sizeof(UsbDevfsUrb)
IO_SUBMIT = ioc(_IOC_READ, "U", 10, URB_SIZE)
IO_DISCARD = (ord("U") << 8) | 11
IO_REAP = ioc(_IOC_WRITE, "U", 12, ctypes.sizeof(ctypes.c_void_p))
IO_REAP_NDELAY = ioc(_IOC_WRITE, "U", 13, ctypes.sizeof(ctypes.c_void_p))
IO_CLAIM = ioc(_IOC_READ, "U", 15, ctypes.sizeof(ctypes.c_uint))
IO_RELEASE = ioc(_IOC_READ, "U", 16, ctypes.sizeof(ctypes.c_uint))

stop_event = threading.Event()
scanner_status = {"state": "starting", "message": "Scanner wordt gezocht"}
scanner_status_lock = threading.Lock()
scan_lock = threading.Lock()
scan_events = []
scan_counter = 0
usb_state_lock = threading.Lock()
usb_state = {"fd": None, "urb": None, "pending": False}


def set_scanner_status(state, message):
    with scanner_status_lock:
        scanner_status.update(state=state, message=message)


def ioctl_ptr(fd, request, obj):
    ctypes.set_errno(0)
    if libc.ioctl(fd, request, ctypes.byref(obj)) < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def text_file(path):
    with open(path, "r", encoding="ascii") as stream:
        return stream.read().strip()


def locate_scanner():
    for vendor_path in glob.glob(os.path.join(USB_SYSFS, "*", "idVendor")):
        device_dir = os.path.dirname(vendor_path)
        try:
            if text_file(vendor_path).lower() != VID:
                continue
            if text_file(os.path.join(device_dir, "idProduct")).lower() != PID:
                continue
            bus = int(text_file(os.path.join(device_dir, "busnum")))
            dev = int(text_file(os.path.join(device_dir, "devnum")))
            device_name = os.path.basename(device_dir)
            interface_name = f"{device_name}:1.{INTERFACE_NUMBER}"
            interface_dir = os.path.join(USB_SYSFS, interface_name)
            if not os.path.isdir(interface_dir):
                raise RuntimeError("USB interface 0 niet gevonden")
            endpoint = None
            packet_size = None
            for ep in glob.glob(os.path.join(interface_dir, "ep_*")):
                address = int(text_file(os.path.join(ep, "bEndpointAddress")), 16)
                attributes = int(text_file(os.path.join(ep, "bmAttributes")), 16)
                if address & 0x80 and (attributes & 0x03) == 0x03:
                    endpoint = address
                    packet_size = int(text_file(os.path.join(ep, "wMaxPacketSize")), 16) & 0x7ff
                    break
            if endpoint is None or not packet_size:
                raise RuntimeError("Interrupt-IN USB-endpoint ontbreekt")
            node = f"/dev/bus/usb/{bus:03d}/{dev:03d}"
            return device_name, interface_name, interface_dir, node, endpoint, packet_size
        except (OSError, ValueError):
            continue
    raise RuntimeError(f"Scanner USB-ID {VID}:{PID} niet gevonden")


# Standard USB HID keyboard usage mapping. HID usage 0x2B (Tab) is the
# suffix observed on this scanner; Enter and keypad Enter are also accepted.
def key_to_text(code, shift):
    if 0x04 <= code <= 0x1D:
        ch = chr(ord("a") + code - 0x04)
        return ch.upper() if shift else ch
    if 0x1E <= code <= 0x27:
        digits = "1234567890"
        shifted = "!@#$%^&*()"
        index = code - 0x1E
        return shifted[index] if shift else digits[index]
    if code == 0x2C:
        return " "
    punctuation = {
        0x2D: ("-", "_"), 0x2E: ("=", "+"), 0x2F: ("[", "{"),
        0x30: ("]", "}"), 0x31: ("\\", "|"), 0x33: (";", ":"),
        0x34: ("'", '"'), 0x35: ("`", "~"), 0x36: (",", "<"),
        0x37: (".", ">"), 0x38: ("/", "?"),
    }
    pair = punctuation.get(code)
    return pair[1 if shift else 0] if pair else ""


def record_scan(code):
    global scan_counter
    code = code.strip()
    if not code:
        return
    with ACTIVE_MODE_LOCK:
        mode = ACTIVE_SCAN_MODE
        stocktake_id = ACTIVE_STOCKTAKE_ID
    delta = 0
    with DB_LOCK, db_session() as conn:
        row = conn.execute("""SELECT i.* FROM items i LEFT JOIN item_barcodes b ON b.item_id=i.id
            WHERE i.barcode=? OR b.barcode=? LIMIT 1""", (code, code)).fetchone()
        item_id = row["id"] if row else None
        units = max(1,int(row["units_per_box"] or 1)) if row and row["box_barcode"] and row["box_barcode"]!=row["barcode"] and code==row["box_barcode"] else 1
        if item_id is not None and mode in ("receive","consume"):
            delta = units if mode=="receive" else -min(units,int(row["stock_count"]))
            if delta:
                conn.execute("UPDATE items SET stock_count=MAX(0,stock_count+?),updated_at=CURRENT_TIMESTAMP WHERE id=?",
                             (delta, item_id))
        if mode == "stocktake" and stocktake_id:
            if row:
                line = conn.execute("SELECT id FROM stocktake_lines WHERE stocktake_id=? AND item_id=? LIMIT 1",
                                    (stocktake_id, item_id)).fetchone()
                if line:
                    conn.execute("UPDATE stocktake_lines SET counted_count=counted_count+? WHERE id=?", (units,line["id"]))
                else:
                    conn.execute("""INSERT INTO stocktake_lines(stocktake_id,item_id,barcode,name_snapshot,expected_count,counted_count)
                        VALUES(?,?,?,?,?,?)""", (stocktake_id,item_id,code,row["name"],row["stock_count"],units))
            else:
                conn.execute("""INSERT INTO stocktake_lines(stocktake_id,item_id,barcode,name_snapshot,expected_count,counted_count)
                    VALUES(?,NULL,?,'Onbekende barcode',0,1)
                    ON CONFLICT(stocktake_id,barcode) DO UPDATE SET counted_count=counted_count+1""",
                    (stocktake_id, code))
        conn.execute("INSERT INTO scan_log(barcode,item_id,source,mode,delta) VALUES(?,?,?,?,?)",
                     (code,item_id,"scanner",mode,delta))
    with scan_lock:
        scan_counter += 1
        scan_events.append({"id": scan_counter, "code": code,
                            "time": datetime.now(timezone.utc).isoformat(), "mode": mode, "delta": delta})
        del scan_events[:-100]
    print(f"Scan ontvangen: {code}", flush=True)


def consume_hid_report(report, previous_keys, current_code):
    if len(report) < 8:
        return previous_keys, current_code
    modifiers = report[0]
    shift = bool(modifiers & 0x22)
    keys = {key for key in report[2:8] if key}
    for key in keys - previous_keys:
        if key in (0x28, 0x2B, 0x58):
            if current_code:
                record_scan(current_code)
            current_code = ""
        else:
            current_code += key_to_text(key, shift)
            if len(current_code) > 512:
                current_code = ""
    return keys, current_code


def scanner_worker():
    fd = None
    detached = False
    claimed = False
    urb_pending = False
    interface_name = None
    urb = None
    buf = None
    try:
        device_name, interface_name, interface_dir, node, endpoint, packet_size = locate_scanner()
        print(f"Scanner gevonden op {node}, endpoint 0x{endpoint:02x}", flush=True)
        fd = os.open(node, os.O_RDWR)

        unbind_path = os.path.join(USB_HID_DRIVER, "unbind")
        bind_path = os.path.join(USB_HID_DRIVER, "bind")
        driver_link = os.path.join(interface_dir, "driver")
        current_driver = os.path.basename(os.path.realpath(driver_link)) if os.path.exists(driver_link) else ""
        if current_driver == "usbhid":
            with open(unbind_path, "w", encoding="ascii") as stream:
                stream.write(interface_name)
            detached = True
            time.sleep(0.2)
        elif current_driver:
            raise RuntimeError(f"Interface gebruikt onverwachte driver: {current_driver}")

        interface = ctypes.c_uint(INTERFACE_NUMBER)
        ioctl_ptr(fd, IO_CLAIM, interface)
        claimed = True

        buf = ctypes.create_string_buffer(packet_size)
        urb = UsbDevfsUrb()
        urb.type = 1  # interrupt transfer
        urb.endpoint = endpoint
        urb.buffer = ctypes.addressof(buf)
        urb.buffer_length = packet_size
        ioctl_ptr(fd, IO_SUBMIT, urb)
        urb_pending = True
        with usb_state_lock:
            usb_state.update(fd=fd, urb=urb, pending=True)
        set_scanner_status("ready", "USB-scanner luistert")

        previous_keys = set()
        current_code = ""
        while not stop_event.is_set():
            completion = ctypes.c_void_p()
            try:
                ioctl_ptr(fd, IO_REAP, completion)
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                if stop_event.is_set():
                    break
                raise
            urb_pending = False
            with usb_state_lock:
                usb_state["pending"] = False
            if urb.status:
                raise OSError(-urb.status, f"USB-transferstatus {urb.status}")
            report = bytes(buf.raw[:urb.actual_length])
            previous_keys, current_code = consume_hid_report(report, previous_keys, current_code)
            if stop_event.is_set():
                break
            urb.status = 0
            urb.actual_length = 0
            ioctl_ptr(fd, IO_SUBMIT, urb)
            urb_pending = True
            with usb_state_lock:
                usb_state["pending"] = True

    except Exception as exc:
        set_scanner_status("error", str(exc))
        print(f"Scannerfout: {type(exc).__name__}: {exc}", flush=True)
    finally:
        if fd is not None and urb_pending and urb is not None:
            try:
                ioctl_ptr(fd, IO_DISCARD, urb)
                completion = ctypes.c_void_p()
                try:
                    ioctl_ptr(fd, IO_REAP_NDELAY, completion)
                except OSError:
                    pass
            except OSError:
                pass
        if fd is not None and claimed:
            try:
                interface = ctypes.c_uint(INTERFACE_NUMBER)
                ioctl_ptr(fd, IO_RELEASE, interface)
            except OSError:
                pass
        with usb_state_lock:
            usb_state.update(fd=None, urb=None, pending=False)
        if fd is not None:
            os.close(fd)
        if detached and interface_name:
            try:
                with open(os.path.join(USB_HID_DRIVER, "bind"), "w", encoding="ascii") as stream:
                    stream.write(interface_name)
                print("Scanner-driver opnieuw aangekoppeld", flush=True)
            except OSError as exc:
                set_scanner_status("error", f"Scanner-driver kon niet terug: {exc}")
                print(f"WAARSCHUWING: usbhid niet teruggekoppeld: {exc}", flush=True)
        if not stop_event.is_set() and scanner_status["state"] != "error":
            set_scanner_status("offline", "Scannerluisteraar gestopt")


def stop_usb_reader():
    stop_event.set()
    with usb_state_lock:
        fd = usb_state.get("fd")
        urb = usb_state.get("urb")
        pending = usb_state.get("pending")
        if fd is not None and urb is not None and pending:
            try:
                ioctl_ptr(fd, IO_DISCARD, urb)
            except OSError:
                pass


DB_LOCK = threading.Lock()
ACTIVE_MODE_LOCK = threading.Lock()
ACTIVE_SCAN_MODE = "normal"
ACTIVE_STOCKTAKE_ID = None


def db_connect():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_session():
    conn = db_connect()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db():
    global ACTIVE_SCAN_MODE, ACTIVE_STOCKTAKE_ID
    with db_session() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            barcode TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            location TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            stock_count INTEGER NOT NULL DEFAULT 1,
            min_stock INTEGER NOT NULL DEFAULT 0,
            is_favorite INTEGER NOT NULL DEFAULT 0,
            photo_path TEXT NOT NULL DEFAULT '',
            box_barcode TEXT NOT NULL DEFAULT '',
            units_per_box INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        item_columns = {row[1] for row in conn.execute("PRAGMA table_info(items)")}
        if "stock_count" not in item_columns:
            conn.execute("ALTER TABLE items ADD COLUMN stock_count INTEGER NOT NULL DEFAULT 1")
        if "min_stock" not in item_columns:
            conn.execute("ALTER TABLE items ADD COLUMN min_stock INTEGER NOT NULL DEFAULT 0")
        if "is_favorite" not in item_columns:
            conn.execute("ALTER TABLE items ADD COLUMN is_favorite INTEGER NOT NULL DEFAULT 0")
        if "photo_path" not in item_columns:
            conn.execute("ALTER TABLE items ADD COLUMN photo_path TEXT NOT NULL DEFAULT ''")
        if "box_barcode" not in item_columns:
            conn.execute("ALTER TABLE items ADD COLUMN box_barcode TEXT NOT NULL DEFAULT ''")
        if "units_per_box" not in item_columns:
            conn.execute("ALTER TABLE items ADD COLUMN units_per_box INTEGER NOT NULL DEFAULT 1")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_items_name ON items(name)")
        conn.execute("""CREATE TABLE IF NOT EXISTS item_barcodes (
            barcode TEXT PRIMARY KEY,
            item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_item_barcodes_item ON item_barcodes(item_id)")
        conn.execute("""CREATE TABLE IF NOT EXISTS scan_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            barcode TEXT NOT NULL,
            item_id INTEGER,
            source TEXT NOT NULL DEFAULT 'scanner',
            mode TEXT NOT NULL DEFAULT 'normal',
            delta INTEGER NOT NULL DEFAULT 0,
            undone INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS stocktakes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT 'Voorraadopname',
            status TEXT NOT NULL DEFAULT 'active',
            started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at TEXT,
            applied_at TEXT
        )""")
        stocktake_columns = {row[1] for row in conn.execute("PRAGMA table_info(stocktakes)")}
        if "applied_at" not in stocktake_columns:
            conn.execute("ALTER TABLE stocktakes ADD COLUMN applied_at TEXT")
        conn.execute("""CREATE TABLE IF NOT EXISTS stocktake_lines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stocktake_id INTEGER NOT NULL REFERENCES stocktakes(id) ON DELETE CASCADE,
            item_id INTEGER,
            barcode TEXT NOT NULL,
            name_snapshot TEXT NOT NULL DEFAULT '',
            expected_count INTEGER NOT NULL DEFAULT 0,
            counted_count INTEGER NOT NULL DEFAULT 0,
            UNIQUE(stocktake_id,barcode)
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_log_created ON scan_log(created_at DESC)")
        conn.execute("""CREATE TABLE IF NOT EXISTS catalog_cache (
            barcode TEXT PRIMARY KEY,
            found INTEGER NOT NULL DEFAULT 0,
            name TEXT NOT NULL DEFAULT '',
            brand TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT '',
            quantity TEXT NOT NULL DEFAULT '',
            image_url TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            source_url TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            offers_json TEXT NOT NULL DEFAULT '[]',
            lookup_version INTEGER NOT NULL DEFAULT 2,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        columns = {row[1] for row in conn.execute("PRAGMA table_info(catalog_cache)")}
        if "offers_json" not in columns:
            conn.execute("ALTER TABLE catalog_cache ADD COLUMN offers_json TEXT NOT NULL DEFAULT '[]'")
        if "lookup_version" not in columns:
            # Force a fresh lookup for old negative results after new providers are added.
            conn.execute("ALTER TABLE catalog_cache ADD COLUMN lookup_version INTEGER NOT NULL DEFAULT 1")
        active = conn.execute("SELECT id FROM stocktakes WHERE status='active' ORDER BY id DESC LIMIT 1").fetchone()
        ACTIVE_STOCKTAKE_ID = active["id"] if active else None
        ACTIVE_SCAN_MODE = "stocktake" if active else "normal"


def row_to_dict(row):
    return dict(row) if row is not None else None


def catalog_row_to_dict(row):
    item = row_to_dict(row)
    if item is not None:
        try:
            item["offers"] = json.loads(item.pop("offers_json", "[]") or "[]")
        except (ValueError, TypeError):
            item["offers"] = []
    return item


def item_to_dict(conn, row):
    item = row_to_dict(row)
    if item is not None:
        item["alternate_barcodes"] = [record[0] for record in conn.execute(
            "SELECT barcode FROM item_barcodes WHERE item_id=? ORDER BY barcode", (item["id"],))]
    return item


def get_item_by_barcode(code):
    with DB_LOCK, db_session() as conn:
        row = conn.execute("""SELECT i.* FROM items i
            LEFT JOIN item_barcodes b ON b.item_id=i.id
            WHERE i.barcode=? OR b.barcode=? LIMIT 1""", (code, code)).fetchone()
        return item_to_dict(conn, row)


def catalog_from_cache(barcode, max_age_hours=24):
    with DB_LOCK, db_session() as conn:
        row = conn.execute("SELECT * FROM catalog_cache WHERE barcode=?", (barcode,)).fetchone()
    if row is None:
        return None
    item = row_to_dict(row)
    if int(item.get("lookup_version", 1)) != LOOKUP_VERSION:
        return None
    try:
        stamp = datetime.strptime(item["updated_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        if (datetime.now(timezone.utc) - stamp).total_seconds() <= max_age_hours * 3600:
            item["cached"] = True
            try:
                item["offers"] = json.loads(item.pop("offers_json", "[]") or "[]")
            except (ValueError, TypeError):
                item["offers"] = []
            return item
    except (ValueError, TypeError):
        pass
    return None


def save_catalog_result(item):
    with DB_LOCK, db_session() as conn:
        conn.execute("""INSERT INTO catalog_cache
            (barcode, found, name, brand, category, quantity, image_url, source, source_url, description, offers_json, lookup_version)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(barcode) DO UPDATE SET found=excluded.found, name=excluded.name,
            brand=excluded.brand, category=excluded.category, quantity=excluded.quantity,
            image_url=excluded.image_url, source=excluded.source, source_url=excluded.source_url,
            description=excluded.description, offers_json=excluded.offers_json,
            lookup_version=excluded.lookup_version, updated_at=CURRENT_TIMESTAMP""",
            (item["barcode"], int(item["found"]), item.get("name", ""), item.get("brand", ""),
             item.get("category", ""), item.get("quantity", ""), item.get("image_url", ""),
             item.get("source", ""), item.get("source_url", ""), item.get("description", ""),
             json.dumps(item.get("offers", []), ensure_ascii=False), LOOKUP_VERSION))


def fetch_fact_product(base, barcode, source_name):
    fields = "code,product_name,product_name_en,generic_name,brands,categories,quantity,image_url,image_front_url,url"
    url = f"{base}/api/v2/product/{quote(barcode, safe='')}.json?{urlencode({'fields': fields})}"
    request = Request(url, headers={"User-Agent": "ScanBase/1.2 (barcode inventory; read-only lookup)"})
    with urlopen(request, timeout=5) as response:
        payload = json.loads(response.read(1_000_000).decode("utf-8"))
    if payload.get("status") != 1:
        return None
    product = payload.get("product") or {}
    name = (product.get("product_name") or product.get("product_name_en") or
            product.get("generic_name") or "").strip()
    if not name:
        return None
    return {
        "barcode": barcode, "found": True, "name": name,
        "brand": product.get("brands", ""), "category": product.get("categories", ""),
        "quantity": product.get("quantity", ""),
        "image_url": product.get("image_url") or product.get("image_front_url", ""),
        "source": source_name,
        "source_url": product.get("url") or f"{base}/product/{quote(barcode, safe='')}",
        "description": product.get("generic_name", ""),
    }


def fetch_gtinsearch_product(barcode):
    """Try the free, open GTIN Search/Datakick catalogue; coverage is community-supplied."""
    url = "https://www.gtinsearch.org/api/items/" + quote(barcode, safe="")
    request = Request(url, headers={"Accept": "application/json",
                                    "User-Agent": "ScanBase/1.6 (open barcode lookup)"})
    with urlopen(request, timeout=5) as response:
        payload = json.loads(response.read(1_000_000).decode("utf-8"))
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict):
        records = payload.get("items") or [payload]
    else:
        return None
    for product in records:
        if not isinstance(product, dict):
            continue
        name = str(product.get("name") or product.get("product_name") or product.get("title") or "").strip()
        if not name:
            continue
        returned_code = str(product.get("gtin") or product.get("gtin14") or product.get("ean") or
                            product.get("upc") or product.get("barcode") or "").strip()
        if returned_code and returned_code != barcode and returned_code.lstrip("0") != barcode.lstrip("0"):
            continue
        brand = product.get("brand_name") or product.get("brand") or product.get("manufacturer") or ""
        size = product.get("size") or product.get("quantity") or ""
        category = product.get("category") or product.get("categories") or ""
        description = product.get("description") or product.get("ingredients") or ""
        image = product.get("image_url") or product.get("image") or ""
        return {"barcode": barcode, "found": True, "name": name, "brand": brand,
                "category": category, "quantity": size, "image_url": image,
                "source": "GTIN Search (open productdata)",
                "source_url": f"https://gtinsearch.org/api/items/{quote(barcode, safe='')}",
                "description": str(description)[:4000], "offers": []}
    return None


def fetch_upcitemdb(barcode):
    # Free Explorer API: no key required, with a published daily request limit.
    url = "https://api.upcitemdb.com/prod/trial/lookup?" + urlencode({"upc": barcode})
    request = Request(url, headers={"Accept": "application/json",
                                    "User-Agent": "ScanBase/1.3 barcode inventory"})
    with urlopen(request, timeout=6) as response:
        payload = json.loads(response.read(1_000_000).decode("utf-8"))
    products = payload.get("items") or []
    if not products:
        return None
    product = products[0]
    title = (product.get("title") or "").strip()
    if not title:
        return None
    offers = []
    for offer in product.get("offers", [])[:8]:
        if not offer.get("link"):
            continue
        offers.append({
            "merchant": offer.get("merchant") or offer.get("domain") or "Winkel",
            "price": offer.get("price", ""),
            "currency": offer.get("currency", ""),
            "shipping": offer.get("shipping", ""),
            "availability": offer.get("availability", ""),
            "link": offer.get("link", ""),
            "updated_t": offer.get("updated_t", ""),
        })
    images = product.get("images") or []
    return {
        "barcode": barcode, "found": True, "name": title,
        "brand": product.get("brand", ""), "category": product.get("category", ""),
        "quantity": product.get("size") or product.get("dimension", ""),
        "image_url": images[0] if images else "", "source": "UPCitemdb",
        "source_url": f"https://www.upcitemdb.com/upc/{quote(barcode, safe='')}",
        "description": product.get("description", ""), "offers": offers,
    }


MUSICBRAINZ_REQUEST_LOCK = threading.Lock()
MUSICBRAINZ_LAST_REQUEST = 0.0


def fetch_upcmdb_movie(barcode):
    """Exact UPC/EAN lookup for DVD, Blu-ray and 4K home-media editions."""
    url = "https://upcmdb.com/v1/demo/lookup/" + quote(barcode, safe="")
    request = Request(url, headers={"Accept": "application/json",
                                    "User-Agent": "ScanBase/1.4 barcode inventory"})
    with urlopen(request, timeout=7) as response:
        product = json.loads(response.read(1_000_000).decode("utf-8"))
    title = (product.get("title") or "").strip()
    if not title or str(product.get("upc") or product.get("ean") or "") not in (barcode, "0" + barcode):
        return None
    year = product.get("year") or product.get("omdbYear") or ""
    format_name = product.get("format", "")
    category = "DVD / Blu-ray"
    if "4k" in str(format_name).lower():
        category = "4K UHD-film"
    elif "blu" in str(format_name).lower():
        category = "Blu-ray-film"
    elif "dvd" in str(format_name).lower():
        category = "DVD-film"
    display_name = f"{title} ({year})" if year else title
    details = [value for value in (format_name, product.get("publisher", ""),
                                   product.get("runtime", "") + " min" if product.get("runtime") else "",
                                   product.get("genre", ""), product.get("resolution", ""),
                                   product.get("subtitles", ""), product.get("plot", "")) if value]
    imdb_id = product.get("imdbID", "")
    return {
        "barcode": barcode, "found": True, "name": display_name,
        "brand": product.get("director", ""), "category": category,
        "quantity": format_name, "image_url": product.get("productImageUrl", ""),
        "source": "UPCMDB", "source_url": f"https://www.imdb.com/title/{quote(imdb_id, safe='')}" if imdb_id else "https://upcmdb.com/demo",
        "description": " · ".join(details)[:4000], "offers": [],
    }


def fetch_musicbrainz_release(barcode):
    """Find a music CD by its printed barcode in MusicBrainz."""
    global MUSICBRAINZ_LAST_REQUEST
    # MusicBrainz requests clients to stay at or below one request per second/IP.
    with MUSICBRAINZ_REQUEST_LOCK:
        delay = 1.1 - (time.monotonic() - MUSICBRAINZ_LAST_REQUEST)
        if delay > 0:
            time.sleep(delay)
        MUSICBRAINZ_LAST_REQUEST = time.monotonic()
    query = urlencode({"query": f"barcode:{barcode}", "fmt": "json", "limit": "5"})
    request = Request(
        "https://musicbrainz.org/ws/2/release/?" + query,
        headers={"Accept": "application/json",
                 "User-Agent": "ScanBase/1.4 (https://github.com/ykdigital)"})
    with urlopen(request, timeout=8) as response:
        payload = json.loads(response.read(1_000_000).decode("utf-8"))
    releases = payload.get("releases") or []
    # Prefer exact matches; do not accidentally identify a neighboring edition.
    release = next((r for r in releases if str(r.get("barcode", "")) == barcode), None)
    if not release:
        return None
    artists = "".join((part.get("name", "") + (part.get("joinphrase", "") or ""))
                      for part in release.get("artist-credit", []) if isinstance(part, dict))
    labels = ", ".join(info.get("label", {}).get("name", "")
                       for info in release.get("label-info", []) if info.get("label", {}).get("name"))
    details = [value for value in (release.get("date", ""), labels,
                                   release.get("country", "")) if value]
    title = release.get("title", "").strip()
    if not title:
        return None
    return {
        "barcode": barcode, "found": True, "name": title,
        "brand": artists, "category": "Muziek-cd", "quantity": "",
        "image_url": "", "source": "MusicBrainz",
        "source_url": f"https://musicbrainz.org/release/{quote(release.get('id', ''), safe='')}",
        "description": " · ".join(details), "offers": [],
    }


def fetch_google_book(barcode):
    """Look up ISBN-10 and ISBN-13 equivalents, useful for older school editions."""
    candidates = isbn_lookup_candidates(barcode)
    last_error = None
    for candidate in candidates:
        query = urlencode({"q": "isbn:" + candidate, "maxResults": "5"})
        request = Request("https://www.googleapis.com/books/v1/volumes?" + query,
                          headers={"Accept": "application/json",
                                   "User-Agent": "ScanBase/1.6 barcode inventory"})
        try:
            with urlopen(request, timeout=7) as response:
                payload = json.loads(response.read(1_000_000).decode("utf-8"))
        except Exception as exc:
            last_error = exc
            continue
        for result in payload.get("items", []):
            info = result.get("volumeInfo") or {}
            identifiers = {str(identifier.get("identifier", "")).replace("-", "")
                           for identifier in info.get("industryIdentifiers", [])}
            if not set(candidates).intersection(identifiers) or not info.get("title"):
                continue
            authors = ", ".join(info.get("authors", []))
            categories = ", ".join(info.get("categories", []))
            details = [value for value in (info.get("publisher", ""),
                                           info.get("publishedDate", ""),
                                           f"{info['pageCount']} pagina's" if info.get("pageCount") else "",
                                           categories) if value]
            image_links = info.get("imageLinks") or {}
            return {
                "barcode": barcode, "found": True, "name": info["title"],
                "brand": authors, "category": categories or "Boek / ISBN",
                "quantity": "", "image_url": image_links.get("thumbnail", "").replace("http://", "https://"),
                "source": "Google Books",
                "source_url": info.get("infoLink") or f"https://books.google.com/books?vid=ISBN{quote(barcode, safe='')}",
                "description": (info.get("description", "") or "")[:4000] or " · ".join(details),
                "offers": [],
            }
    if last_error:
        raise last_error
    return None


def isbn10_from_isbn13(value):
    """Return a valid ISBN-10 equivalent for a 978 ISBN-13, if possible."""
    if len(value) != 13 or not value.startswith("978") or not value.isdigit():
        return ""
    checksum13 = sum(int(digit) * (1 if index % 2 == 0 else 3)
                     for index, digit in enumerate(value[:12]))
    if (10 - checksum13 % 10) % 10 != int(value[12]):
        return ""
    body = value[3:12]
    checksum10 = sum(int(digit) * (10 - index) for index, digit in enumerate(body))
    remainder = (11 - checksum10 % 11) % 11
    return body + ("X" if remainder == 10 else str(remainder))


def isbn13_from_isbn10(value):
    """Return the equivalent 978 ISBN-13 when a valid ISBN-10 is scanned."""
    if (len(value) != 10 or not value[:9].isdigit() or value[-1] not in "0123456789X"
            or set(value) == {"0"}):
        return ""
    values = [int(digit) for digit in value[:9]]
    check10 = 10 if value[-1] == "X" else int(value[-1])
    if (sum(digit * (10 - index) for index, digit in enumerate(values)) + check10) % 11 != 0:
        return ""
    body = "978" + value[:9]
    checksum = sum(int(digit) * (1 if index % 2 == 0 else 3) for index, digit in enumerate(body))
    return body + str((10 - checksum % 10) % 10)


def isbn_lookup_candidates(barcode):
    """Return validated ISBN barcode plus its compatible ISBN-10/13 equivalent."""
    if len(barcode) == 13 and barcode.startswith(("978", "979")) and barcode.isdigit():
        checksum = sum(int(digit) * (1 if index % 2 == 0 else 3)
                       for index, digit in enumerate(barcode[:12]))
        if (10 - checksum % 10) % 10 != int(barcode[12]):
            return []
        equivalent = isbn10_from_isbn13(barcode)
    elif len(barcode) == 10:
        equivalent = isbn13_from_isbn10(barcode)
        if not equivalent:
            return []
    else:
        return []
    candidates = [barcode]
    if equivalent:
        candidates.append(equivalent)
    return candidates


def fetch_kb_nbt_book(isbn13):
    """Search the Dutch KB National Bibliography (NBT), no API key required."""
    if not (isbn13.startswith("97890") or isbn13.startswith("97894")):
        return None
    values = [isbn13]
    isbn10 = isbn10_from_isbn13(isbn13)
    if isbn10:
        values.append(isbn10)
    isbn_values = " ".join(json.dumps(value) for value in values)
    query = f"""PREFIX schema: <http://schema.org/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX dct: <http://purl.org/dc/terms#>
SELECT ?book ?title ?author ?year ?language ?pages ?publication ?isbn
WHERE {{
  VALUES ?isbn {{ {isbn_values} }}
  ?book schema:isbn ?isbn ; schema:name ?title .
  OPTIONAL {{ ?book schema:author ?authorId . ?authorId rdfs:label ?author . }}
  OPTIONAL {{ ?book dct:issued ?year . }}
  OPTIONAL {{ ?book schema:inLanguage ?language . }}
  OPTIONAL {{ ?book schema:numberOfPages ?pages . }}
  OPTIONAL {{ ?book schema:publication ?publicationId . ?publicationId rdfs:label ?publication . }}
}}"""
    url = "https://data.bibliotheken.nl/sparql?" + urlencode({"query": query})
    request = Request(url, headers={"Accept": "application/sparql-results+json",
                                    "User-Agent": "ScanBase/1.5 (Dutch barcode inventory)"})
    with urlopen(request, timeout=9) as response:
        payload = json.loads(response.read(1_000_000).decode("utf-8"))
    bindings = payload.get("results", {}).get("bindings", [])
    # Prefer an exact ISBN-13 record; some older national records only store ISBN-10.
    bindings.sort(key=lambda row: row.get("isbn", {}).get("value") != isbn13)
    for row in bindings:
        def value(key):
            return (row.get(key) or {}).get("value", "").strip()
        title = value("title")
        if not title:
            continue
        author = value("author")
        publication = value("publication")
        year = value("year")
        pages = value("pages")
        language = value("language")
        details = [value for value in (
            publication, (year if year and year not in publication else ""),
            f"{pages} pagina's" if pages else "", f"Taal: {language}" if language else "") if value]
        source_url = value("book").replace("http://", "https://", 1)
        return {
            "barcode": isbn13, "found": True, "name": title,
            "brand": author, "category": "Boek · KB/Nederlandse bibliografie",
            "quantity": "", "image_url": "", "source": "KB/NBT",
            "source_url": source_url or "https://data.bibliotheken.nl/sparql",
            "description": " · ".join(details), "offers": [],
        }
    return None


def lookup_online(barcode, use_cache=True):
    barcode = str(barcode).strip()
    if use_cache:
        cached = catalog_from_cache(barcode)
        if cached is not None:
            return cached

    errors = []
    isbn_codes = isbn_lookup_candidates(barcode)
    isbn13 = next((value for value in isbn_codes if len(value) == 13), "")
    # Prefer the national source for Dutch ISBNs; this also catches scanned ISBN-10 codes.
    if isbn13.startswith(("97890", "97894")):
        try:
            item = fetch_kb_nbt_book(isbn13)
            if item:
                item["barcode"] = barcode
                save_catalog_result(item)
                return item
        except Exception as exc:
            errors.append(f"KB/NBT: {type(exc).__name__}")

    movie_lookup_attempted = False
    try:
        item = fetch_upcitemdb(barcode)
        if item:
            category_text = str(item.get("category", "")).lower()
            if any(word in category_text for word in ("dvd", "blu-ray", "movie", "film", "video")):
                movie_lookup_attempted = True
                try:
                    movie = fetch_upcmdb_movie(barcode)
                    if movie:
                        save_catalog_result(movie)
                        return movie
                except Exception as exc:
                    errors.append(f"UPCMDB: {type(exc).__name__}")
            save_catalog_result(item)
            return item
    except Exception as exc:
        errors.append(f"UPCitemdb: {type(exc).__name__}")

    # A separate physical-media catalogue has exact lookups for DVD/Blu-ray UPCs.
    # The public demo route requires no API key; only standard UPC/EAN lengths are tried.
    if not movie_lookup_attempted and barcode.isdigit() and len(barcode) in (12, 13):
        try:
            movie = fetch_upcmdb_movie(barcode)
            if movie:
                save_catalog_result(movie)
                return movie
        except Exception as exc:
            errors.append(f"UPCMDB: {type(exc).__name__}")

    # Try specialist open barcode catalogues; not every barcode is indexed.
    sources = [
        ("Open Food Facts", "https://world.openfoodfacts.org"),
        ("Open Products Facts", "https://world.openproductsfacts.org"),
        ("Open Beauty Facts", "https://world.openbeautyfacts.org"),
        ("Open Pet Food Facts", "https://world.openpetfoodfacts.org"),
    ]
    for source_name, base in sources:
        try:
            item = fetch_fact_product(base, barcode, source_name)
            if item:
                save_catalog_result(item)
                return item
        except Exception as exc:
            errors.append(f"{source_name}: {type(exc).__name__}")

    # Free open GTIN catalogue fallback can add non-food and retail products.
    try:
        item = fetch_gtinsearch_product(barcode)
        if item:
            save_catalog_result(item)
            return item
    except Exception as exc:
        errors.append(f"GTIN Search: {type(exc).__name__}")

    # MusicBrainz is a specialist barcode source for CD editions, not ISBNs.
    if barcode.isdigit() and 8 <= len(barcode) <= 14 and not isbn_codes:
        try:
            item = fetch_musicbrainz_release(barcode)
            if item:
                save_catalog_result(item)
                return item
        except Exception as exc:
            errors.append(f"MusicBrainz: {type(exc).__name__}")

    # Google Books and Open Library now also try the ISBN-10/13 equivalent;
    # exact identifier matching avoids confusing different editions.
    if isbn_codes:
        try:
            item = fetch_google_book(barcode)
            if item:
                save_catalog_result(item)
                return item
        except Exception as exc:
            errors.append(f"Google Books: {type(exc).__name__}")

        try:
            bibkeys = ",".join("ISBN:" + candidate for candidate in isbn_codes)
            url = "https://openlibrary.org/api/books?" + urlencode({
                "bibkeys": bibkeys, "format": "json", "jscmd": "data"})
            request = Request(url, headers={"User-Agent": "ScanBase/1.6 (barcode inventory; read-only lookup)"})
            with urlopen(request, timeout=5) as response:
                payload = json.loads(response.read(1_000_000).decode("utf-8"))
            book = next((payload.get("ISBN:" + candidate) for candidate in isbn_codes
                         if payload.get("ISBN:" + candidate, {}).get("title")), None)
            if book and book.get("title"):
                authors = ", ".join(a.get("name", "") for a in book.get("authors", []) if a.get("name"))
                item = {"barcode": barcode, "found": True, "name": book["title"],
                        "brand": authors, "category": "Boek", "quantity": "",
                        "image_url": (book.get("cover") or {}).get("medium", ""),
                        "source": "Open Library", "source_url": f"https://openlibrary.org/isbn/{quote(barcode, safe='')}",
                        "description": book.get("publish_date", "")}
                save_catalog_result(item)
                return item
        except Exception as exc:
            errors.append(f"Open Library: {type(exc).__name__}")

    item = {"barcode": barcode, "found": False, "name": "", "brand": "", "category": "",
            "quantity": "", "image_url": "", "source": "", "source_url": "",
            "description": "", "lookup_error": "; ".join(errors)}
    save_catalog_result(item)
    return item


def recent_catalog_items(limit=50):
    with DB_LOCK, db_session() as conn:
        rows = conn.execute("SELECT * FROM catalog_cache WHERE lookup_version=? ORDER BY updated_at DESC, rowid DESC LIMIT ?", (LOOKUP_VERSION, limit)).fetchall()
    return [catalog_row_to_dict(row) for row in rows]


def search_catalog_cache(query, limit=50):
    like = f"%{query}%"
    with DB_LOCK, db_session() as conn:
        rows = conn.execute("""SELECT * FROM catalog_cache WHERE lookup_version=? AND
            (barcode LIKE ? OR name LIKE ? OR brand LIKE ? OR category LIKE ?)
            ORDER BY updated_at DESC, rowid DESC LIMIT ?""",
            (LOOKUP_VERSION, like, like, like, like, limit)).fetchall()
    return [catalog_row_to_dict(row) for row in rows]


def inventory_locations():
    with DB_LOCK, db_session() as conn:
        rows = conn.execute("""SELECT DISTINCT location FROM items
            WHERE TRIM(location) != '' ORDER BY location COLLATE NOCASE""").fetchall()
    return [row[0] for row in rows]


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "ScanBase/1.0"

    def log_message(self, fmt, *args):
        print("HTTP:", fmt % args, flush=True)

    def send_json(self, value, status=200):
        body = json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size > 2_000_000:
            raise ValueError("Aanvraag te groot (maximaal 2 MB)")
        raw = self.rfile.read(size)
        return json.loads(raw or b"{}")

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == "/":
            body = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/status":
            with scanner_status_lock:
                status = dict(scanner_status)
            self.send_json({"scanner": status})
            return
        if parsed.path == "/api/scans":
            try:
                after = int(params.get("after", ["0"])[0])
            except ValueError:
                after = 0
            with scan_lock:
                events = [event for event in scan_events if event["id"] > after]
            self.send_json({"scans": events})
            return
        if parsed.path == "/api/scan-mode":
            with ACTIVE_MODE_LOCK:
                self.send_json({"mode": ACTIVE_SCAN_MODE, "stocktake_id": ACTIVE_STOCKTAKE_ID})
            return
        if parsed.path == "/api/history":
            try:
                limit = min(500, max(1, int(params.get("limit", ["100"])[0])))
                offset = max(0, int(params.get("offset", ["0"])[0]))
            except ValueError:
                limit, offset = 100, 0
            with DB_LOCK, db_session() as conn:
                rows = conn.execute("""SELECT l.*,i.name FROM scan_log l LEFT JOIN items i ON i.id=l.item_id
                    ORDER BY l.id DESC LIMIT ? OFFSET ?""", (limit,offset)).fetchall()
            self.send_json({"events": [row_to_dict(row) for row in rows]})
            return
        if parsed.path == "/api/stocktake":
            with DB_LOCK, db_session() as conn:
                row = conn.execute("SELECT * FROM stocktakes ORDER BY id DESC LIMIT 1").fetchone()
                info = row_to_dict(row)
                if info:
                    info["line_count"] = conn.execute("SELECT COUNT(*) FROM stocktake_lines WHERE stocktake_id=?", (info["id"],)).fetchone()[0]
                    info["differences"] = conn.execute("SELECT COUNT(*) FROM stocktake_lines WHERE stocktake_id=? AND counted_count<>expected_count", (info["id"],)).fetchone()[0]
            self.send_json({"stocktake": info})
            return
        if parsed.path == "/api/stocktake/lines":
            try:
                stocktake_id = int(params.get("id", [""])[0])
            except ValueError:
                stocktake_id = None
            with DB_LOCK, db_session() as conn:
                if not stocktake_id:
                    active = conn.execute("SELECT id FROM stocktakes ORDER BY id DESC LIMIT 1").fetchone()
                    stocktake_id = active[0] if active else None
                rows = conn.execute("""SELECT * FROM stocktake_lines WHERE stocktake_id=?
                    ORDER BY name_snapshot COLLATE NOCASE,barcode""", (stocktake_id,)).fetchall() if stocktake_id else []
            self.send_json({"lines": [row_to_dict(row) for row in rows], "stocktake_id": stocktake_id})
            return
        if parsed.path == "/api/photo":
            try:
                item_id = int(params.get("id", [""])[0])
            except ValueError:
                self.send_json({"error": "Ongeldig ID"}, 400); return
            with DB_LOCK, db_session() as conn:
                row = conn.execute("SELECT photo_path FROM items WHERE id=?", (item_id,)).fetchone()
            if not row or not row["photo_path"]:
                self.send_json({"photo": ""}); return
            path = os.path.join(os.path.dirname(DB_PATH) or ".", "photos", os.path.basename(row["photo_path"]))
            try:
                with open(path, "rb") as image:
                    raw = image.read(3_000_001)
                mime="image/png" if row["photo_path"].lower().endswith(".png") else "image/jpeg"
                self.send_json({"photo": f"data:{mime};base64," + base64.b64encode(raw).decode("ascii")})
            except OSError:
                self.send_json({"photo": ""})
            return
        if parsed.path == "/api/items":
            with DB_LOCK, db_session() as conn:
                rows = conn.execute("SELECT * FROM items ORDER BY name COLLATE NOCASE").fetchall()
                items = [item_to_dict(conn, row) for row in rows]
            self.send_json({"items": items})
            return
        if parsed.path == "/api/search":
            q = params.get("q", [""])[0].strip()
            if not q:
                self.send_json({"items": []})
                return
            like = f"%{q}%"
            with DB_LOCK, db_session() as conn:
                rows = conn.execute("""SELECT * FROM items i
                    WHERE barcode LIKE ? OR name LIKE ? OR location LIKE ? OR notes LIKE ?
                    OR EXISTS(SELECT 1 FROM item_barcodes b WHERE b.item_id=i.id AND b.barcode LIKE ?)
                    ORDER BY name COLLATE NOCASE LIMIT 60""", (like, like, like, like, like)).fetchall()
                items = [item_to_dict(conn, row) for row in rows]
            self.send_json({"items": items})
            return
        if parsed.path == "/api/item":
            try:
                item_id = int(params.get("id", [""])[0])
            except ValueError:
                self.send_json({"error": "Ongeldig ID"}, 400)
                return
            with DB_LOCK, db_session() as conn:
                row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
                item = item_to_dict(conn, row)
            if item is None:
                self.send_json({"error": "Niet gevonden"}, 404)
            else:
                self.send_json({"item": item})
            return
        if parsed.path == "/api/by-barcode":
            code = params.get("code", [""])[0]
            self.send_json({"item": get_item_by_barcode(code)})
            return
        if parsed.path == "/api/lookup":
            code = params.get("barcode", [""])[0].strip()
            if not code or len(code) > 64:
                self.send_json({"error": "Voer een geldige barcode in"}, 400)
                return
            item = lookup_online(code, use_cache=params.get("refresh", [""])[0] != "1")
            self.send_json({"item": item, "existing_item": get_item_by_barcode(code),
                            "locations": inventory_locations()})
            return
        if parsed.path == "/api/locations":
            self.send_json({"locations": inventory_locations()})
            return
        if parsed.path == "/api/catalog/recent":
            self.send_json({"items": recent_catalog_items()})
            return
        if parsed.path == "/api/catalog/search":
            query = params.get("q", [""])[0].strip()
            if not query:
                self.send_json({"items": recent_catalog_items()})
            else:
                self.send_json({"items": search_catalog_cache(query)})
            return
        self.send_json({"error": "Niet gevonden"}, 404)

    def do_POST(self):
        global ACTIVE_SCAN_MODE, ACTIVE_STOCKTAKE_ID
        parsed = urlparse(self.path)
        try:
            data = self.read_json()
        except Exception as exc:
            self.send_json({"error": str(exc)}, 400)
            return
        if parsed.path == "/api/ingest":
            code = str(data.get("code", "")).strip()
            if not code or len(code) > 512:
                self.send_json({"error": "Ongeldige barcode"}, 400)
                return
            record_scan(code)
            set_scanner_status("ready", "Scans ontvangen via NAS-brug")
            self.send_json({"ok": True})
            return
        if parsed.path == "/api/scan-mode":
            mode = str(data.get("mode", "normal"))
            if mode not in ("normal", "receive", "consume", "stocktake"):
                self.send_json({"error": "Onbekende scanmodus"}, 400); return
            with ACTIVE_MODE_LOCK:
                if mode == "stocktake" and not ACTIVE_STOCKTAKE_ID:
                    self.send_json({"error": "Start eerst een voorraadopname"}, 409); return
                ACTIVE_SCAN_MODE = mode
            self.send_json({"mode": mode, "stocktake_id": ACTIVE_STOCKTAKE_ID})
            return
        if parsed.path == "/api/stocktake":
            action = str(data.get("action", ""))
            if action == "start":
                name = str(data.get("name", "Voorraadopname")).strip()[:200] or "Voorraadopname"
                with ACTIVE_MODE_LOCK:
                    if ACTIVE_STOCKTAKE_ID:
                        self.send_json({"error": "Er loopt al een voorraadopname"}, 409); return
                    with DB_LOCK, db_session() as conn:
                        cursor = conn.execute("INSERT INTO stocktakes(name,status) VALUES(?,'active')", (name,))
                        stocktake_id = cursor.lastrowid
                        conn.execute("""INSERT INTO stocktake_lines(stocktake_id,item_id,barcode,name_snapshot,expected_count,counted_count)
                            SELECT ?,id,barcode,name,stock_count,0 FROM items""", (stocktake_id,))
                    ACTIVE_STOCKTAKE_ID = stocktake_id
                    ACTIVE_SCAN_MODE = "stocktake"
                self.send_json({"ok": True, "stocktake_id": stocktake_id})
                return
            if action == "finish":
                with ACTIVE_MODE_LOCK:
                    stocktake_id = ACTIVE_STOCKTAKE_ID
                    if not stocktake_id:
                        self.send_json({"error": "Er is geen actieve voorraadopname"}, 409); return
                    with DB_LOCK, db_session() as conn:
                        conn.execute("UPDATE stocktakes SET status='completed',completed_at=CURRENT_TIMESTAMP WHERE id=?", (stocktake_id,))
                    ACTIVE_STOCKTAKE_ID = None
                    ACTIVE_SCAN_MODE = "normal"
                self.send_json({"ok": True, "stocktake_id": stocktake_id})
                return
            if action == "apply":
                try:
                    stocktake_id = int(data.get("stocktake_id"))
                    with DB_LOCK, db_session() as conn:
                        session = conn.execute("SELECT status FROM stocktakes WHERE id=?", (stocktake_id,)).fetchone()
                        if not session: raise ValueError("Voorraadopname niet gevonden")
                        lines = conn.execute("SELECT item_id,barcode,counted_count,expected_count FROM stocktake_lines WHERE stocktake_id=?", (stocktake_id,)).fetchall()
                        updated = 0
                        for line in lines:
                            if line["item_id"] is not None and line["counted_count"] != line["expected_count"]:
                                conn.execute("UPDATE items SET stock_count=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (line["counted_count"],line["item_id"]))
                                conn.execute("INSERT INTO scan_log(barcode,item_id,source,mode,delta) VALUES(?,?, 'stocktake','stocktake_apply',?)",
                                             (line["barcode"],line["item_id"],line["counted_count"]-line["expected_count"]))
                                updated += 1
                        conn.execute("UPDATE stocktakes SET applied_at=CURRENT_TIMESTAMP WHERE id=?", (stocktake_id,))
                    self.send_json({"ok": True, "updated": updated})
                except (TypeError,ValueError) as exc:
                    self.send_json({"error": str(exc)}, 400)
                return
            self.send_json({"error": "Actie moet start, finish of apply zijn"}, 400)
            return
        if parsed.path == "/api/stocktake/count":
            try:
                line_id = int(data.get("line_id")); count = int(data.get("count"))
                if count < 0: raise ValueError("Geteld aantal mag niet negatief zijn")
                with DB_LOCK, db_session() as conn:
                    cursor = conn.execute("UPDATE stocktake_lines SET counted_count=? WHERE id=?", (count,line_id))
                if not cursor.rowcount: self.send_json({"error": "Regel niet gevonden"}, 404)
                else: self.send_json({"ok": True})
            except (TypeError, ValueError) as exc:
                self.send_json({"error": str(exc)}, 400)
            return
        if parsed.path == "/api/undo-last":
            with DB_LOCK, db_session() as conn:
                event = conn.execute("SELECT * FROM scan_log WHERE delta<>0 AND undone=0 AND mode IN ('receive','consume') ORDER BY id DESC LIMIT 1").fetchone()
                if not event:
                    self.send_json({"error": "Geen voorraadscan om ongedaan te maken"}, 404); return
                if event["item_id"] is not None:
                    conn.execute("UPDATE items SET stock_count=MAX(0,stock_count-?),updated_at=CURRENT_TIMESTAMP WHERE id=?",
                                 (event["delta"],event["item_id"]))
                conn.execute("UPDATE scan_log SET undone=1 WHERE id=?", (event["id"],))
                conn.execute("INSERT INTO scan_log(barcode,item_id,source,mode,delta) VALUES(?,?,?,?,?)",
                             (event["barcode"],event["item_id"],"undo","undo",-event["delta"]))
            self.send_json({"ok": True, "barcode": event["barcode"]})
            return
        if parsed.path == "/api/box-settings":
            try:
                item_id=int(data.get("id")); code=str(data.get("box_barcode", "")).strip()[:64]
                units=int(data.get("units_per_box",1))
                if units<1 or units>100000: raise ValueError("Doosinhoud moet tussen 1 en 100.000 liggen")
                with DB_LOCK, db_session() as conn:
                    item=conn.execute("SELECT * FROM items WHERE id=?",(item_id,)).fetchone()
                    if not item: raise ValueError("Artikel niet gevonden")
                    if code and code != item["barcode"]:
                        owner=conn.execute("""SELECT id FROM items WHERE barcode=? UNION SELECT item_id AS id FROM item_barcodes WHERE barcode=? LIMIT 1""",(code,code)).fetchone()
                        if owner and owner["id"]!=item_id: raise ValueError("Deze doosbarcode hoort al bij een ander artikel")
                        conn.execute("INSERT OR IGNORE INTO item_barcodes(barcode,item_id) VALUES(?,?)",(code,item_id))
                    conn.execute("UPDATE items SET box_barcode=?,units_per_box=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(code,units,item_id))
                    saved=item_to_dict(conn,conn.execute("SELECT * FROM items WHERE id=?",(item_id,)).fetchone())
                self.send_json({"item":saved})
            except (TypeError,ValueError,sqlite3.IntegrityError) as exc:
                self.send_json({"error":str(exc)},400)
            return
        if parsed.path == "/api/barcode-alias":
            try:
                item_id=int(data.get("id")); code=str(data.get("barcode", "")).strip()[:64]
                if not code: raise ValueError("Voer een doosbarcode in")
                with DB_LOCK, db_session() as conn:
                    item=conn.execute("SELECT * FROM items WHERE id=?",(item_id,)).fetchone()
                    if not item: raise ValueError("Artikel niet gevonden")
                    if item["barcode"] != code:
                        owner=conn.execute("""SELECT id FROM items WHERE barcode=? UNION
                            SELECT item_id AS id FROM item_barcodes WHERE barcode=? LIMIT 1""",(code,code)).fetchone()
                        if owner and owner["id"] != item_id: raise ValueError("Deze barcode hoort al bij een ander artikel")
                        conn.execute("INSERT OR IGNORE INTO item_barcodes(barcode,item_id) VALUES(?,?)",(code,item_id))
                    saved=item_to_dict(conn,conn.execute("SELECT * FROM items WHERE id=?",(item_id,)).fetchone())
                self.send_json({"item":saved})
            except (TypeError,ValueError,sqlite3.IntegrityError) as exc:
                self.send_json({"error":str(exc)},400)
            return
        if parsed.path == "/api/photo":
            try:
                item_id = int(data.get("id")); data_url = str(data.get("data", ""))
                if not data_url.startswith(("data:image/jpeg;base64,", "data:image/png;base64,")):
                    raise ValueError("Foto moet JPG of PNG zijn")
                mime, encoded = data_url.split(",",1)
                if len(encoded) > 1_800_000: raise ValueError("Foto is te groot; kies een kleinere afbeelding")
                raw = base64.b64decode(encoded, validate=True)
                if len(raw) > 1_300_000: raise ValueError("Foto is te groot")
                extension = ".jpg" if "jpeg" in mime else ".png"
                photo_dir = os.path.join(os.path.dirname(DB_PATH) or ".", "photos")
                os.makedirs(photo_dir, exist_ok=True)
                filename = f"item-{item_id}{extension}"
                with DB_LOCK, db_session() as conn:
                    row = conn.execute("SELECT photo_path FROM items WHERE id=?", (item_id,)).fetchone()
                    if not row: raise ValueError("Artikel niet gevonden")
                    old_path = row["photo_path"]
                    with open(os.path.join(photo_dir, filename), "wb") as image: image.write(raw)
                    conn.execute("UPDATE items SET photo_path=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (filename,item_id))
                if old_path and old_path != filename:
                    try: os.remove(os.path.join(photo_dir, os.path.basename(old_path)))
                    except OSError: pass
                self.send_json({"ok": True, "filename": filename})
            except (TypeError, ValueError, binascii.Error) as exc:
                self.send_json({"error": str(exc)}, 400)
            return
        if parsed.path == "/api/save":
            barcode = str(data.get("barcode", "")).strip()[:64]
            name = str(data.get("name", "")).strip()[:500]
            location = str(data.get("location", "")).strip()[:500]
            notes = str(data.get("notes", "")).strip()[:5000]
            item_id = data.get("id")
            box_barcode_provided = "box_barcode" in data
            units_provided = "units_per_box" in data
            box_barcode = str(data.get("box_barcode", "")).strip()[:64]
            if not barcode or not name:
                self.send_json({"error": "Barcode en naam zijn verplicht"}, 400)
                return
            aliases_provided = "alternate_barcodes" in data
            raw_aliases = data.get("alternate_barcodes", [])
            if isinstance(raw_aliases, str): raw_aliases = raw_aliases.replace(";", "\n").replace(",", "\n").splitlines()
            if not isinstance(raw_aliases, list): raw_aliases = []
            aliases = list(dict.fromkeys(str(code).strip()[:64] for code in raw_aliases if str(code).strip()))
            aliases = [code for code in aliases if code and code != barcode][:30]
            try:
                stock_count = int(data.get("stock_count", 1))
                min_stock = int(data.get("min_stock", 0))
                units_per_box = int(data.get("units_per_box", 1))
                if stock_count < 0 or min_stock < 0 or units_per_box < 1 or units_per_box > 100000:
                    raise ValueError("Aantal/minimum mogen niet negatief zijn; doosinhoud moet tussen 1 en 100.000 liggen")
                target_id = int(item_id) if item_id else None
                with DB_LOCK, db_session() as conn:
                    if target_id:
                        current=conn.execute("SELECT box_barcode,units_per_box FROM items WHERE id=?",(target_id,)).fetchone()
                        if not current: raise ValueError("Artikel niet gevonden")
                        if not box_barcode_provided: box_barcode=current["box_barcode"]
                        if not units_provided: units_per_box=current["units_per_box"]
                        if not aliases_provided:
                            aliases=[r[0] for r in conn.execute("SELECT barcode FROM item_barcodes WHERE item_id=?",(target_id,))]
                            aliases_provided=True
                    if box_barcode and box_barcode != barcode and box_barcode not in aliases:
                        aliases.append(box_barcode)
                        aliases_provided=True
                    for code in [barcode] + aliases:
                        owner = conn.execute("""SELECT id FROM items WHERE barcode=? UNION
                            SELECT item_id AS id FROM item_barcodes WHERE barcode=? LIMIT 1""", (code,code)).fetchone()
                        if owner and owner["id"] != target_id and (code != barcode or target_id is not None):
                            raise ValueError(f"Barcode {code} is al aan een ander artikel gekoppeld")
                    if target_id:
                        cursor = conn.execute("""UPDATE items SET barcode=?,name=?,location=?,notes=?,
                            stock_count=?,min_stock=?,box_barcode=?,units_per_box=?,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                            (barcode,name,location,notes,stock_count,min_stock,box_barcode,units_per_box,target_id))
                        if not cursor.rowcount: raise ValueError("Artikel niet gevonden")
                    else:
                        conn.execute("""INSERT INTO items(barcode,name,location,notes,stock_count,min_stock,box_barcode,units_per_box)
                            VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(barcode) DO UPDATE SET
                            name=excluded.name,location=excluded.location,notes=excluded.notes,
                            stock_count=excluded.stock_count,min_stock=excluded.min_stock,
                            box_barcode=excluded.box_barcode,units_per_box=excluded.units_per_box,updated_at=CURRENT_TIMESTAMP""",
                            (barcode,name,location,notes,stock_count,min_stock,box_barcode,units_per_box))
                        target_id = conn.execute("SELECT id FROM items WHERE barcode=?", (barcode,)).fetchone()[0]
                    if aliases_provided:
                        conn.execute("DELETE FROM item_barcodes WHERE item_id=?", (target_id,))
                        for code in aliases:
                            conn.execute("INSERT INTO item_barcodes(barcode,item_id) VALUES(?,?)", (code,target_id))
                    row = conn.execute("SELECT * FROM items WHERE id=?", (target_id,)).fetchone()
                    saved = item_to_dict(conn,row)
                self.send_json({"item": saved})
            except sqlite3.IntegrityError as exc:
                self.send_json({"error": f"Barcode bestaat al: {exc}"}, 409)
            except (ValueError, TypeError) as exc:
                self.send_json({"error": str(exc)}, 400)
            return
        if parsed.path == "/api/import":
            incoming = data.get("items")
            if not isinstance(incoming, list) or len(incoming) > 10000:
                self.send_json({"error": "Back-up moet een lijst met maximaal 10.000 artikelen bevatten"}, 400)
                return
            added = skipped = 0
            try:
                with DB_LOCK, db_session() as conn:
                    for item in incoming:
                        if not isinstance(item, dict):
                            skipped += 1
                            continue
                        barcode = str(item.get("barcode", "")).strip()[:64]
                        name = str(item.get("name", "")).strip()[:500]
                        if not barcode or not name:
                            skipped += 1
                            continue
                        location = str(item.get("location", "")).strip()[:500]
                        notes = str(item.get("notes", "")).strip()[:5000]
                        stock_count = max(0, int(item.get("stock_count", 1)))
                        min_stock = max(0, int(item.get("min_stock", 0)))
                        is_favorite = 1 if item.get("is_favorite") else 0
                        box_barcode = str(item.get("box_barcode", "")).strip()[:64]
                        units_per_box = max(1, min(100000, int(item.get("units_per_box", 1))))
                        if box_barcode and box_barcode != barcode:
                            box_owner=conn.execute("SELECT id FROM items WHERE barcode=? UNION SELECT item_id AS id FROM item_barcodes WHERE barcode=? LIMIT 1",(box_barcode,box_barcode)).fetchone()
                            if box_owner: box_barcode=""
                        owner = conn.execute("""SELECT id FROM items WHERE barcode=? UNION
                            SELECT item_id AS id FROM item_barcodes WHERE barcode=? LIMIT 1""", (barcode,barcode)).fetchone()
                        if owner:
                            skipped += 1
                            continue
                        cursor = conn.execute("""INSERT INTO items
                            (barcode,name,location,notes,stock_count,min_stock,is_favorite,box_barcode,units_per_box) VALUES(?,?,?,?,?,?,?,?,?)
                            ON CONFLICT(barcode) DO NOTHING""",
                            (barcode, name, location, notes, stock_count, min_stock, is_favorite,box_barcode,units_per_box))
                        if cursor.rowcount:
                            item_id = conn.execute("SELECT id FROM items WHERE barcode=?", (barcode,)).fetchone()[0]
                            aliases = item.get("alternate_barcodes", [])
                            if isinstance(aliases, list):
                                aliases = list(aliases)
                                if box_barcode and box_barcode != barcode and box_barcode not in aliases: aliases.append(box_barcode)
                                for alias in dict.fromkeys(str(code).strip()[:64] for code in aliases if str(code).strip()):
                                    if alias != barcode:
                                        alias_owner=conn.execute("SELECT id FROM items WHERE barcode=? UNION SELECT item_id AS id FROM item_barcodes WHERE barcode=? LIMIT 1",(alias,alias)).fetchone()
                                        if not alias_owner:
                                            conn.execute("INSERT OR IGNORE INTO item_barcodes(barcode,item_id) VALUES(?,?)", (alias,item_id))
                            added += 1
                        else:
                            skipped += 1
                self.send_json({"added": added, "skipped": skipped})
            except (ValueError, TypeError) as exc:
                self.send_json({"error": f"Ongeldige voorraad in back-up: {exc}"}, 400)
            return
        if parsed.path == "/api/stock-delta":
            try:
                item_id = int(data.get("id"))
                delta = int(data.get("delta"))
                if delta not in (-1, 1):
                    raise ValueError("Aantal kan alleen met 1 worden aangepast")
                with DB_LOCK, db_session() as conn:
                    cursor = conn.execute("""UPDATE items SET
                        stock_count=MAX(0,stock_count+?), updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                        (delta, item_id))
                    row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
                if cursor.rowcount == 0:
                    self.send_json({"error": "Artikel niet gevonden"}, 404)
                else:
                    self.send_json({"item": row_to_dict(row)})
            except (TypeError, ValueError) as exc:
                self.send_json({"error": str(exc)}, 400)
            return
        if parsed.path == "/api/favorite":
            try:
                item_id = int(data.get("id"))
                is_favorite = 1 if data.get("is_favorite") else 0
                with DB_LOCK, db_session() as conn:
                    cursor = conn.execute("UPDATE items SET is_favorite=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                                          (is_favorite, item_id))
                    row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
                if cursor.rowcount == 0:
                    self.send_json({"error": "Artikel niet gevonden"}, 404)
                else:
                    self.send_json({"item": row_to_dict(row)})
            except (TypeError, ValueError) as exc:
                self.send_json({"error": str(exc)}, 400)
            return
        if parsed.path == "/api/delete":
            try:
                item_id = int(data.get("id"))
            except (TypeError, ValueError):
                self.send_json({"error": "Ongeldig ID"}, 400)
                return
            with DB_LOCK, db_session() as conn:
                row=conn.execute("SELECT photo_path FROM items WHERE id=?",(item_id,)).fetchone()
                conn.execute("DELETE FROM item_barcodes WHERE item_id=?",(item_id,))
                conn.execute("DELETE FROM items WHERE id=?", (item_id,))
            if row and row["photo_path"]:
                try: os.remove(os.path.join(os.path.dirname(DB_PATH) or ".","photos",os.path.basename(row["photo_path"])))
                except OSError: pass
            self.send_json({"ok": True})
            return
        self.send_json({"error": "Niet gevonden"}, 404)


PAGE = r'''<!doctype html>
<html lang="nl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ScanBase — voorraad</title><style>
:root{font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#eaf0ff;background:#0b1020;--panel:#151d33;--line:#283451;--muted:#a4b0ca;--accent:#73e0c1;--blue:#6da8ff}
*{box-sizing:border-box}body{margin:0}header{padding:22px max(20px,calc((100% - 1100px)/2));display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);background:#10172a;gap:14px}h1{font-size:22px;margin:0}header p{margin:4px 0 0;color:var(--muted);font-size:13px}.header-actions{display:flex;align-items:center;gap:9px;flex-wrap:wrap}.online-shortcut{background:#183d42;color:var(--accent);border:1px solid #286956;padding:8px 12px;border-radius:999px}.status{font-size:13px;padding:8px 12px;border:1px solid var(--line);border-radius:999px;color:var(--muted)}.status.ready{color:var(--accent);border-color:#286956}.status.error{color:#ff9292;border-color:#8c3b46}.tabbar{max-width:1100px;margin:18px auto 0;padding:0 18px;display:flex;gap:10px}.tabbutton{background:transparent;border:1px solid var(--line);color:var(--muted)}.tabbutton.active{background:#203653;color:var(--accent);border-color:#3b6e7f}.catalog-grid{max-width:1100px;margin:24px auto;padding:0 18px;display:grid;grid-template-columns:1fr 1fr;gap:18px}.searchrow{display:flex;gap:10px}.searchrow input{flex:1}.catalog-result{margin-top:16px;padding:16px;border:1px solid var(--line);border-radius:12px;background:#101a30}.catalog-result h3{margin:0 0 8px;font-size:20px}.catalog-result p{color:var(--muted);margin:6px 0}.product-image{max-width:140px;max-height:140px;object-fit:contain;float:right;margin:0 0 10px 14px;border-radius:8px}.buy-links{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}.buy-links a{display:inline-block;padding:8px 11px;background:#263653;border-radius:8px;color:#cfe3ff;text-decoration:none}.recent-row{width:100%;text-align:left;padding:11px;border:1px solid var(--line);background:#111a2e;border-radius:9px;color:#edf3ff;margin:5px 0}.inventory-list-heading{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}.inventory-list-heading h2{margin-bottom:4px}.inventory-list-heading .hint{margin:0}.inventory-filters{display:grid;grid-template-columns:minmax(180px,1fr) repeat(3,minmax(130px,190px)) minmax(130px,180px);gap:10px;margin:14px 0}.inventory-list{display:grid;gap:8px}.inventory-row{display:grid;grid-template-columns:minmax(0,1fr) minmax(100px,150px) auto auto;align-items:center;gap:12px;padding:12px;border:1px solid var(--line);background:#111a2e;border-radius:10px}.stock-controls{display:flex;align-items:center;gap:7px}.stock-controls button{padding:5px 10px;min-width:32px}.stock-controls span{min-width:24px;text-align:center;font-weight:700}.inventory-row.low-stock{border-color:#8c3b46;background:#241722}.stock-badge{display:inline-block;margin-top:5px;padding:3px 7px;border-radius:999px;background:#66313a;color:#ffd4d4;font-size:12px}.inventory-row strong{display:block}.inventory-row small{display:block;color:var(--muted);margin-top:3px;word-break:break-all}.inventory-row .item-location{color:var(--muted);font-size:14px}.inventory-row .buttons{margin:0}.details-dialog{width:min(560px,calc(100vw - 32px));max-height:90vh;overflow:auto;margin:auto;padding:22px;background:#151d33;color:#eaf0ff;border:1px solid #3b6e7f;border-radius:16px;box-shadow:0 24px 70px #000a}.details-dialog::backdrop{background:#000b;backdrop-filter:blur(3px)}.details-heading{display:flex;align-items:center;justify-content:space-between;gap:12px}.details-heading h2{margin:0}.details-content{display:grid;gap:9px;margin-top:16px}.detail-field{padding:10px 12px;background:#0f1830;border:1px solid var(--line);border-radius:9px}.detail-field small{display:block;color:var(--muted);margin-bottom:3px}.detail-field strong{white-space:pre-wrap;overflow-wrap:anywhere}.catalog-form{border-top:1px solid var(--line);margin-top:15px;padding-top:12px}dialog.catalog-form{width:min(560px,calc(100vw - 32px));max-height:90vh;overflow:auto;margin:auto;padding:22px;background:#151d33;color:#eaf0ff;border:1px solid #3b6e7f;border-radius:16px;box-shadow:0 24px 70px #000a}dialog.catalog-form::backdrop{background:#000b;backdrop-filter:blur(3px)}.catalog-message{color:var(--muted);font-size:13px;margin-top:8px}.tool-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.tool-panel{padding:14px;border:1px solid var(--line);border-radius:12px;background:#101a30}.tool-panel h3{margin:0 0 8px;font-size:15px}.tool-list{display:grid;gap:6px;max-height:260px;overflow:auto;margin-top:10px}.tool-row{padding:8px 10px;border-radius:8px;background:#111a2e;font-size:13px}.tool-row small{display:block;color:var(--muted);margin-top:3px}.photo-thumb{max-width:120px;max-height:120px;object-fit:contain;border-radius:8px}.label-dialog{width:min(520px,calc(100vw - 32px));max-height:90vh;overflow:auto;margin:auto;padding:22px;background:#151d33;color:#eaf0ff;border:1px solid #3b6e7f;border-radius:16px}.label-dialog::backdrop{background:#000b}@media print{body>*{display:none!important}#printArea{display:block!important}.print-label{width:62mm;height:35mm;border:1px dashed #777;padding:3mm;display:inline-flex;flex-direction:column;align-items:center;justify-content:center;overflow:hidden;font:10pt Arial,sans-serif;page-break-inside:avoid}.print-label svg{width:90%;height:15mm}.print-label strong{max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.print-label small{font-size:8pt}}@media(max-width:760px){.catalog-grid{grid-template-columns:1fr}.searchrow{flex-direction:column}.inventory-filters{grid-template-columns:1fr}.inventory-row{grid-template-columns:1fr}.inventory-row .buttons{justify-content:flex-start}.tool-grid{grid-template-columns:1fr}}
main{max-width:1100px;margin:24px auto;padding:0 18px;display:grid;grid-template-columns:1fr 1fr;gap:18px}.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px;box-shadow:0 10px 30px #0002}.card h2{font-size:17px;margin:0 0 16px}.wide{grid-column:1/-1}.scanbox{padding:14px;border-radius:12px;background:#0f1830;border:1px solid #273858;margin-bottom:12px}.scanbox small{color:var(--muted)}#lastScan{font-size:23px;font-weight:700;margin-top:4px;word-break:break-all;color:var(--accent)}.scan-details{padding:13px 14px;border:1px solid var(--line);border-radius:12px;background:#111a2e;min-height:68px}.scan-details strong{display:block;font-size:18px}.scan-details span{display:block;color:var(--muted);margin-top:5px}.scan-details.empty{color:var(--muted)}label{display:block;font-size:13px;color:var(--muted);margin:13px 0 6px}input,textarea,select{font:inherit;width:100%;padding:11px 12px;border-radius:9px;border:1px solid #364461;background:#0e1527;color:#f5f7ff;outline:none}input:focus,textarea:focus{border-color:var(--blue);box-shadow:0 0 0 3px #6da8ff22}textarea{min-height:85px;resize:vertical}.buttons{display:flex;gap:9px;flex-wrap:wrap;margin-top:16px}button{font:inherit;border:0;border-radius:9px;padding:10px 14px;cursor:pointer;background:#283653;color:#edf3ff}button.primary{background:#69d8b6;color:#071b18;font-weight:700}button.danger{background:#492632;color:#ffb5b5}button:hover{filter:brightness(1.12)}.results{display:grid;gap:8px;margin-top:12px}.result{width:100%;text-align:left;padding:12px;border:1px solid var(--line);background:#111a2e}.result strong{display:block}.result span{display:block;color:var(--muted);font-size:13px;margin-top:3px}.hint,#message{color:var(--muted);font-size:13px}.empty{padding:14px;color:var(--muted);font-size:14px}.footer{max-width:1100px;margin:0 auto 25px;padding:0 18px;color:#7e8ba8;font-size:12px}@media(max-width:760px){main{grid-template-columns:1fr}.wide{grid-column:auto}header{align-items:flex-start;flex-direction:column}}
</style></head><body>
<header><div><h1>ScanBase</h1><p>Voorraad, barcodes en locaties</p></div><div class="header-actions"><button id="headerOnline" class="online-shortcut" type="button">Online zoeken</button><div id="status" class="status">Scanner verbinden…</div></div></header>
<nav class="tabbar"><button id="tabInventory" class="tabbutton active" type="button">Mijn voorraad</button><button id="tabCatalog" class="tabbutton" type="button">Algemene database</button></nav>
<main id="inventoryView"><section class="card"><h2>Scanner</h2><div class="scanbox"><small>Laatste scan</small><div id="lastScan">Nog niets gescand</div></div><div id="scanDetails" class="scan-details empty">Na een scan zie je hier de naam en locatie.</div><p class="hint">Bekende artikelen worden getoond; onbekende codes kun je hieronder toevoegen.</p></section>
<section class="card"><h2>Zoeken</h2><label for="search">Zoek op naam, barcode, locatie of notitie</label><input id="search" autocomplete="off" placeholder="Bijvoorbeeld: boormachine of kast A2"><div id="results" class="results"><div class="empty">Typ om artikelen te zoeken.</div></div></section>
<section class="card wide" id="itemFormCard"><h2 id="formTitle">Artikel toevoegen of wijzigen</h2><input type="hidden" id="itemId"><label for="barcode">Barcode</label><input id="barcode" autocomplete="off" placeholder="Scan of typ een barcode"><label for="name">Naam</label><input id="name" autocomplete="off" placeholder="Bijvoorbeeld: accuboormachine"><label for="location">Locatie</label><input id="location" list="locationSuggestions" autocomplete="off" placeholder="Bijvoorbeeld: schuur, kast A2"><datalist id="locationSuggestions"></datalist><label for="alternateBarcodes">Extra barcodes voor hetzelfde artikel</label><textarea id="alternateBarcodes" placeholder="Eén barcode per regel (bijvoorbeeld extra verpakking) "></textarea><label for="boxBarcode">Barcode van de hele doos (optioneel)</label><input id="boxBarcode" autocomplete="off" placeholder="Verschilt de doosbarcode? Vul die hier in"><label for="unitsPerBox">Stuks in een hele doos</label><input id="unitsPerBox" type="number" min="1" step="1" value="1"><label for="stockCount">Aantal op voorraad</label><input id="stockCount" type="number" min="0" step="1" value="1"><label for="minStock">Waarschuw als aantal hierop of lager komt (0 = uit)</label><input id="minStock" type="number" min="0" step="1" value="0"><label for="notes">Notities</label><textarea id="notes" placeholder="Extra informatie (optioneel)"></textarea><label for="itemPhoto">Foto (blijft lokaal bewaard)</label><input id="itemPhoto" type="file" accept="image/jpeg,image/png"><img id="photoPreview" alt="Artikel foto" hidden style="max-width:180px;max-height:180px;object-fit:contain;border-radius:10px;margin-top:10px"><div class="buttons"><button class="primary" id="save">Opslaan</button><button id="clear">Leegmaken</button><button class="danger" id="delete" hidden>Verwijderen</button></div><p id="message" role="status"></p></section>
<section class="card wide" id="inventoryListCard"><div class="inventory-list-heading"><div><h2>Alle artikelen</h2><p id="inventoryStats" class="hint">Voorraad laden…</p></div><div class="buttons"><button id="refreshInventory" type="button">Verversen</button><button id="randomItem" type="button">🎲 Kies willekeurig</button><button id="exportCsv" type="button">Download CSV</button><button id="exportLowStock" type="button">Aanvullijst</button><button id="exportJson" type="button">Back-up JSON</button><button id="importJson" type="button">Importeer back-up</button><button id="importCsv" type="button">Importeer CSV</button><input id="importBackupFile" type="file" accept=".json,application/json" hidden><input id="importCsvFile" type="file" accept=".csv,text/csv" hidden></div></div><div class="inventory-filters"><input id="inventoryListSearch" autocomplete="off" placeholder="Filter op naam, barcode of notitie"><select id="inventoryLocationFilter"><option value="">Alle locaties</option></select><select id="inventoryStockFilter"><option value="">Alle voorraadniveaus</option><option value="low">Lage voorraad</option></select><select id="inventoryFavoriteFilter"><option value="">Alle artikelen</option><option value="yes">Alleen favorieten</option></select><select id="inventorySort"><option value="name">Naam A–Z</option><option value="recent">Laatst gewijzigd</option><option value="location">Locatie A–Z</option></select></div><div id="inventoryListRows" class="inventory-list"><div class="empty">Voorraad laden…</div></div></section><section class="card wide" id="toolsCard"><h2>Extra functies</h2><div class="tool-grid"><div class="tool-panel"><h3>Scanmodus</h3><p class="hint">Kies wat een scan doet. Ontvangst verhoogt de voorraad; verbruik verlaagt die.</p><select id="scanMode"><option value="normal">Normaal — alleen herkennen</option><option value="receive">Ontvangst — +1 per scan</option><option value="consume">Verbruik — −1 per scan</option><option value="stocktake">Voorraadopname</option></select><div class="buttons"><button id="undoScan" type="button">Laatste voorraadscan ongedaan maken</button></div><p id="modeMessage" class="hint"></p></div><div class="tool-panel"><h3>Voorraadopname</h3><label for="stocktakeName">Naam</label><input id="stocktakeName" value="Voorraadopname"><div class="buttons"><button id="startStocktake" class="primary" type="button">Start opname</button><button id="finishStocktake" type="button">Opname afronden</button><button id="applyStocktake" type="button">Pas verschillen toe</button><button id="refreshStocktake" type="button">Ververs telling</button></div><p id="stocktakeStatus" class="hint">Geen actieve opname.</p><div id="stocktakeLines" class="tool-list"></div></div><div class="tool-panel"><h3>Scanlogboek</h3><div class="buttons"><button id="refreshHistory" type="button">Ververs logboek</button><button id="moreHistory" type="button">Meer laden</button></div><div id="scanHistory" class="tool-list"><div class="empty">Nog geen scans.</div></div></div><div class="tool-panel"><h3>Bijbesteladvies</h3><p class="hint">Aantal om weer tot het minimum aan te vullen. Exporteer de aanvullijst bij Alle artikelen.</p><div id="reorderAdvice" class="tool-list"></div></div></div></section></main>
<main id="catalogView" class="catalog-grid" hidden><section class="card"><h2>Algemene productdatabase</h2><p class="hint">Zoek een barcode in openbare productdatabases. De dekking verschilt per productsoort.</p><label for="catalogBarcode">Barcode</label><div class="searchrow"><input id="catalogBarcode" autocomplete="off" placeholder="Scan of typ EAN/UPC/ISBN"><button class="primary" id="catalogLookup" type="button">Zoek online</button></div><div id="catalogResult" class="catalog-result"><p>Voer een barcode in of scan een onbekend artikel.</p></div></section><section class="card"><h2>Recent online opgezocht</h2><label for="catalogSearch">Zoek in je online zoekgeschiedenis</label><input id="catalogSearch" autocomplete="off" placeholder="Naam, merk of barcode"><div id="catalogRecent" class="results"><div class="empty">Nog geen online zoekopdrachten.</div></div><p class="hint">Dit is de lokale geschiedenis van opgezochte codes, niet een volledige kopie van internet.</p></section></main>
<dialog id="itemDetailsDialog" class="details-dialog"><div class="details-heading"><h2>Artikelgegevens</h2><button id="closeDetails" type="button">Sluiten</button></div><div id="detailsContent" class="details-content"></div><div class="buttons"><button id="copyDetailBarcode" type="button">Barcode kopiëren</button><button id="printLabels" type="button">Etiketten afdrukken</button><button class="primary" id="editDetailItem" type="button">Wijzigen</button></div><p id="detailsMessage" class="catalog-message" role="status"></p></dialog>
<dialog id="labelDialog" class="label-dialog"><h2>Etiketten afdrukken</h2><label for="labelKind">Soort etiket</label><select id="labelKind"><option value="unit">Los artikel — één stuk</option><option value="box-same">Hele doos — zelfde barcode</option><option value="box-own">Hele doos — eigen doosbarcode</option></select><label for="labelBoxQty">Aantal stuks in de doos</label><input id="labelBoxQty" type="number" min="1" step="1" value="1"><label for="labelBoxBarcode">Barcode doos (bij eigen barcode)</label><input id="labelBoxBarcode" placeholder="Scan of typ de doosbarcode"><label for="labelCopies">Aantal etiketten</label><input id="labelCopies" type="number" min="1" max="200" step="1" value="1"><p id="labelItemName" class="hint"></p><div class="buttons"><button id="cancelLabels" type="button">Annuleren</button><button id="doPrintLabels" class="primary" type="button">Afdrukken</button></div></dialog>
<dialog id="csvPreviewDialog" class="label-dialog"><h2>CSV-import controleren</h2><p id="csvPreviewSummary" class="hint"></p><div id="csvPreviewRows" class="tool-list"></div><div class="buttons"><button id="cancelCsvImport" type="button">Annuleren</button><button id="confirmCsvImport" class="primary" type="button">Importeer nieuwe artikelen</button></div></dialog>
<div class="footer">Persoonlijke voorraad, foto's, alternatieve barcodes, voorraadopnames en scanlogboek worden lokaal op de NAS bewaard. Behoud de gedeelde map <code>/data</code> wanneer je de container bijwerkt.</div>
<script>
const $=id=>document.getElementById(id);let lastId=0;let searchTimer;let catalogTimer;let allInventoryItems=[];let activeDetailItem=null;let selectedPhoto=null;
function setMessage(t){$('message').textContent=t||''}
function setTab(name){const inventory=name==='inventory';$('inventoryView').hidden=!inventory;$('catalogView').hidden=inventory;$('tabInventory').classList.toggle('active',inventory);$('tabCatalog').classList.toggle('active',!inventory);if(!inventory)loadCatalogRecent()}
$('headerOnline').onclick=()=>{setTab('catalog');$('catalogBarcode').focus()};
function showScanDetails(item,code=''){const root=$('scanDetails');root.replaceChildren();if(item){root.className='scan-details';const title=document.createElement('strong');title.textContent=item.name||'Naam ontbreekt';const location=document.createElement('span');location.textContent='Locatie: '+(item.location||'Nog geen locatie ingevuld');root.append(title,location);return}root.className='scan-details empty';const title=document.createElement('strong');title.textContent=code?'Nog niet opgeslagen':'Na een scan zie je hier de naam en locatie.';const detail=document.createElement('span');detail.textContent=code?'Barcode: '+code:'';root.append(title,detail)}
function clearForm(){ $('itemId').value='';$('barcode').value='';$('name').value='';$('location').value='';$('alternateBarcodes').value='';$('boxBarcode').value='';$('unitsPerBox').value='1';$('stockCount').value='1';$('minStock').value='0';$('notes').value='';$('itemPhoto').value='';selectedPhoto=null;$('photoPreview').hidden=true;$('formTitle').textContent='Artikel toevoegen of wijzigen';$('delete').hidden=true;setMessage('') }
function fillForm(item){$('itemId').value=item?.id||'';$('barcode').value=item?.barcode||'';$('name').value=item?.name||'';$('location').value=item?.location||'';$('alternateBarcodes').value=(item?.alternate_barcodes||[]).filter(code=>code!==item?.box_barcode).join('\n');$('boxBarcode').value=item?.box_barcode||'';$('unitsPerBox').value=item?.units_per_box??1;$('stockCount').value=item?.stock_count??1;$('minStock').value=item?.min_stock??0;$('notes').value=item?.notes||'';$('itemPhoto').value='';selectedPhoto=null;$('photoPreview').hidden=true;$('formTitle').textContent=item?.id?'Artikel wijzigen':'Nieuw artikel';$('delete').hidden=!item?.id;setMessage(item?.id?'Artikel geladen.':'Onbekende barcode — vul een naam en locatie in.');showScanDetails(item?.id?item:null,item?.barcode||'');if(item?.id){fetch('/api/photo?id='+encodeURIComponent(item.id)).then(r=>r.json()).then(d=>{if($('itemId').value==item.id&&d.photo){$('photoPreview').src=d.photo;$('photoPreview').hidden=false}}).catch(()=>{})}}
async function loadByBarcode(code){$('lastScan').textContent=code;try{let r=await fetch('/api/by-barcode?code='+encodeURIComponent(code));let d=await r.json();if(d.item){setTab('inventory');fillForm(d.item)}else{setTab('catalog');$('catalogBarcode').value=code;fillForm({barcode:code});await lookupOnline(code)}}catch(e){setTab('inventory');fillForm({barcode:code});setMessage('Kon artikel niet laden: '+e.message)}}
async function pollScans(){try{let d=await (await fetch('/api/scans?after='+lastId)).json();for(const s of d.scans){lastId=s.id;await loadByBarcode(s.code)}if(d.scans.length){await Promise.all([loadScanHistory(true),loadInventoryList(),loadStocktake()])}}catch(e){}setTimeout(pollScans,500)}
async function refreshStatus(){try{let d=await (await fetch('/api/status')).json(),s=d.scanner;$('status').textContent=s.message;$('status').className='status '+(s.state==='ready'?'ready':s.state==='error'?'error':'')}catch(e){$('status').textContent='Verbinding met NAS mislukt'}setTimeout(refreshStatus,2000)}
function showResults(items){let root=$('results');root.replaceChildren();if(!items.length){root.innerHTML='<div class="empty">Geen artikelen gevonden.</div>';return}for(const item of items){let b=document.createElement('button');b.className='result';let strong=document.createElement('strong');strong.textContent=item.name;let span=document.createElement('span');span.textContent=(item.location||'Geen locatie')+' · '+item.barcode;b.append(strong,span);b.onclick=()=>fillForm(item);root.appendChild(b)}}
async function loadInventoryList(){try{let response=await fetch('/api/items');let data=await response.json();allInventoryItems=data.items||[];let select=$('inventoryLocationFilter'),current=select.value;select.replaceChildren();let all=document.createElement('option');all.value='';all.textContent='Alle locaties';select.appendChild(all);let none=document.createElement('option');none.value='__none__';none.textContent='Geen locatie';select.appendChild(none);let locations=[...new Set(allInventoryItems.map(item=>item.location).filter(Boolean))].sort((a,b)=>a.localeCompare(b,'nl'));let locationList=$('locationSuggestions');locationList.replaceChildren();for(const value of locations){let option=document.createElement('option');option.value=value;option.textContent=value;select.appendChild(option);let suggestion=document.createElement('option');suggestion.value=value;locationList.appendChild(suggestion)}if([...select.options].some(option=>option.value===current))select.value=current;renderInventoryList();renderReorderAdvice()}catch(e){$('inventoryStats').textContent='Voorraad kon niet worden geladen.'}}
async function changeStock(id,delta){try{let response=await fetch('/api/stock-delta',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,delta})});let data=await response.json();if(!response.ok)throw Error(data.error||'Aantal aanpassen mislukt');await loadInventoryList()}catch(e){alert(e.message)}}
async function setFavorite(id,isFavorite){try{let response=await fetch('/api/favorite',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,is_favorite:isFavorite})});let data=await response.json();if(!response.ok)throw Error(data.error||'Favoriet aanpassen mislukt');await loadInventoryList()}catch(e){alert(e.message)}}
function renderInventoryList(){let root=$('inventoryListRows');root.replaceChildren();let query=$('inventoryListSearch').value.trim().toLocaleLowerCase('nl');let location=$('inventoryLocationFilter').value;let lowOnly=$('inventoryStockFilter').value==='low';let favoritesOnly=$('inventoryFavoriteFilter').value==='yes';let isLow=item=>Number(item.min_stock||0)>0&&Number(item.stock_count??1)<=Number(item.min_stock);let rows=allInventoryItems.filter(item=>{let text=[item.name,item.barcode,item.location,item.notes,item.box_barcode,...(item.alternate_barcodes||[])].join(' ').toLocaleLowerCase('nl');let locationMatch=!location||(location==='__none__'?!item.location:item.location===location);return locationMatch&&(!lowOnly||isLow(item))&&(!favoritesOnly||Boolean(item.is_favorite))&&(!query||text.includes(query))});let sort=$('inventorySort').value;rows.sort((a,b)=>sort==='recent'?String(b.updated_at||'').localeCompare(String(a.updated_at||'')):sort==='location'?(String(a.location||'').localeCompare(String(b.location||''),'nl')||String(a.name||'').localeCompare(String(b.name||''),'nl')):String(a.name||'').localeCompare(String(b.name||''),'nl'));let distinctLocations=new Set(allInventoryItems.map(item=>item.location).filter(Boolean)).size;let noLocation=allInventoryItems.filter(item=>!item.location).length;let lowCount=allInventoryItems.filter(isLow).length;let favoriteCount=allInventoryItems.filter(item=>Boolean(item.is_favorite)).length;$('inventoryStats').textContent=`${allInventoryItems.length} artikelen · ${distinctLocations} locaties · ${noLocation} zonder locatie · ${lowCount} lage voorraad · ${favoriteCount} favorieten${rows.length!==allInventoryItems.length?' · '+rows.length+' in deze selectie':''}`;if(!rows.length){root.innerHTML='<div class="empty">Geen artikelen in deze selectie.</div>';return}for(const item of rows){let low=isLow(item);let row=document.createElement('div');row.className='inventory-row'+(low?' low-stock':'');let info=document.createElement('div');let title=document.createElement('strong');title.textContent=item.name||'Naam ontbreekt';let barcode=document.createElement('small');barcode.textContent='Barcode: '+item.barcode;let stock=document.createElement('small');stock.textContent=`Aantal: ${Number(item.stock_count??1)}${Number(item.min_stock||0)>0?' · minimum: '+Number(item.min_stock):''}`;info.append(title,barcode,stock);if(item.box_barcode){let box=document.createElement('small');box.textContent=`Doos: ${item.units_per_box||1} stuks · ${item.box_barcode}`;info.appendChild(box)}let extraCodes=(item.alternate_barcodes||[]).filter(code=>code!==item.box_barcode);if(extraCodes.length){let otherCodes=document.createElement('small');otherCodes.textContent='Extra barcodes: '+extraCodes.join(', ');info.appendChild(otherCodes)}if(low){let badge=document.createElement('span');badge.className='stock-badge';badge.textContent='Lage voorraad';info.appendChild(badge)}let place=document.createElement('div');place.className='item-location';place.textContent=item.location||'Geen locatie';let stockControls=document.createElement('div');stockControls.className='stock-controls';let minus=document.createElement('button');minus.type='button';minus.textContent='−';minus.title='Aantal met één verlagen';minus.onclick=()=>changeStock(item.id,-1);let stockValue=document.createElement('span');stockValue.textContent=String(Number(item.stock_count??1));let plus=document.createElement('button');plus.type='button';plus.textContent='+';plus.title='Aantal met één verhogen';plus.onclick=()=>changeStock(item.id,1);stockControls.append(minus,stockValue,plus);let buttons=document.createElement('div');buttons.className='buttons';let favorite=document.createElement('button');favorite.type='button';favorite.textContent=item.is_favorite?'★':'☆';favorite.title=item.is_favorite?'Favoriet verwijderen':'Markeren als favoriet';favorite.setAttribute('aria-label',favorite.title);favorite.onclick=()=>setFavorite(item.id,!item.is_favorite);let details=document.createElement('button');details.type='button';details.textContent='Details';details.onclick=()=>openItemDetails(item.id);let edit=document.createElement('button');edit.type='button';edit.textContent='Wijzigen';edit.onclick=()=>{setTab('inventory');fillForm(item);$('itemFormCard').scrollIntoView({behavior:'smooth',block:'start'})};buttons.append(favorite,details,edit);row.append(info,place,stockControls,buttons);root.appendChild(row)}}
function renderReorderAdvice(){let root=$('reorderAdvice');if(!root)return;root.replaceChildren();let rows=allInventoryItems.filter(item=>Number(item.min_stock||0)>Number(item.stock_count??1)).sort((a,b)=>(Number(b.min_stock)-Number(b.stock_count))-(Number(a.min_stock)-Number(a.stock_count)));if(!rows.length){root.innerHTML='<div class="empty">Geen aanvulling nodig.</div>';return}for(const item of rows.slice(0,30)){let row=document.createElement('div');row.className='tool-row';row.textContent=`${item.name}: bestel ${Number(item.min_stock)-Number(item.stock_count)} (voorraad ${item.stock_count}, minimum ${item.min_stock})`;root.appendChild(row)}}
let historyOffset=0;async function loadScanHistory(reset=false){try{let root=$('scanHistory');if(reset){historyOffset=0;root.replaceChildren()}let data=await(await fetch('/api/history?limit=100&offset='+historyOffset)).json();if(!data.events?.length){if(historyOffset===0)root.innerHTML='<div class="empty">Nog geen scans.</div>';$('moreHistory').hidden=true;return}for(const event of data.events){let row=document.createElement('div');row.className='tool-row';let action=event.mode==='receive'?' · ontvangen +'+event.delta:event.mode==='consume'&&event.delta?' · verbruikt '+Math.abs(event.delta):event.mode==='stocktake'?' · voorraadopname':event.mode==='stocktake_apply'?' · opname toegepast':event.mode==='undo'?' · ongedaan gemaakt':'';row.textContent=(event.name||'Onbekende barcode')+' · '+event.barcode+action;let small=document.createElement('small');small.textContent=event.created_at+(event.undone?' · ongedaan gemaakt':'');row.appendChild(small);root.appendChild(row)}historyOffset+=data.events.length;$('moreHistory').hidden=data.events.length<100}catch(e){}}
async function loadStocktake(){try{let data=await(await fetch('/api/stocktake')).json();let st=data.stocktake;let root=$('stocktakeLines');root.replaceChildren();$('startStocktake').disabled=!!(st&&st.status==='active');$('finishStocktake').disabled=!(st&&st.status==='active');$('applyStocktake').disabled=!st;if(!st){$('stocktakeStatus').textContent='Nog geen voorraadopname.';root.innerHTML='<div class="empty">Start een opname om artikelen te tellen.</div>';return}$('stocktakeStatus').textContent=`${st.name} · ${st.status==='active'?'ACTIEF':'afgerond'} · ${st.line_count} regels · ${st.differences} verschillen · gestart ${st.started_at}`;let dataLines=await(await fetch('/api/stocktake/lines?id='+st.id)).json();if(!dataLines.lines.length){root.innerHTML='<div class="empty">Geen regels.</div>';return}for(const line of dataLines.lines){let row=document.createElement('div');row.className='tool-row';let title=document.createElement('strong');title.textContent=(line.name_snapshot||'Onbekend')+' · '+line.barcode;let detail=document.createElement('small');detail.textContent=`Verwacht: ${line.expected_count} · Geteld: ${line.counted_count} · Verschil: ${Number(line.counted_count)-Number(line.expected_count)}`;let controls=document.createElement('div');controls.className='buttons';let input=document.createElement('input');input.type='number';input.min='0';input.value=line.counted_count;input.setAttribute('aria-label','Geteld aantal');input.style.maxWidth='110px';let save=document.createElement('button');save.textContent='Aantal bewaren';save.onclick=async()=>{let res=await fetch('/api/stocktake/count',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({line_id:line.id,count:input.value})});let result=await res.json();if(!res.ok){alert(result.error);return}loadStocktake()};controls.append(input,save);row.append(title,detail,controls);root.appendChild(row)}}catch(e){$('stocktakeStatus').textContent='Voorraadopname kon niet worden geladen.'}}
async function loadScanMode(){try{let d=await(await fetch('/api/scan-mode')).json();$('scanMode').value=d.mode||'normal';$('modeMessage').textContent=d.mode==='receive'?'Ontvangst actief: elke bekende scan verhoogt met één.':d.mode==='consume'?'Verbruik actief: elke bekende scan verlaagt met één.':d.mode==='stocktake'?'Voorraadopname actief; scans tellen artikelen.':'Normale scanmodus: voorraad verandert niet.'}catch(e){}}
$('scanMode').onchange=async()=>{try{let r=await fetch('/api/scan-mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:$('scanMode').value})});let d=await r.json();if(!r.ok)throw Error(d.error);loadScanMode()}catch(e){alert(e.message);loadScanMode()}};
$('undoScan').onclick=async()=>{try{let r=await fetch('/api/undo-last',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});let d=await r.json();if(!r.ok)throw Error(d.error);await Promise.all([loadInventoryList(),loadScanHistory()]);alert('Laatste voorraadscan ongedaan gemaakt: '+d.barcode)}catch(e){alert(e.message)}};
$('startStocktake').onclick=async()=>{try{let r=await fetch('/api/stocktake',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'start',name:$('stocktakeName').value})});let d=await r.json();if(!r.ok)throw Error(d.error);await Promise.all([loadStocktake(),loadScanMode()])}catch(e){alert(e.message)}};
$('finishStocktake').onclick=async()=>{if(!confirm('Voorraadopname afronden? Je kunt de telling nog bekijken.'))return;try{let r=await fetch('/api/stocktake',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'finish'})});let d=await r.json();if(!r.ok)throw Error(d.error);await Promise.all([loadStocktake(),loadScanMode()])}catch(e){alert(e.message)}};
$('applyStocktake').onclick=async()=>{let d=await(await fetch('/api/stocktake')).json();let st=d.stocktake;if(!st){alert('Geen telling beschikbaar.');return}if(!confirm('De getelde aantallen van '+st.name+' toepassen op de voorraad? Dit werkt de voorraad bij voor alle verschillen.'))return;try{let r=await fetch('/api/stocktake',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'apply',stocktake_id:st.id})});let result=await r.json();if(!r.ok)throw Error(result.error);alert(result.updated+' artikelen bijgewerkt.');await Promise.all([loadInventoryList(),loadStocktake(),loadScanHistory()])}catch(e){alert(e.message)}};
$('refreshStocktake').onclick=loadStocktake;$('refreshHistory').onclick=()=>loadScanHistory(true);$('moreHistory').onclick=()=>loadScanHistory(false);
async function openItemDetails(id){try{let response=await fetch('/api/item?id='+encodeURIComponent(id));let data=await response.json();if(!response.ok||!data.item)throw Error(data.error||'Artikel niet gevonden');activeDetailItem=data.item;let root=$('detailsContent');root.replaceChildren();let photoData=await fetch('/api/photo?id='+encodeURIComponent(id)).then(r=>r.json()).catch(()=>({photo:''}));if(photoData.photo){let image=document.createElement('img');image.src=photoData.photo;image.alt=data.item.name;image.className='photo-thumb';root.appendChild(image)}for(const [label,value] of [['Naam',data.item.name],['Barcode',data.item.barcode],['Extra barcodes',(data.item.alternate_barcodes||[]).filter(code=>code!==data.item.box_barcode).join(', ')||'Geen'],['Barcode doos',data.item.box_barcode||'Zelfde als artikel'],['Stuks per doos',String(data.item.units_per_box||1)],['Locatie',data.item.location||'Geen locatie'],['Aantal',String(data.item.stock_count??1)],['Minimumvoorraad',String(data.item.min_stock??0)],['Favoriet',data.item.is_favorite?'Ja':'Nee'],['Notities',data.item.notes||'Geen notities'],['Laatst gewijzigd',data.item.updated_at||'']]){let box=document.createElement('div');box.className='detail-field';let small=document.createElement('small');small.textContent=label;let strong=document.createElement('strong');strong.textContent=value;box.append(small,strong);root.appendChild(box)}$('detailsMessage').textContent='';$('itemDetailsDialog').showModal()}catch(e){alert(e.message)}}
$('closeDetails').onclick=()=>$('itemDetailsDialog').close();$('itemDetailsDialog').addEventListener('click',event=>{if(event.target===$('itemDetailsDialog'))$('itemDetailsDialog').close()});$('editDetailItem').onclick=()=>{if(!activeDetailItem)return;$('itemDetailsDialog').close();setTab('inventory');fillForm(activeDetailItem);$('itemFormCard').scrollIntoView({behavior:'smooth',block:'start'})};$('copyDetailBarcode').onclick=async()=>{if(!activeDetailItem)return;try{await navigator.clipboard.writeText(activeDetailItem.barcode);$('detailsMessage').textContent='Barcode gekopieerd.'}catch(e){let field=document.createElement('textarea');field.value=activeDetailItem.barcode;document.body.appendChild(field);field.select();let copied=false;try{copied=document.execCommand('copy')}catch(_){}field.remove();$('detailsMessage').textContent=copied?'Barcode gekopieerd.':'Kopiëren lukte niet; barcode staat hierboven in Details.'}};
function barcodeSvg(code){let original=String(code||'');let value=original;let left=['0001101','0011001','0010011','0111101','0100011','0110001','0101111','0111011','0110111','0001011'];let right=left.map(x=>[...x].map(b=>b==='1'?'0':'1').join(''));let bits='';if(/^\d{12}$/.test(value))value='0'+value;if(/^\d{13}$/.test(value)){let sum=[...value.slice(0,12)].reduce((a,d,i)=>a+Number(d)*(i%2?3:1),0);if((10-sum%10)%10!==Number(value[12]))return '';let parity=['LLLLLL','LLGLGG','LLGGLG','LLGGGL','LGLLGG','LGGLLG','LGGGLL','LGLGLG','LGLGGL','LGGLGL'][Number(value[0])];bits='101';for(let i=1;i<=6;i++)bits+=(parity[i-1]==='L'?left:right)[Number(value[i])];bits+='01010';for(let i=7;i<=12;i++)bits+=right[Number(value[i])]}else if(/^\d{8}$/.test(value)){let sum=[...value.slice(0,7)].reduce((a,d,i)=>a+Number(d)*(i%2?1:3),0);if((10-sum%10)%10!==Number(value[7]))return '';bits='101'+[...value.slice(0,4)].map(d=>left[Number(d)]).join('')+'01010'+[...value.slice(4)].map(d=>right[Number(d)]).join('')+'101'}else return '';let rects='';for(let i=0;i<bits.length;i++)if(bits[i]==='1')rects+=`<rect x="${i+11}" y="0" width="1" height="70"/>`;return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${bits.length+22} 70" preserveAspectRatio="none" aria-label="${escHtml(original)}"><g fill="#111">${rects}</g></svg>`}
function escHtml(value){return String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
$('printLabels').onclick=()=>{if(!activeDetailItem)return;$('labelItemName').textContent=activeDetailItem.name+' · '+activeDetailItem.barcode;$('labelBoxBarcode').value=activeDetailItem.box_barcode||'';$('labelBoxQty').value=activeDetailItem.units_per_box||1;$('labelDialog').showModal()};$('cancelLabels').onclick=()=>$('labelDialog').close();$('labelKind').onchange=()=>{$('labelBoxQty').disabled=$('labelKind').value==='unit';$('labelBoxBarcode').disabled=$('labelKind').value!=='box-own'};$('labelKind').onchange();
$('doPrintLabels').onclick=async()=>{if(!activeDetailItem)return;let kind=$('labelKind').value;let code=kind==='box-own'?$('labelBoxBarcode').value.trim():activeDetailItem.barcode;let qty=Math.max(1,parseInt($('labelBoxQty').value||'1',10));let copies=Math.min(200,Math.max(1,parseInt($('labelCopies').value||'1',10)));if(kind==='box-own'&&!code){alert('Voer de doosbarcode in.');return}if(kind!=='unit'){try{let boxCode=kind==='box-own'?code:(activeDetailItem.box_barcode||'');let r=await fetch('/api/box-settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:activeDetailItem.id,box_barcode:boxCode,units_per_box:qty})});let d=await r.json();if(!r.ok)throw Error(d.error);activeDetailItem=d.item}catch(e){alert('Doosgegevens niet opgeslagen: '+e.message);return}}let labelType=kind==='unit'?'Los artikel':`Doos · ${qty} stuks`;let svg=barcodeSvg(code);let win=window.open('','_blank');if(!win){alert('Sta pop-ups toe om etiketten af te drukken.');return}let labels=Array.from({length:copies},()=>`<div class="label"><strong>${escHtml(activeDetailItem.name)}</strong>${svg||`<div class="textcode">${escHtml(code)}</div>`}<div>${escHtml(labelType)}</div><small>${escHtml(activeDetailItem.location||'Geen locatie')} · ${escHtml(code)}</small></div>`).join('');win.document.open();win.document.write(`<!doctype html><html lang="nl"><head><meta charset="utf-8"><title>ScanBase etiketten</title><style>@page{margin:5mm}.grid{display:grid;grid-template-columns:repeat(3,62mm);gap:3mm}.label{width:62mm;height:35mm;border:1px dashed #999;padding:2mm;display:flex;flex-direction:column;align-items:center;justify-content:center;overflow:hidden;font:9pt Arial,sans-serif;text-align:center;break-inside:avoid}.label svg{width:90%;height:15mm}.label strong{max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.label small{font-size:7pt}.textcode{font:bold 14pt monospace;letter-spacing:1mm}</style></head><body><div class="grid">${labels}</div></body></html>`);win.document.close();$('labelDialog').close();setTimeout(()=>win.print(),300)};
function exportInventoryCsv(){if(!allInventoryItems.length){alert('Er zijn geen voorraadartikelen om te exporteren.');return}let columns=[['barcode','Barcode'],['alternate_barcodes','Extra barcodes (| gescheiden)'],['box_barcode','Doosbarcode'],['units_per_box','Stuks per doos'],['name','Naam'],['location','Locatie'],['stock_count','Aantal'],['min_stock','Minimumvoorraad'],['is_favorite','Favoriet'],['notes','Notities'],['updated_at','Laatst gewijzigd']];let quote=value=>'"'+String(value??'').replace(/"/g,'""')+'"';let csv='\uFEFF'+[columns.map(column=>quote(column[1])).join(';'),...allInventoryItems.map(item=>columns.map(column=>quote(column[0]==='alternate_barcodes'?(item.alternate_barcodes||[]).filter(code=>code!==item.box_barcode).join('|'):column[0]==='is_favorite'?(item.is_favorite?'Ja':'Nee'):item[column[0]])).join(';'))].join('\r\n');let url=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'}));let link=document.createElement('a');link.href=url;link.download='scanbase-voorraad-'+new Date().toISOString().slice(0,10)+'.csv';document.body.appendChild(link);link.click();link.remove();URL.revokeObjectURL(url)}
function exportLowStockCsv(){let low=allInventoryItems.filter(item=>Number(item.min_stock||0)>0&&Number(item.stock_count??1)<=Number(item.min_stock));if(!low.length){alert('Er zijn geen artikelen onder hun minimumvoorraad.');return}let columns=[['barcode','Barcode'],['name','Naam'],['location','Locatie'],['stock_count','Aantal'],['min_stock','Minimumvoorraad'],['reorder_count','Bijbestellen']];let quote=value=>'"'+String(value??'').replace(/"/g,'""')+'"';let csv='\uFEFF'+[columns.map(column=>quote(column[1])).join(';'),...low.map(item=>columns.map(column=>quote(column[0]==='reorder_count'?Math.max(0,Number(item.min_stock||0)-Number(item.stock_count||0)):item[column[0]])).join(';'))].join('\r\n');let url=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'}));let link=document.createElement('a');link.href=url;link.download='scanbase-aanvullijst-'+new Date().toISOString().slice(0,10)+'.csv';document.body.appendChild(link);link.click();link.remove();URL.revokeObjectURL(url)}
$('exportLowStock').onclick=exportLowStockCsv;$('randomItem').onclick=()=>{if(!allInventoryItems.length){alert('Je voorraad is nog leeg.');return}let item=allInventoryItems[Math.floor(Math.random()*allInventoryItems.length)];openItemDetails(item.id)};
function exportInventoryJson(){if(!allInventoryItems.length){alert('Er zijn geen voorraadartikelen om te back-uppen.');return}let backup={schema_version:2,exported_at:new Date().toISOString(),items:allInventoryItems.map(({barcode,name,location,notes,stock_count,min_stock,is_favorite,alternate_barcodes,box_barcode,units_per_box})=>({barcode,name,location,notes,stock_count,min_stock,is_favorite,alternate_barcodes,box_barcode,units_per_box}))};let url=URL.createObjectURL(new Blob([JSON.stringify(backup,null,2)],{type:'application/json;charset=utf-8'}));let link=document.createElement('a');link.href=url;link.download='scanbase-backup-'+new Date().toISOString().slice(0,10)+'.json';document.body.appendChild(link);link.click();link.remove();URL.revokeObjectURL(url)}
$('exportJson').onclick=exportInventoryJson;$('importJson').onclick=()=>$('importBackupFile').click();$('importBackupFile').onchange=async()=>{let file=$('importBackupFile').files[0];if(!file)return;try{if(file.size>2_000_000)throw Error('Het back-upbestand is groter dan 2 MB.');let backup=JSON.parse(await file.text());if(!Array.isArray(backup.items))throw Error('Dit bestand bevat geen geldige items-lijst.');let incoming=backup.items.map(item=>({barcode:item.barcode,name:item.name,location:item.location||'',notes:item.notes||'',stock_count:item.stock_count??1,min_stock:item.min_stock??0,is_favorite:item.is_favorite||false,alternate_barcodes:item.alternate_barcodes||[],box_barcode:item.box_barcode||'',units_per_box:item.units_per_box||1}));if(incoming.length>10000)throw Error('Maximaal 10.000 artikelen per import.');if(!confirm(`${incoming.length} artikelen gevonden. Nieuwe barcodes toevoegen? Bestaande barcodes worden overgeslagen en niet overschreven.`))return;let response=await fetch('/api/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({items:incoming})});let result=await response.json();if(!response.ok)throw Error(result.error||'Importeren mislukt');await loadInventoryList();alert(`Import voltooid: ${result.added} toegevoegd, ${result.skipped} overgeslagen.`)}catch(error){alert('Back-up niet geïmporteerd: '+error.message)}finally{$('importBackupFile').value=''}};
let pendingCsvItems=[];function parseCsvText(text){text=text.replace(/^\uFEFF/,'');let first=text.split(/\r?\n/,1)[0]||'';let delimiter=(first.match(/;/g)||[]).length>=(first.match(/,/g)||[]).length?';':',';let rows=[],row=[],field='',quoted=false;for(let i=0;i<text.length;i++){let c=text[i];if(c==='"'){if(quoted&&text[i+1]==='"'){field+='"';i++}else quoted=!quoted}else if(c===delimiter&&!quoted){row.push(field);field=''}else if((c==='\n'||c==='\r')&&!quoted){if(c==='\r'&&text[i+1]==='\n')i++;row.push(field);if(row.some(v=>v.trim()))rows.push(row);row=[];field=''}else field+=c}row.push(field);if(row.some(v=>v.trim()))rows.push(row);return rows}
$('importCsv').onclick=()=>$('importCsvFile').click();$('importCsvFile').onchange=async()=>{let file=$('importCsvFile').files[0];if(!file)return;try{if(file.size>1_000_000)throw Error('CSV mag maximaal 1 MB zijn.');let rows=parseCsvText(await file.text());if(rows.length<2)throw Error('CSV heeft geen gegevensregels.');let norm=x=>String(x||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase().replace(/[^a-z0-9]+/g,'');let headers=rows[0].map(norm);let find=(...names)=>names.map(n=>headers.indexOf(norm(n))).find(i=>i>=0);let ix={barcode:find('barcode','ean','isbn','gtin'),name:find('naam','name','product'),location:find('locatie','location'),stock:find('aantal','stock_count','voorraad'),min:find('minimumvoorraad','min_stock'),notes:find('notities','notes'),aliases:find('extra barcodes gescheiden','alternate_barcodes'),box:find('doosbarcode','box_barcode'),units:find('stuks per doos','units_per_box'),favorite:find('favoriet','is_favorite')};if(ix.barcode==null||ix.name==null)throw Error('CSV moet kolommen Barcode/EAN en Naam/Name bevatten.');let parsed=rows.slice(1).map(row=>{let get=i=>i==null?'':String(row[i]||'').trim();return {barcode:get(ix.barcode),name:get(ix.name),location:get(ix.location),notes:get(ix.notes),stock_count:Math.max(0,parseInt(get(ix.stock)||'1',10)||0),min_stock:Math.max(0,parseInt(get(ix.min)||'0',10)||0),alternate_barcodes:get(ix.aliases).split('|').map(x=>x.trim()).filter(Boolean),box_barcode:get(ix.box),units_per_box:Math.max(1,parseInt(get(ix.units)||'1',10)||1),is_favorite:['1','ja','yes','true','waar'].includes(get(ix.favorite).toLowerCase())}}).filter(x=>x.barcode&&x.name);if(parsed.length>10000)throw Error('Maximaal 10.000 regels per import.');let known=new Set(allInventoryItems.flatMap(x=>[x.barcode,...(x.alternate_barcodes||[])]));let newItems=[];let duplicateCount=0;for(const item of parsed){if(known.has(item.barcode)){duplicateCount++;continue}known.add(item.barcode);item.alternate_barcodes=item.alternate_barcodes.filter(code=>!known.has(code));item.alternate_barcodes.forEach(code=>known.add(code));if(item.box_barcode){if(known.has(item.box_barcode)&&item.box_barcode!==item.barcode){item.box_barcode=''}else known.add(item.box_barcode)}newItems.push(item)}pendingCsvItems=newItems;$('csvPreviewSummary').textContent=`${parsed.length} bruikbare regels · ${newItems.length} nieuw · ${duplicateCount} bestaande/duplicaat · ${rows.length-1-parsed.length} onvolledig overgeslagen. Controleer hieronder de nieuwe artikelen.`;let root=$('csvPreviewRows');root.replaceChildren();for(const item of newItems.slice(0,50)){let line=document.createElement('div');line.className='tool-row';line.textContent=`${item.name} · ${item.barcode} · ${item.location||'Geen locatie'} · aantal ${item.stock_count}`;root.appendChild(line)}if(newItems.length>50){let line=document.createElement('div');line.className='hint';line.textContent=`… en nog ${newItems.length-50} regels`;root.appendChild(line)}$('confirmCsvImport').disabled=!newItems.length;$('csvPreviewDialog').showModal()}catch(e){alert('CSV-import mislukt: '+e.message)}finally{$('importCsvFile').value=''}};
$('cancelCsvImport').onclick=()=>$('csvPreviewDialog').close();$('confirmCsvImport').onclick=async()=>{try{let r=await fetch('/api/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({items:pendingCsvItems})});let d=await r.json();if(!r.ok)throw Error(d.error);$('csvPreviewDialog').close();await loadInventoryList();alert(`Import klaar: ${d.added} toegevoegd, ${d.skipped} overgeslagen.`)}catch(e){alert(e.message)}};
$('inventoryListSearch').addEventListener('input',renderInventoryList);$('inventoryLocationFilter').addEventListener('change',renderInventoryList);$('inventoryStockFilter').addEventListener('change',renderInventoryList);$('inventoryFavoriteFilter').addEventListener('change',renderInventoryList);$('inventorySort').addEventListener('change',renderInventoryList);$('refreshInventory').onclick=loadInventoryList;$('exportCsv').onclick=exportInventoryCsv;
$('search').addEventListener('input',()=>{clearTimeout(searchTimer);let q=$('search').value.trim();if(!q){$('results').innerHTML='<div class="empty">Typ om artikelen te zoeken.</div>';return}searchTimer=setTimeout(async()=>{try{let d=await (await fetch('/api/search?q='+encodeURIComponent(q))).json();showResults(d.items)}catch(e){}},220)});
$('save').onclick=async()=>{let payload={id:$('itemId').value||null,barcode:$('barcode').value.trim(),name:$('name').value.trim(),location:$('location').value.trim(),alternate_barcodes:$('alternateBarcodes').value.split(/[\n,;]+/).map(x=>x.trim()).filter(Boolean),box_barcode:$('boxBarcode').value.trim(),units_per_box:$('unitsPerBox').value,stock_count:$('stockCount').value,min_stock:$('minStock').value,notes:$('notes').value.trim()};let photoToSave=selectedPhoto;try{let r=await fetch('/api/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});let d=await r.json();if(!r.ok)throw Error(d.error||'Opslaan mislukt');if(photoToSave){let pr=await fetch('/api/photo',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:d.item.id,data:photoToSave})});let pd=await pr.json();if(!pr.ok)throw Error(pd.error||'Artikel opgeslagen, maar foto uploaden is mislukt')}fillForm(d.item);$('lastScan').textContent=d.item.barcode;setMessage('Opgeslagen. Naam en locatie staan nu bovenaan bij Scanner.');loadInventoryList();if($('search').value.trim())$('search').dispatchEvent(new Event('input'))}catch(e){setMessage(e.message)}};
$('itemPhoto').onchange=()=>{let file=$('itemPhoto').files[0];if(!file){selectedPhoto=null;return}if(file.size>10_000_000){alert('Kies een foto kleiner dan 10 MB.');$('itemPhoto').value='';return}let url=URL.createObjectURL(file);let image=new Image();image.onload=()=>{let scale=Math.min(1,1000/Math.max(image.width,image.height));let canvas=document.createElement('canvas');canvas.width=Math.round(image.width*scale);canvas.height=Math.round(image.height*scale);canvas.getContext('2d').drawImage(image,0,0,canvas.width,canvas.height);selectedPhoto=canvas.toDataURL('image/jpeg',0.78);$('photoPreview').src=selectedPhoto;$('photoPreview').hidden=false;URL.revokeObjectURL(url)};image.onerror=()=>{URL.revokeObjectURL(url);alert('Foto kon niet worden geopend.')} ;image.src=url};
$('clear').onclick=clearForm;
$('delete').onclick=async()=>{if(!confirm('Dit artikel verwijderen?'))return;try{let r=await fetch('/api/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:$('itemId').value})});let d=await r.json();if(!r.ok)throw Error(d.error||'Verwijderen mislukt');clearForm();setMessage('Artikel verwijderd.');loadInventoryList();if($('search').value.trim())$('search').dispatchEvent(new Event('input'))}catch(e){setMessage(e.message)}};
function addLink(container,label,url){let a=document.createElement('a');a.textContent=label;a.href=url;a.target='_blank';a.rel='noopener noreferrer';container.appendChild(a)}
function catalogQueryLinks(item){let q=(item.name?item.name+' ':'')+item.barcode;let encoded=encodeURIComponent(q);let googleSite=site=> 'https://www.google.com/search?q='+encodeURIComponent('site:'+site+' '+q);return {google:'https://www.google.com/search?tbm=shop&q='+encoded,web:'https://www.google.com/search?q='+encoded,bol:'https://www.bol.com/nl/nl/s/?searchtext='+encoded,amazon:'https://www.amazon.nl/s?k='+encoded,marktplaats:'https://www.marktplaats.nl/q/'+encoded+'/',action:googleSite('action.com/nl-nl/p'),lidl:googleSite('lidl.nl/p'),vandijk:googleSite('vandijk.nl'),studystore:googleSite('studystore.nl'),deslegte:googleSite('deslegte.com'),bookmatch:googleSite('bookmatch.nl'),bruna:googleSite('bruna.nl'),discogs:'https://www.discogs.com/search/?q='+encoded+'&type=all'}}
function renderCatalogItem(item,locations=[],existingItem=null){let root=$('catalogResult');root.replaceChildren();let h=document.createElement('h3');h.textContent=item.found?item.name:'Niet gevonden in openbare catalogi';root.appendChild(h);if(item.image_url&&item.found){let img=document.createElement('img');img.className='product-image';img.src=item.image_url;img.alt=item.name;img.referrerPolicy='no-referrer';root.appendChild(img)}if(item.found){if(item.brand)root.appendChild(Object.assign(document.createElement('p'),{textContent:'Merk/auteur: '+item.brand}));if(item.category)root.appendChild(Object.assign(document.createElement('p'),{textContent:'Categorie: '+item.category}));if(item.quantity)root.appendChild(Object.assign(document.createElement('p'),{textContent:'Inhoud/maat: '+item.quantity}));if(item.description)root.appendChild(Object.assign(document.createElement('p'),{textContent:item.description}));let source=document.createElement('p');source.textContent='Bron: '+(item.source||'openbare database')+(item.cached?' (opgeslagen zoekresultaat)':'');root.appendChild(source);if(item.source_url)addLink(root,'Bekijk bron',item.source_url)}else{let p=document.createElement('p');p.textContent='De barcode is niet gevonden in de openbare productdatabases. Je kunt de winkelzoeklinks hieronder proberen of het artikel handmatig aan je voorraad toevoegen.';root.appendChild(p);if(item.lookup_error){let e=document.createElement('p');e.className='catalog-message';e.textContent='Niet alle online bronnen waren bereikbaar.';root.appendChild(e)}let retry=document.createElement('button');retry.type='button';retry.textContent='Opnieuw zoeken in catalogi';retry.title='Slaat de lokale zoekcache over';retry.onclick=()=>lookupOnline(item.barcode,true);root.appendChild(retry)}
let links=document.createElement('div');links.className='buy-links';let urls=catalogQueryLinks(item);addLink(links,'Google Shopping',urls.google);addLink(links,'Google zoeken',urls.web);addLink(links,'Bol.com',urls.bol);addLink(links,'Amazon.nl',urls.amazon);addLink(links,'Action',urls.action);addLink(links,'Lidl',urls.lidl);addLink(links,'VanDijk schoolboeken',urls.vandijk);addLink(links,'StudyStore studieboeken',urls.studystore);addLink(links,'Marktplaats',urls.marktplaats);addLink(links,'De Slegte',urls.deslegte);addLink(links,'Bookmatch',urls.bookmatch);addLink(links,'Bruna',urls.bruna);addLink(links,'Discogs (muziek)',urls.discogs);root.appendChild(links);if(item.offers&&item.offers.length){let offersTitle=document.createElement('h4');offersTitle.textContent='Mogelijke aanbieders (via UPCitemdb)';root.appendChild(offersTitle);for(const offer of item.offers){let row=document.createElement('p');let price=offer.price?(' — '+offer.price+(offer.currency?' '+offer.currency:' (valuta onbekend)')):'';let shipping=offer.shipping?(' · verzending '+offer.shipping):'';row.textContent=(offer.merchant||'Winkel')+price+shipping+(offer.availability?' · '+offer.availability:'');root.appendChild(row);if(offer.link)addLink(root,'Bekijk bij '+(offer.merchant||'winkel'),offer.link)}let note=document.createElement('p');note.className='catalog-message';note.textContent='Aanbiedingen kunnen verouderd zijn; controleer prijs en voorraad bij de winkel.';root.appendChild(note)}
let form=document.createElement(item.found?'dialog':'div');form.className='catalog-form';let prompt=document.createElement('h4');prompt.textContent=item.found?(existingItem?'Dit artikel staat al in je voorraad. Wil je de gegevens wijzigen?':'Product gevonden. Wil je het opslaan in Mijn voorraad?'):'Niet online gevonden. Wil je het zelf aan Mijn voorraad toevoegen?';let nameLabel=document.createElement('label');nameLabel.textContent='Naam (aanpasbaar)';let name=document.createElement('input');name.value=existingItem?.name||item.name||'';name.placeholder='Vul zelf een naam in';let locLabel=document.createElement('label');locLabel.textContent='Welke locatie?';let location=document.createElement('select');let noLocation=document.createElement('option');noLocation.value='';noLocation.textContent='Geen locatie';location.appendChild(noLocation);let locationValues=[...new Set([...(locations||[]),existingItem?.location||''].filter(Boolean))];for(const place of locationValues){let option=document.createElement('option');option.value=place;option.textContent=place;location.appendChild(option)}let newLocationOption=document.createElement('option');newLocationOption.value='__new__';newLocationOption.textContent='Nieuwe locatie invoeren…';location.appendChild(newLocationOption);if(existingItem?.location)location.value=existingItem.location;let customLocation=document.createElement('input');customLocation.placeholder='Typ de nieuwe locatie';customLocation.hidden=true;location.onchange=()=>{customLocation.hidden=location.value!=='__new__';if(!customLocation.hidden)customLocation.focus()};let stockLabel=document.createElement('label');stockLabel.textContent='Aantal op voorraad';let stockCount=document.createElement('input');stockCount.type='number';stockCount.min='0';stockCount.step='1';stockCount.value=existingItem?.stock_count??1;let minLabel=document.createElement('label');minLabel.textContent='Waarschuw bij dit aantal of lager (0 = uit)';let minStock=document.createElement('input');minStock.type='number';minStock.min='0';minStock.step='1';minStock.value=existingItem?.min_stock??0;let noteLabel=document.createElement('label');noteLabel.textContent='Notities';let notes=document.createElement('textarea');notes.value=existingItem?.notes||[item.source?'Bron: '+item.source:'',item.brand,item.category,item.quantity,item.description].filter(Boolean).join(' · ');let buttons=document.createElement('div');buttons.className='buttons';let save=document.createElement('button');save.className='primary';save.textContent=existingItem?'Opslaan van wijzigingen':item.found?'Ja, opslaan in Mijn voorraad':'Handmatig toevoegen';let skip=document.createElement('button');skip.textContent='Nee, niet opslaan';let msg=document.createElement('p');msg.className='catalog-message';save.onclick=async()=>{if(!name.value.trim()){msg.textContent='Vul eerst een naam in.';return}let chosenLocation=location.value==='__new__'?customLocation.value.trim():location.value;if(location.value==='__new__'&&!chosenLocation){msg.textContent='Typ een locatie of kies “Geen locatie”.';return}try{let response=await fetch('/api/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:existingItem?.id||null,barcode:item.barcode,name:name.value.trim(),location:chosenLocation,stock_count:stockCount.value,min_stock:minStock.value,notes:notes.value.trim()})});let data=await response.json();if(!response.ok)throw Error(data.error||'Opslaan mislukt');if(form instanceof HTMLDialogElement&&form.open)form.close();setTab('inventory');$('lastScan').textContent=data.item.barcode;fillForm(data.item);setMessage('Opgeslagen vanuit de algemene database.');loadInventoryList()}catch(e){msg.textContent=e.message}};skip.onclick=()=>{if(item.found){form.close();let notice=document.createElement('p');notice.className='catalog-message';notice.textContent='Niet opgeslagen in Mijn voorraad; het resultaat blijft alleen in de online zoekgeschiedenis.';root.insertBefore(notice,root.firstChild)}else{msg.textContent='Niet toegevoegd aan Mijn voorraad.'}};form.append(prompt,nameLabel,name,locLabel,location,customLocation,stockLabel,stockCount,minLabel,minStock,noteLabel,notes,buttons,msg);buttons.append(save,skip);root.appendChild(form);if(item.found)form.showModal()}
async function lookupOnline(code,force=false){code=(code||'').trim();if(!code)return;$('catalogBarcode').value=code;$('catalogResult').textContent='Zoeken in openbare databases…';setTab('catalog');try{let url='/api/lookup?barcode='+encodeURIComponent(code)+(force?'&refresh=1':'');let response=await fetch(url);let data=await response.json();if(!response.ok)throw Error(data.error||'Zoeken mislukt');renderCatalogItem(data.item,data.locations||[],data.existing_item||null);loadCatalogRecent()}catch(e){$('catalogResult').textContent='Online zoeken mislukt: '+e.message}}
$('catalogLookup').onclick=()=>lookupOnline($('catalogBarcode').value);$('catalogBarcode').addEventListener('keydown',e=>{if(e.key==='Enter')lookupOnline($('catalogBarcode').value)});
function renderRecentCatalog(items){let root=$('catalogRecent');root.replaceChildren();if(!items.length){root.innerHTML='<div class="empty">Nog geen online zoekopdrachten.</div>';return}for(const item of items){let b=document.createElement('button');b.className='recent-row';b.textContent=(item.name||'Onbekend product')+' · '+item.barcode;b.onclick=async()=>{setTab('catalog');$('catalogBarcode').value=item.barcode;try{let [loc,stock]=await Promise.all([fetch('/api/locations').then(r=>r.json()),fetch('/api/by-barcode?code='+encodeURIComponent(item.barcode)).then(r=>r.json())]);renderCatalogItem(item,loc.locations||[],stock.item||null)}catch(e){renderCatalogItem(item)}};root.appendChild(b)}}
async function loadCatalogRecent(){try{let q=$('catalogSearch').value.trim();let url=q?'/api/catalog/search?q='+encodeURIComponent(q):'/api/catalog/recent';let d=await(await fetch(url)).json();renderRecentCatalog(d.items||[])}catch(e){}}
$('catalogSearch').addEventListener('input',()=>{clearTimeout(catalogTimer);catalogTimer=setTimeout(loadCatalogRecent,200)});
$('tabInventory').onclick=()=>setTab('inventory');$('tabCatalog').onclick=()=>setTab('catalog');
pollScans();refreshStatus();loadInventoryList();loadScanHistory();loadStocktake();loadScanMode();
</script></body></html>'''


def make_server():
    return ThreadingHTTPServer(("0.0.0.0", PORT), Handler)


def main():
    init_db()
    worker = None
    if SCANNER_MODE == "external":
        set_scanner_status("waiting", "Wacht op scannerbrug op de NAS")
    else:
        worker = threading.Thread(target=scanner_worker, name="usb-hid-reader", daemon=True)
        worker.start()
    server = make_server()

    def request_stop(signum, frame):
        stop_event.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    print(f"ScanBase draait op 0.0.0.0:{PORT} (scanner_mode={SCANNER_MODE})", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        if worker:
            stop_usb_reader()
            worker.join(timeout=8)
        server.server_close()
        print("ScanBase gestopt", flush=True)


if __name__ == "__main__":
    main()
