#!/usr/bin/env python3
"""Small Synology inventory web app with a raw USB-HID scanner reader.

The USB reader uses Linux usbfs directly (ctypes + USBDEVFS URBs), so it has
no pip dependencies. It temporarily unbinds only the scanner's keyboard
interface and attempts to rebind it on shutdown.
"""

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
LOOKUP_VERSION = 3
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
    with scan_lock:
        scan_counter += 1
        scan_events.append({"id": scan_counter, "code": code,
                            "time": datetime.now(timezone.utc).isoformat()})
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
    with db_session() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            barcode TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            location TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_items_name ON items(name)")
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


def get_item_by_barcode(code):
    with DB_LOCK, db_session() as conn:
        row = conn.execute("SELECT * FROM items WHERE barcode=?", (code,)).fetchone()
        return row_to_dict(row)


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
    """Look up ISBNs in Google Books, which often indexes school editions."""
    query = urlencode({"q": "isbn:" + barcode, "maxResults": "5"})
    request = Request("https://www.googleapis.com/books/v1/volumes?" + query,
                      headers={"Accept": "application/json",
                               "User-Agent": "ScanBase/1.4 barcode inventory"})
    with urlopen(request, timeout=7) as response:
        payload = json.loads(response.read(1_000_000).decode("utf-8"))
    for result in payload.get("items", []):
        info = result.get("volumeInfo") or {}
        identifiers = {str(identifier.get("identifier", "")).replace("-", "")
                       for identifier in info.get("industryIdentifiers", [])}
        if barcode not in identifiers or not info.get("title"):
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
    # Prefer the national source for Dutch ISBNs before spending a general UPC lookup.
    if len(barcode) == 13 and barcode.startswith(("97890", "97894")):
        try:
            item = fetch_kb_nbt_book(barcode)
            if item:
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

    # MusicBrainz is a specialist barcode source for CD editions, not ISBNs.
    if barcode.isdigit() and 8 <= len(barcode) <= 14 and not (
            len(barcode) == 13 and barcode.startswith(("978", "979"))):
        try:
            item = fetch_musicbrainz_release(barcode)
            if item:
                save_catalog_result(item)
                return item
        except Exception as exc:
            errors.append(f"MusicBrainz: {type(exc).__name__}")

    # ISBNs may be school editions; Google Books often has publisher/edition details.
    if len(barcode) in (10, 13) and (barcode.startswith("978") or barcode.startswith("979") or len(barcode) == 10):
        try:
            item = fetch_google_book(barcode)
            if item:
                save_catalog_result(item)
                return item
        except Exception as exc:
            errors.append(f"Google Books: {type(exc).__name__}")

        # Open Library is a second independent ISBN fallback.
        try:
            url = "https://openlibrary.org/api/books?" + urlencode({

                "bibkeys": "ISBN:" + barcode, "format": "json", "jscmd": "data"})
            request = Request(url, headers={"User-Agent": "ScanBase/1.2 (barcode inventory; read-only lookup)"})
            with urlopen(request, timeout=5) as response:
                payload = json.loads(response.read(1_000_000).decode("utf-8"))
            book = payload.get("ISBN:" + barcode)
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
        if size > 100_000:
            raise ValueError("Aanvraag te groot")
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
        if parsed.path == "/api/search":
            q = params.get("q", [""])[0].strip()
            if not q:
                self.send_json({"items": []})
                return
            like = f"%{q}%"
            with DB_LOCK, db_session() as conn:
                rows = conn.execute("""SELECT * FROM items
                    WHERE barcode LIKE ? OR name LIKE ? OR location LIKE ? OR notes LIKE ?
                    ORDER BY name COLLATE NOCASE LIMIT 60""", (like, like, like, like)).fetchall()
            self.send_json({"items": [row_to_dict(r) for r in rows]})
            return
        if parsed.path == "/api/item":
            try:
                item_id = int(params.get("id", [""])[0])
            except ValueError:
                self.send_json({"error": "Ongeldig ID"}, 400)
                return
            with DB_LOCK, db_session() as conn:
                row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                self.send_json({"error": "Niet gevonden"}, 404)
            else:
                self.send_json({"item": row_to_dict(row)})
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
            item = lookup_online(code)
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
        if parsed.path == "/api/save":
            barcode = str(data.get("barcode", "")).strip()
            name = str(data.get("name", "")).strip()
            location = str(data.get("location", "")).strip()
            notes = str(data.get("notes", "")).strip()
            item_id = data.get("id")
            if not barcode or not name:
                self.send_json({"error": "Barcode en naam zijn verplicht"}, 400)
                return
            try:
                with DB_LOCK, db_session() as conn:
                    if item_id:
                        conn.execute("""UPDATE items SET barcode=?, name=?, location=?, notes=?,
                            updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                            (barcode, name, location, notes, int(item_id)))
                        row = conn.execute("SELECT * FROM items WHERE id=?", (int(item_id),)).fetchone()
                    else:
                        conn.execute("""INSERT INTO items(barcode,name,location,notes)
                            VALUES(?,?,?,?) ON CONFLICT(barcode) DO UPDATE SET
                            name=excluded.name, location=excluded.location, notes=excluded.notes,
                            updated_at=CURRENT_TIMESTAMP""", (barcode, name, location, notes))
                        row = conn.execute("SELECT * FROM items WHERE barcode=?", (barcode,)).fetchone()
                self.send_json({"item": row_to_dict(row)})
            except sqlite3.IntegrityError as exc:
                self.send_json({"error": f"Barcode bestaat al: {exc}"}, 409)
            except (ValueError, TypeError) as exc:
                self.send_json({"error": str(exc)}, 400)
            return
        if parsed.path == "/api/delete":
            try:
                item_id = int(data.get("id"))
            except (TypeError, ValueError):
                self.send_json({"error": "Ongeldig ID"}, 400)
                return
            with DB_LOCK, db_session() as conn:
                conn.execute("DELETE FROM items WHERE id=?", (item_id,))
            self.send_json({"ok": True})
            return
        self.send_json({"error": "Niet gevonden"}, 404)


PAGE = r'''<!doctype html>
<html lang="nl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ScanBase — voorraad</title><style>
:root{font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#eaf0ff;background:#0b1020;--panel:#151d33;--line:#283451;--muted:#a4b0ca;--accent:#73e0c1;--blue:#6da8ff}
*{box-sizing:border-box}body{margin:0}header{padding:22px max(20px,calc((100% - 1100px)/2));display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);background:#10172a;gap:14px}h1{font-size:22px;margin:0}header p{margin:4px 0 0;color:var(--muted);font-size:13px}.header-actions{display:flex;align-items:center;gap:9px;flex-wrap:wrap}.online-shortcut{background:#183d42;color:var(--accent);border:1px solid #286956;padding:8px 12px;border-radius:999px}.status{font-size:13px;padding:8px 12px;border:1px solid var(--line);border-radius:999px;color:var(--muted)}.status.ready{color:var(--accent);border-color:#286956}.status.error{color:#ff9292;border-color:#8c3b46}.tabbar{max-width:1100px;margin:18px auto 0;padding:0 18px;display:flex;gap:10px}.tabbutton{background:transparent;border:1px solid var(--line);color:var(--muted)}.tabbutton.active{background:#203653;color:var(--accent);border-color:#3b6e7f}.catalog-grid{max-width:1100px;margin:24px auto;padding:0 18px;display:grid;grid-template-columns:1fr 1fr;gap:18px}.searchrow{display:flex;gap:10px}.searchrow input{flex:1}.catalog-result{margin-top:16px;padding:16px;border:1px solid var(--line);border-radius:12px;background:#101a30}.catalog-result h3{margin:0 0 8px;font-size:20px}.catalog-result p{color:var(--muted);margin:6px 0}.product-image{max-width:140px;max-height:140px;object-fit:contain;float:right;margin:0 0 10px 14px;border-radius:8px}.buy-links{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}.buy-links a{display:inline-block;padding:8px 11px;background:#263653;border-radius:8px;color:#cfe3ff;text-decoration:none}.recent-row{width:100%;text-align:left;padding:11px;border:1px solid var(--line);background:#111a2e;border-radius:9px;color:#edf3ff;margin:5px 0}.catalog-form{border-top:1px solid var(--line);margin-top:15px;padding-top:12px}dialog.catalog-form{width:min(560px,calc(100vw - 32px));max-height:90vh;overflow:auto;margin:auto;padding:22px;background:#151d33;color:#eaf0ff;border:1px solid #3b6e7f;border-radius:16px;box-shadow:0 24px 70px #000a}dialog.catalog-form::backdrop{background:#000b;backdrop-filter:blur(3px)}.catalog-message{color:var(--muted);font-size:13px;margin-top:8px}@media(max-width:760px){.catalog-grid{grid-template-columns:1fr}.searchrow{flex-direction:column}}
main{max-width:1100px;margin:24px auto;padding:0 18px;display:grid;grid-template-columns:1fr 1fr;gap:18px}.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px;box-shadow:0 10px 30px #0002}.card h2{font-size:17px;margin:0 0 16px}.wide{grid-column:1/-1}.scanbox{padding:14px;border-radius:12px;background:#0f1830;border:1px solid #273858;margin-bottom:12px}.scanbox small{color:var(--muted)}#lastScan{font-size:23px;font-weight:700;margin-top:4px;word-break:break-all;color:var(--accent)}.scan-details{padding:13px 14px;border:1px solid var(--line);border-radius:12px;background:#111a2e;min-height:68px}.scan-details strong{display:block;font-size:18px}.scan-details span{display:block;color:var(--muted);margin-top:5px}.scan-details.empty{color:var(--muted)}label{display:block;font-size:13px;color:var(--muted);margin:13px 0 6px}input,textarea,select{font:inherit;width:100%;padding:11px 12px;border-radius:9px;border:1px solid #364461;background:#0e1527;color:#f5f7ff;outline:none}input:focus,textarea:focus{border-color:var(--blue);box-shadow:0 0 0 3px #6da8ff22}textarea{min-height:85px;resize:vertical}.buttons{display:flex;gap:9px;flex-wrap:wrap;margin-top:16px}button{font:inherit;border:0;border-radius:9px;padding:10px 14px;cursor:pointer;background:#283653;color:#edf3ff}button.primary{background:#69d8b6;color:#071b18;font-weight:700}button.danger{background:#492632;color:#ffb5b5}button:hover{filter:brightness(1.12)}.results{display:grid;gap:8px;margin-top:12px}.result{width:100%;text-align:left;padding:12px;border:1px solid var(--line);background:#111a2e}.result strong{display:block}.result span{display:block;color:var(--muted);font-size:13px;margin-top:3px}.hint,#message{color:var(--muted);font-size:13px}.empty{padding:14px;color:var(--muted);font-size:14px}.footer{max-width:1100px;margin:0 auto 25px;padding:0 18px;color:#7e8ba8;font-size:12px}@media(max-width:760px){main{grid-template-columns:1fr}.wide{grid-column:auto}header{align-items:flex-start;flex-direction:column}}
</style></head><body>
<header><div><h1>ScanBase</h1><p>Voorraad, barcodes en locaties</p></div><div class="header-actions"><button id="headerOnline" class="online-shortcut" type="button">Online zoeken</button><div id="status" class="status">Scanner verbinden…</div></div></header>
<nav class="tabbar"><button id="tabInventory" class="tabbutton active" type="button">Mijn voorraad</button><button id="tabCatalog" class="tabbutton" type="button">Algemene database</button></nav>
<main id="inventoryView"><section class="card"><h2>Scanner</h2><div class="scanbox"><small>Laatste scan</small><div id="lastScan">Nog niets gescand</div></div><div id="scanDetails" class="scan-details empty">Na een scan zie je hier de naam en locatie.</div><p class="hint">Bekende artikelen worden getoond; onbekende codes kun je hieronder toevoegen.</p></section>
<section class="card"><h2>Zoeken</h2><label for="search">Zoek op naam, barcode, locatie of notitie</label><input id="search" autocomplete="off" placeholder="Bijvoorbeeld: boormachine of kast A2"><div id="results" class="results"><div class="empty">Typ om artikelen te zoeken.</div></div></section>
<section class="card wide"><h2 id="formTitle">Artikel toevoegen of wijzigen</h2><input type="hidden" id="itemId"><label for="barcode">Barcode</label><input id="barcode" autocomplete="off" placeholder="Scan of typ een barcode"><label for="name">Naam</label><input id="name" autocomplete="off" placeholder="Bijvoorbeeld: accuboormachine"><label for="location">Locatie</label><input id="location" autocomplete="off" placeholder="Bijvoorbeeld: schuur, kast A2"><label for="notes">Notities</label><textarea id="notes" placeholder="Extra informatie (optioneel)"></textarea><div class="buttons"><button class="primary" id="save">Opslaan</button><button id="clear">Leegmaken</button><button class="danger" id="delete" hidden>Verwijderen</button></div><p id="message" role="status"></p></section></main>
<main id="catalogView" class="catalog-grid" hidden><section class="card"><h2>Algemene productdatabase</h2><p class="hint">Zoek een barcode in openbare productdatabases. De dekking verschilt per productsoort.</p><label for="catalogBarcode">Barcode</label><div class="searchrow"><input id="catalogBarcode" autocomplete="off" placeholder="Scan of typ EAN/UPC/ISBN"><button class="primary" id="catalogLookup" type="button">Zoek online</button></div><div id="catalogResult" class="catalog-result"><p>Voer een barcode in of scan een onbekend artikel.</p></div></section><section class="card"><h2>Recent online opgezocht</h2><label for="catalogSearch">Zoek in je online zoekgeschiedenis</label><input id="catalogSearch" autocomplete="off" placeholder="Naam, merk of barcode"><div id="catalogRecent" class="results"><div class="empty">Nog geen online zoekopdrachten.</div></div><p class="hint">Dit is de lokale geschiedenis van opgezochte codes, niet een volledige kopie van internet.</p></section></main>
<div class="footer">Persoonlijke voorraad blijft apart van online productinformatie. Online resultaten komen uit openbare databases; winkelknoppen openen zoekpagina's.</div>
<script>
const $=id=>document.getElementById(id);let lastId=0;let searchTimer;let catalogTimer;
function setMessage(t){$('message').textContent=t||''}
function setTab(name){const inventory=name==='inventory';$('inventoryView').hidden=!inventory;$('catalogView').hidden=inventory;$('tabInventory').classList.toggle('active',inventory);$('tabCatalog').classList.toggle('active',!inventory);if(!inventory)loadCatalogRecent()}
$('headerOnline').onclick=()=>{setTab('catalog');$('catalogBarcode').focus()};
function showScanDetails(item,code=''){const root=$('scanDetails');root.replaceChildren();if(item){root.className='scan-details';const title=document.createElement('strong');title.textContent=item.name||'Naam ontbreekt';const location=document.createElement('span');location.textContent='Locatie: '+(item.location||'Nog geen locatie ingevuld');root.append(title,location);return}root.className='scan-details empty';const title=document.createElement('strong');title.textContent=code?'Nog niet opgeslagen':'Na een scan zie je hier de naam en locatie.';const detail=document.createElement('span');detail.textContent=code?'Barcode: '+code:'';root.append(title,detail)}
function clearForm(){ $('itemId').value='';$('barcode').value='';$('name').value='';$('location').value='';$('notes').value='';$('formTitle').textContent='Artikel toevoegen of wijzigen';$('delete').hidden=true;setMessage('') }
function fillForm(item){$('itemId').value=item?.id||'';$('barcode').value=item?.barcode||'';$('name').value=item?.name||'';$('location').value=item?.location||'';$('notes').value=item?.notes||'';$('formTitle').textContent=item?.id?'Artikel wijzigen':'Nieuw artikel';$('delete').hidden=!item?.id;setMessage(item?.id?'Artikel geladen.':'Onbekende barcode — vul een naam en locatie in.');showScanDetails(item?.id?item:null,item?.barcode||'')}
async function loadByBarcode(code){$('lastScan').textContent=code;try{let r=await fetch('/api/by-barcode?code='+encodeURIComponent(code));let d=await r.json();if(d.item){setTab('inventory');fillForm(d.item)}else{setTab('catalog');$('catalogBarcode').value=code;fillForm({barcode:code});await lookupOnline(code)}}catch(e){setTab('inventory');fillForm({barcode:code});setMessage('Kon artikel niet laden: '+e.message)}}
async function pollScans(){try{let d=await (await fetch('/api/scans?after='+lastId)).json();for(const s of d.scans){lastId=s.id;await loadByBarcode(s.code)}}catch(e){}setTimeout(pollScans,500)}
async function refreshStatus(){try{let d=await (await fetch('/api/status')).json(),s=d.scanner;$('status').textContent=s.message;$('status').className='status '+(s.state==='ready'?'ready':s.state==='error'?'error':'')}catch(e){$('status').textContent='Verbinding met NAS mislukt'}setTimeout(refreshStatus,2000)}
function showResults(items){let root=$('results');root.replaceChildren();if(!items.length){root.innerHTML='<div class="empty">Geen artikelen gevonden.</div>';return}for(const item of items){let b=document.createElement('button');b.className='result';let strong=document.createElement('strong');strong.textContent=item.name;let span=document.createElement('span');span.textContent=(item.location||'Geen locatie')+' · '+item.barcode;b.append(strong,span);b.onclick=()=>fillForm(item);root.appendChild(b)}}
$('search').addEventListener('input',()=>{clearTimeout(searchTimer);let q=$('search').value.trim();if(!q){$('results').innerHTML='<div class="empty">Typ om artikelen te zoeken.</div>';return}searchTimer=setTimeout(async()=>{try{let d=await (await fetch('/api/search?q='+encodeURIComponent(q))).json();showResults(d.items)}catch(e){}},220)});
$('save').onclick=async()=>{let payload={id:$('itemId').value||null,barcode:$('barcode').value.trim(),name:$('name').value.trim(),location:$('location').value.trim(),notes:$('notes').value.trim()};try{let r=await fetch('/api/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});let d=await r.json();if(!r.ok)throw Error(d.error||'Opslaan mislukt');fillForm(d.item);$('lastScan').textContent=d.item.barcode;setMessage('Opgeslagen. Naam en locatie staan nu bovenaan bij Scanner.');if($('search').value.trim())$('search').dispatchEvent(new Event('input'))}catch(e){setMessage(e.message)}};
$('clear').onclick=clearForm;
$('delete').onclick=async()=>{if(!confirm('Dit artikel verwijderen?'))return;try{let r=await fetch('/api/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:$('itemId').value})});let d=await r.json();if(!r.ok)throw Error(d.error||'Verwijderen mislukt');clearForm();setMessage('Artikel verwijderd.');if($('search').value.trim())$('search').dispatchEvent(new Event('input'))}catch(e){setMessage(e.message)}};
function addLink(container,label,url){let a=document.createElement('a');a.textContent=label;a.href=url;a.target='_blank';a.rel='noopener noreferrer';container.appendChild(a)}
function catalogQueryLinks(item){let q=(item.name?item.name+' ':'')+item.barcode;let encoded=encodeURIComponent(q);return {google:'https://www.google.com/search?tbm=shop&q='+encoded,web:'https://www.google.com/search?q='+encoded,bol:'https://www.bol.com/nl/nl/s/?searchtext='+encoded,amazon:'https://www.amazon.nl/s?k='+encoded,marktplaats:'https://www.marktplaats.nl/q/'+encoded+'/',deslegte:'https://www.google.com/search?q='+encodeURIComponent('site:deslegte.com '+q),bookmatch:'https://www.google.com/search?q='+encodeURIComponent('site:bookmatch.nl '+q),bruna:'https://www.google.com/search?q='+encodeURIComponent('site:bruna.nl '+q),discogs:'https://www.discogs.com/search/?q='+encoded+'&type=all'}}
function renderCatalogItem(item,locations=[],existingItem=null){let root=$('catalogResult');root.replaceChildren();let h=document.createElement('h3');h.textContent=item.found?item.name:'Niet gevonden in openbare catalogi';root.appendChild(h);if(item.image_url&&item.found){let img=document.createElement('img');img.className='product-image';img.src=item.image_url;img.alt=item.name;img.referrerPolicy='no-referrer';root.appendChild(img)}if(item.found){if(item.brand)root.appendChild(Object.assign(document.createElement('p'),{textContent:'Merk/auteur: '+item.brand}));if(item.category)root.appendChild(Object.assign(document.createElement('p'),{textContent:'Categorie: '+item.category}));if(item.quantity)root.appendChild(Object.assign(document.createElement('p'),{textContent:'Inhoud/maat: '+item.quantity}));if(item.description)root.appendChild(Object.assign(document.createElement('p'),{textContent:item.description}));let source=document.createElement('p');source.textContent='Bron: '+(item.source||'openbare database')+(item.cached?' (opgeslagen zoekresultaat)':'');root.appendChild(source);if(item.source_url)addLink(root,'Bekijk bron',item.source_url)}else{let p=document.createElement('p');p.textContent='De barcode is niet gevonden in de openbare productdatabases. Je kunt de winkelzoeklinks hieronder proberen of het artikel handmatig aan je voorraad toevoegen.';root.appendChild(p);if(item.lookup_error){let e=document.createElement('p');e.className='catalog-message';e.textContent='Niet alle online bronnen waren bereikbaar.';root.appendChild(e)}}
let links=document.createElement('div');links.className='buy-links';let urls=catalogQueryLinks(item);addLink(links,'Google Shopping',urls.google);addLink(links,'Google zoeken',urls.web);addLink(links,'Bol.com',urls.bol);addLink(links,'Amazon.nl',urls.amazon);addLink(links,'Marktplaats',urls.marktplaats);addLink(links,'De Slegte',urls.deslegte);addLink(links,'Bookmatch',urls.bookmatch);addLink(links,'Bruna',urls.bruna);addLink(links,'Discogs (muziek)',urls.discogs);root.appendChild(links);if(item.offers&&item.offers.length){let offersTitle=document.createElement('h4');offersTitle.textContent='Mogelijke aanbieders (via UPCitemdb)';root.appendChild(offersTitle);for(const offer of item.offers){let row=document.createElement('p');let price=offer.price?(' — '+offer.price+(offer.currency?' '+offer.currency:' (valuta onbekend)')):'';let shipping=offer.shipping?(' · verzending '+offer.shipping):'';row.textContent=(offer.merchant||'Winkel')+price+shipping+(offer.availability?' · '+offer.availability:'');root.appendChild(row);if(offer.link)addLink(root,'Bekijk bij '+(offer.merchant||'winkel'),offer.link)}let note=document.createElement('p');note.className='catalog-message';note.textContent='Aanbiedingen kunnen verouderd zijn; controleer prijs en voorraad bij de winkel.';root.appendChild(note)}
let form=document.createElement(item.found?'dialog':'div');form.className='catalog-form';let prompt=document.createElement('h4');prompt.textContent=item.found?(existingItem?'Dit artikel staat al in je voorraad. Wil je de gegevens wijzigen?':'Product gevonden. Wil je het opslaan in Mijn voorraad?'):'Niet online gevonden. Wil je het zelf aan Mijn voorraad toevoegen?';let nameLabel=document.createElement('label');nameLabel.textContent='Naam (aanpasbaar)';let name=document.createElement('input');name.value=existingItem?.name||item.name||'';name.placeholder='Vul zelf een naam in';let locLabel=document.createElement('label');locLabel.textContent='Welke locatie?';let location=document.createElement('select');let noLocation=document.createElement('option');noLocation.value='';noLocation.textContent='Geen locatie';location.appendChild(noLocation);let locationValues=[...new Set([...(locations||[]),existingItem?.location||''].filter(Boolean))];for(const place of locationValues){let option=document.createElement('option');option.value=place;option.textContent=place;location.appendChild(option)}let newLocationOption=document.createElement('option');newLocationOption.value='__new__';newLocationOption.textContent='Nieuwe locatie invoeren…';location.appendChild(newLocationOption);if(existingItem?.location)location.value=existingItem.location;let customLocation=document.createElement('input');customLocation.placeholder='Typ de nieuwe locatie';customLocation.hidden=true;location.onchange=()=>{customLocation.hidden=location.value!=='__new__';if(!customLocation.hidden)customLocation.focus()};let noteLabel=document.createElement('label');noteLabel.textContent='Notities';let notes=document.createElement('textarea');notes.value=existingItem?.notes||[item.source?'Bron: '+item.source:'',item.brand,item.category,item.quantity,item.description].filter(Boolean).join(' · ');let buttons=document.createElement('div');buttons.className='buttons';let save=document.createElement('button');save.className='primary';save.textContent=existingItem?'Opslaan van wijzigingen':item.found?'Ja, opslaan in Mijn voorraad':'Handmatig toevoegen';let skip=document.createElement('button');skip.textContent='Nee, niet opslaan';let msg=document.createElement('p');msg.className='catalog-message';save.onclick=async()=>{if(!name.value.trim()){msg.textContent='Vul eerst een naam in.';return}let chosenLocation=location.value==='__new__'?customLocation.value.trim():location.value;if(location.value==='__new__'&&!chosenLocation){msg.textContent='Typ een locatie of kies “Geen locatie”.';return}try{let response=await fetch('/api/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:existingItem?.id||null,barcode:item.barcode,name:name.value.trim(),location:chosenLocation,notes:notes.value.trim()})});let data=await response.json();if(!response.ok)throw Error(data.error||'Opslaan mislukt');if(form instanceof HTMLDialogElement&&form.open)form.close();setTab('inventory');$('lastScan').textContent=data.item.barcode;fillForm(data.item);setMessage('Opgeslagen vanuit de algemene database.')}catch(e){msg.textContent=e.message}};skip.onclick=()=>{if(item.found){form.close();let notice=document.createElement('p');notice.className='catalog-message';notice.textContent='Niet opgeslagen in Mijn voorraad; het resultaat blijft alleen in de online zoekgeschiedenis.';root.insertBefore(notice,root.firstChild)}else{msg.textContent='Niet toegevoegd aan Mijn voorraad.'}};form.append(prompt,nameLabel,name,locLabel,location,customLocation,noteLabel,notes,buttons,msg);buttons.append(save,skip);root.appendChild(form);if(item.found)form.showModal()}
async function lookupOnline(code){code=(code||'').trim();if(!code)return;$('catalogBarcode').value=code;$('catalogResult').textContent='Zoeken in openbare databases…';setTab('catalog');try{let response=await fetch('/api/lookup?barcode='+encodeURIComponent(code));let data=await response.json();if(!response.ok)throw Error(data.error||'Zoeken mislukt');renderCatalogItem(data.item,data.locations||[],data.existing_item||null);loadCatalogRecent()}catch(e){$('catalogResult').textContent='Online zoeken mislukt: '+e.message}}
$('catalogLookup').onclick=()=>lookupOnline($('catalogBarcode').value);$('catalogBarcode').addEventListener('keydown',e=>{if(e.key==='Enter')lookupOnline($('catalogBarcode').value)});
function renderRecentCatalog(items){let root=$('catalogRecent');root.replaceChildren();if(!items.length){root.innerHTML='<div class="empty">Nog geen online zoekopdrachten.</div>';return}for(const item of items){let b=document.createElement('button');b.className='recent-row';b.textContent=(item.name||'Onbekend product')+' · '+item.barcode;b.onclick=async()=>{setTab('catalog');$('catalogBarcode').value=item.barcode;try{let [loc,stock]=await Promise.all([fetch('/api/locations').then(r=>r.json()),fetch('/api/by-barcode?code='+encodeURIComponent(item.barcode)).then(r=>r.json())]);renderCatalogItem(item,loc.locations||[],stock.item||null)}catch(e){renderCatalogItem(item)}};root.appendChild(b)}}
async function loadCatalogRecent(){try{let q=$('catalogSearch').value.trim();let url=q?'/api/catalog/search?q='+encodeURIComponent(q):'/api/catalog/recent';let d=await(await fetch(url)).json();renderRecentCatalog(d.items||[])}catch(e){}}
$('catalogSearch').addEventListener('input',()=>{clearTimeout(catalogTimer);catalogTimer=setTimeout(loadCatalogRecent,200)});
$('tabInventory').onclick=()=>setTab('inventory');$('tabCatalog').onclick=()=>setTab('catalog');
pollScans();refreshStatus();
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
