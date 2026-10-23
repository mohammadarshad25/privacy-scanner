#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Privacy Scanner — WiFi Surveillance Device Detector (Cross-Platform)
Defensive security tool for detecting hidden cameras in rental accommodations.

Supports: Linux, macOS (Darwin), Windows
Requires: nmap (mandatory)
Optional: python-nmap, zeroconf, requests

Usage:
    # Linux/macOS (root recommended):
    sudo python3 scan.py

    # Windows (run as Administrator):
    python scan.py

    # Options:
    python3 scan.py --interface eth0 --subnet 192.168.1.0/24 --quick --lang en
"""

import argparse
import glob as glob_mod
import ipaddress
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Optional imports with graceful degradation
# ---------------------------------------------------------------------------
HAS_SPYDEVICES = False
HAS_TRAFFIC = False

try:
    import spydevices
    HAS_SPYDEVICES = True
except ImportError:
    pass

try:
    import traffic as traffic_mod
    HAS_TRAFFIC = True
except ImportError:
    pass

HAS_PYTHON_NMAP = False
HAS_ZEROCONF = False
HAS_REQUESTS = False

try:
    import nmap as python_nmap  # noqa: F401

    HAS_PYTHON_NMAP = True
except ImportError:
    pass

try:
    from zeroconf import ServiceBrowser, Zeroconf  # noqa: F401

    HAS_ZEROCONF = True
except ImportError:
    pass

try:
    import requests  # noqa: F401

    HAS_REQUESTS = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
SYSTEM = platform.system()  # "Linux", "Darwin", "Windows"

# ---------------------------------------------------------------------------
# Enable ANSI colors on Windows 10+
# ---------------------------------------------------------------------------
if SYSTEM == "Windows":
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------
RED = "\033[0;31m"
ORANGE = "\033[0;33m"
YELLOW = "\033[1;33m"
GREEN = "\033[0;32m"
BLUE = "\033[0;34m"
CYAN = "\033[0;36m"
WHITE = "\033[1;37m"
BOLD = "\033[1m"
DIM = "\033[2m"
NC = "\033[0m"

ICON_CRITICAL = "\U0001f534"   # red circle
ICON_HIGH     = "\U0001f7e0"   # orange circle
ICON_MODERATE = "\U0001f7e1"   # yellow circle
ICON_LOW      = "\U0001f7e2"   # green circle
ICON_INFO     = "\U0001f535"   # blue circle

# ---------------------------------------------------------------------------
# Camera ports
# ---------------------------------------------------------------------------
CAMERA_PORTS = "554,8554,80,443,8080,8443,8000,8200,37777,34567,34599,9000,3702,1935,5000,6667,8899,49152,7070,9527"

RTSP_PORTS = {"554", "8554"}
HTTP_PORTS = {"80", "443", "8080", "8443", "8899"}
VENDOR_PORTS = {"8000", "8200", "37777", "34567", "34599", "9000"}

# ---------------------------------------------------------------------------
# nmap MAC prefix database paths
# ---------------------------------------------------------------------------
NMAP_MAC_PATHS = [
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
    "/opt/homebrew/share/nmap/nmap-mac-prefixes",
    "/opt/homebrew/Cellar/nmap/*/share/nmap/nmap-mac-prefixes",
    r"C:\Program Files\Nmap\nmap-mac-prefixes",
    r"C:\Program Files (x86)\Nmap\nmap-mac-prefixes",
]

# ---------------------------------------------------------------------------
# Tier 1: Dedicated surveillance OUI prefixes (always cameras)
# ---------------------------------------------------------------------------
TIER1_OUIS: dict[str, str] = {}

_HIKVISION = (
    "00BC99 040312 04EECD 083BC1 085411 08A189 08CC81 0C75D2 1012FB "
    "1868CB 188025 240F9B 2428FD 2432AE 244845 2857BE 2CA59C 340962 "
    "3C1BF8 40ACBF 4419B6 4447CC 44A642 48785B 4C1F86 4C62DF 4CBD8F "
    "4CF5DC 50E538 548C81 54C415 5803FB 5850ED 5C345B 64DB8B 686DBC "
    "743FC2 80489F 807C62 80BEAF 80F5AE 849459 849A40 88DE39 8C22D2 "
    "8CE748 94E1AC 988B0A 989DE5 98DF82 98F112 A0FF0C A41437 A42902 "
    "A44BD9 A4A459 A4D5C2 ACCB51 ACB92F B4A382 BC2978 BC5E33 BC9B5E "
    "BCAD28 BCBAC2 C0517E C056E3 C06DED C42F90 C8A702 D4E853 DC07F8 "
    "DCD26A E0BAAD E0CA3C E0DF13 E4D58B E8A0ED ECA971 ECC89C F84DFC "
    "FC9FFD"
)
for _o in _HIKVISION.split():
    TIER1_OUIS[_o] = "Hikvision"

_EZVIZ = "0CA64C 20BBBC 34C6DD 54D60D 588FCF 64244D 64F2FB 78A6A0 78C1AE 94EC13 AC1C26 EC97E0 F47018"
for _o in _EZVIZ.split():
    TIER1_OUIS[_o] = "EZVIZ"

_DAHUA = (
    "08EDED 14A78B 24526A 30DDAA 38AF29 3CE36B 3CEF8C 407AA4 4C11BF "
    "4C99E8 5CF51A 64FD29 6C1C71 74C929 8CE9B4 9002A9 98F9CC 9C1463 "
    "A0BD1D A8CA87 B44C3B BC325F C0395A C4AAC4 D4430E E02EFE E0508B "
    "E4246C F4B1C2 F8CE07 FC5F49 FCB69D"
)
for _o in _DAHUA.split():
    TIER1_OUIS[_o] = "Dahua"

for _o in "00651E 9C8ECD A06032".split():
    TIER1_OUIS[_o] = "Amcrest"
for _o in "48EA63 6CF17E 88263F C47905".split():
    TIER1_OUIS[_o] = "Uniview"
for _o in "00408C ACCC8E B8A44F E82725".split():
    TIER1_OUIS[_o] = "Axis"
TIER1_OUIS["EC71DB"] = "Reolink"

# ---------------------------------------------------------------------------
# Tier 2: Consumer camera brands (HIGH risk)
# ---------------------------------------------------------------------------
TIER2_OUIS: dict[str, str] = {}

for _o in "2CAA8E 7C78B2 80482C D03F27 F0C88B".split():
    TIER2_OUIS[_o] = "Wyze"
for _o in "3CA070 70AD43 74AB93 F074C1".split():
    TIER2_OUIS[_o] = "Blink"
for _o in "486264 A41162 FC9C98".split():
    TIER2_OUIS[_o] = "Arlo"
for _o in "18B430 641666".split():
    TIER2_OUIS[_o] = "NestLabs"
for _o in "C0562D C8D719 008E10 E0B9E5 001EF2".split():
    TIER2_OUIS[_o] = "Foscam"
for _o in "78025E 7811DC 34CE00 04CF8C 28D127 58A60B 641327".split():
    TIER2_OUIS[_o] = "Yi-Xiaomi"
for _o in "98F1B1 78C57D 8CEEA7".split():
    TIER2_OUIS[_o] = "Eufy"

# ---------------------------------------------------------------------------
# Camera HTTP keywords & headers
# ---------------------------------------------------------------------------
CAMERA_KEYWORDS_HIGH = (
    r"camera|webcam|ipcam|DVR|NVR|surveillance|CCTV|hikvision|dahua|amcrest|"
    r"reolink|foscam|wyze|ONVIF|rtsp://|live\.view|liveview|snapshot|"
    r"motion\.detect|PTZ|night\.vision|DNVRS-Webs|App-webs|XMEye|"
    r"NETSurveillance|IPCamera|webcamXP|Yawcam|Blue\.Iris|ZoneMinder|"
    r"Shinobi|MotionEye|Frigate|ISAPI|Streaming/Channels|cam/realmonitor"
)

CAMERA_KEYWORDS_MEDIUM = (
    r"stream|video|media\.server|MJPEG|H\.264|H\.265|codec|bitrate|firmware|device\.info"
)

CAMERA_HEADERS = r"DNVRS-Webs|App-webs|Hikvision|Dahua|DH-IPC|uc-httpd|GoAhead-Webs|JAWS/|Boa/"

CAMERA_TITLE_RE = re.compile(
    r"NETSurveillance|DVR|NVR|IPCamera|IP Camera|Network Camera|iVMS|SADP|"
    r"webcamXP|Yawcam|Blue\.Iris|ZoneMinder|Shinobi|MotionEye|Frigate",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Known safe manufacturers (substring match, lowercase)
# ---------------------------------------------------------------------------
SAFE_MANUFACTURERS = re.compile(
    r"apple|samsung electronics|intel|dell|hewlett|lenovo|huawei device|"
    r"xiaomi comm|google|amazon|sonos|roku|brother|canon|philips|ecobee|"
    r"honeywell|microsoft",
    re.IGNORECASE,
)

IOT_CHIPSETS = re.compile(r"espressif|tuya|smartlife|beken", re.IGNORECASE)
GENERIC_CHIPSETS = re.compile(r"realtek|mediatek|qualcomm|broadcom|marvell|ralink", re.IGNORECASE)
CAMERA_MFR_KEYWORDS = re.compile(r"camera|surveillance|security|cctv|dvr|nvr|vision", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def log_phase(num: str, name: str) -> None:
    print()
    print(f"{BOLD}{CYAN}{'━' * 58}{NC}")
    print(f"{BOLD}{WHITE}  Phase {num}: {name}{NC}")
    print(f"{BOLD}{CYAN}{'━' * 58}{NC}")


def log_info(msg: str) -> None:
    print(f"  {BLUE}[*]{NC} {msg}")


def log_ok(msg: str) -> None:
    print(f"  {GREEN}[+]{NC} {msg}")


def log_warn(msg: str) -> None:
    print(f"  {YELLOW}[!]{NC} {msg}")


def log_critical(msg: str) -> None:
    print(f"  {RED}[!!!]{NC} {BOLD}{msg}{NC}")


def log_dim(msg: str) -> None:
    print(f"  {DIM}{msg}{NC}")


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def run_cmd(cmd: list[str] | str, timeout: int = 30, shell: bool = False) -> tuple[str, str, int]:
    """Run a command and return (stdout, stderr, returncode). Never raises."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, shell=shell,
        )
        return r.stdout, r.stderr, r.returncode
    except FileNotFoundError:
        return "", f"Command not found: {cmd}", 127
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 124
    except Exception as exc:
        return "", str(exc), 1


def mac_to_oui(mac: str) -> str:
    """Convert any MAC format to 6-char uppercase OUI (e.g. 'A4D5C2')."""
    cleaned = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    return cleaned[:6]


def is_mac_randomized(mac: str) -> bool:
    """Check locally-administered bit (bit 1 of first octet)."""
    cleaned = mac.replace(":", "").replace("-", "").replace(".", "")
    if len(cleaned) < 2:
        return False
    try:
        first_byte = int(cleaned[:2], 16)
        return bool(first_byte & 0x02)
    except ValueError:
        return False


def is_root() -> bool:
    """Check if running with elevated privileges."""
    if SYSTEM == "Windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def find_nmap_mac_db() -> str | None:
    """Locate the nmap-mac-prefixes file on disk."""
    for p in NMAP_MAC_PATHS:
        if "*" in p:
            matches = glob_mod.glob(p)
            for m in matches:
                if os.path.isfile(m):
                    return m
        elif os.path.isfile(p):
            return p
    return None


def load_nmap_mac_db(path: str) -> dict[str, str]:
    """Parse nmap-mac-prefixes into {OUI: manufacturer}."""
    db: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    db[parts[0].upper()] = parts[1]
    except OSError:
        pass
    return db


# ---------------------------------------------------------------------------
# Network detection — per-platform
# ---------------------------------------------------------------------------

def detect_network_linux(iface_hint: str | None) -> dict:
    """Detect gateway, interface, local IP, subnet on Linux."""
    info: dict = {"gateway": "", "interface": "", "local_ip": "", "subnet": ""}

    stdout, _, _ = run_cmd(["ip", "route"])
    for line in stdout.splitlines():
        if line.startswith("default"):
            parts = line.split()
            try:
                gw_idx = parts.index("via") + 1
                info["gateway"] = parts[gw_idx]
            except (ValueError, IndexError):
                pass
            try:
                dev_idx = parts.index("dev") + 1
                info["interface"] = parts[dev_idx]
            except (ValueError, IndexError):
                pass
            break

    if iface_hint:
        info["interface"] = iface_hint

    iface = info["interface"]
    if iface:
        stdout, _, _ = run_cmd(["ip", "-4", "addr", "show", iface])
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", stdout)
        if m:
            info["local_ip"] = m.group(1)
            cidr = f"{m.group(1)}/{m.group(2)}"
            try:
                info["subnet"] = str(ipaddress.ip_interface(cidr).network)
            except ValueError:
                info["subnet"] = f"{m.group(1).rsplit('.', 1)[0]}.0/24"

    return info


def detect_network_darwin(iface_hint: str | None) -> dict:
    """Detect gateway, interface, local IP, subnet on macOS."""
    info: dict = {"gateway": "", "interface": "", "local_ip": "", "subnet": ""}

    stdout, _, _ = run_cmd(["route", "-n", "get", "default"])
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("gateway:"):
            info["gateway"] = line.split(":", 1)[1].strip()
        elif line.startswith("interface:"):
            info["interface"] = line.split(":", 1)[1].strip()

    if iface_hint:
        info["interface"] = iface_hint

    iface = info["interface"]
    if iface:
        stdout, _, _ = run_cmd(["ifconfig", iface])
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)", stdout)
        if m:
            info["local_ip"] = m.group(1)
            try:
                mask_int = int(m.group(2), 16)
                prefix_len = bin(mask_int).count("1")
                cidr = f"{m.group(1)}/{prefix_len}"
                info["subnet"] = str(ipaddress.ip_interface(cidr).network)
            except (ValueError, OverflowError):
                info["subnet"] = f"{m.group(1).rsplit('.', 1)[0]}.0/24"

    return info


def detect_network_windows(iface_hint: str | None) -> dict:
    """Detect gateway, interface, local IP, subnet on Windows."""
    info: dict = {"gateway": "", "interface": "", "local_ip": "", "subnet": ""}

    stdout, _, _ = run_cmd(["ipconfig"], timeout=15)

    current_adapter = ""
    current_ip = ""
    current_mask = ""
    current_gw = ""

    for line in stdout.splitlines():
        adapter_match = re.match(r"^(\S.*adapter .+):", line)
        if adapter_match:
            # Save previous adapter if it had a gateway
            if current_gw and current_ip:
                info["gateway"] = current_gw
                info["local_ip"] = current_ip
                info["interface"] = current_adapter
                if current_mask:
                    try:
                        prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{current_mask}").prefixlen
                        info["subnet"] = str(
                            ipaddress.ip_interface(f"{current_ip}/{prefix_len}").network
                        )
                    except ValueError:
                        info["subnet"] = f"{current_ip.rsplit('.', 1)[0]}.0/24"
                break
            current_adapter = adapter_match.group(1).strip()
            current_ip = current_mask = current_gw = ""
            continue

        stripped = line.strip()
        if "IPv4" in stripped and ". :" in stripped:
            current_ip = stripped.split(":")[-1].strip()
        elif "Subnet Mask" in stripped and ". :" in stripped:
            current_mask = stripped.split(":")[-1].strip()
        elif "Default Gateway" in stripped and ". :" in stripped:
            val = stripped.split(":")[-1].strip()
            if val:
                current_gw = val

    # Handle last adapter
    if not info["gateway"] and current_gw and current_ip:
        info["gateway"] = current_gw
        info["local_ip"] = current_ip
        info["interface"] = current_adapter
        if current_mask:
            try:
                prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{current_mask}").prefixlen
                info["subnet"] = str(
                    ipaddress.ip_interface(f"{current_ip}/{prefix_len}").network
                )
            except ValueError:
                info["subnet"] = f"{current_ip.rsplit('.', 1)[0]}.0/24"

    if iface_hint:
        info["interface"] = iface_hint

    return info


def detect_network(iface_hint: str | None = None) -> dict:
    """Dispatch to platform-specific network detection."""
    if SYSTEM == "Linux":
        return detect_network_linux(iface_hint)
    elif SYSTEM == "Darwin":
        return detect_network_darwin(iface_hint)
    elif SYSTEM == "Windows":
        return detect_network_windows(iface_hint)
    else:
        log_warn(f"Unsupported platform: {SYSTEM}, attempting Linux-style detection")
        return detect_network_linux(iface_hint)


# ---------------------------------------------------------------------------
# ARP table retrieval
# ---------------------------------------------------------------------------

def get_arp_table() -> list[tuple[str, str]]:
    """Return list of (IP, MAC) from the system ARP table."""
    results: list[tuple[str, str]] = []

    if SYSTEM == "Linux":
        stdout, _, _ = run_cmd(["ip", "neigh", "show"])
        for line in stdout.splitlines():
            parts = line.split()
            if "lladdr" in parts:
                try:
                    ip = parts[0]
                    mac = parts[parts.index("lladdr") + 1]
                    if mac.upper() not in ("INCOMPLETE", "FAILED"):
                        results.append((ip, mac))
                except (ValueError, IndexError):
                    continue
    else:
        # macOS and Windows both support arp -a
        stdout, _, _ = run_cmd(["arp", "-a"])
        for line in stdout.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-fA-F:.-]{11,17})", line)
            if m:
                ip = m.group(1)
                mac = m.group(2)
                if mac.lower() not in ("(incomplete)", "ff:ff:ff:ff:ff:ff", "ff-ff-ff-ff-ff-ff"):
                    results.append((ip, mac))

    return results


# ---------------------------------------------------------------------------
# WiFi SSID count
# ---------------------------------------------------------------------------

def count_nearby_ssids(iface: str) -> int:
    """Best-effort count of visible WiFi networks."""
    count = 0
    try:
        if SYSTEM == "Linux":
            stdout, _, rc = run_cmd(["nmcli", "-t", "-f", "SSID", "dev", "wifi", "list"], timeout=15)
            if rc == 0:
                ssids = {s.strip() for s in stdout.splitlines() if s.strip()}
                return len(ssids)
            stdout, _, rc = run_cmd(["iwlist", iface, "scan"], timeout=15)
            if rc == 0:
                count = len(re.findall(r"ESSID:", stdout))
        elif SYSTEM == "Darwin":
            airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if os.path.exists(airport):
                stdout, _, rc = run_cmd([airport, "-s"], timeout=15)
                if rc == 0:
                    lines = [l for l in stdout.splitlines()[1:] if l.strip()]
                    count = len(lines)
        elif SYSTEM == "Windows":
            stdout, _, rc = run_cmd(["netsh", "wlan", "show", "networks"], timeout=15)
            if rc == 0:
                count = len(re.findall(r"SSID \d+", stdout))
    except Exception:
        pass
    return count


# ===========================================================================
# Phase 0: Prerequisites
# ===========================================================================

class ScanContext:
    """Holds all scan state and configuration."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.start_time = time.time()
        self.timestamp = time.strftime("%Y%m%d-%H%M%S")

        # Network info (filled by detect)
        self.interface = args.interface or ""
        self.subnet = args.subnet or ""
        self.gateway = ""
        self.my_ip = ""

        # Capability flags
        self.is_root = is_root()
        self.has_nmap = bool(shutil.which("nmap"))
        self.has_arpscan = bool(shutil.which("arp-scan"))
        self.nmap_mac_db_path = find_nmap_mac_db()
        self.nmap_mac_db: dict[str, str] = {}
        if self.nmap_mac_db_path:
            self.nmap_mac_db = load_nmap_mac_db(self.nmap_mac_db_path)

        # Scan work directory (temp)
        self.scan_dir = tempfile.mkdtemp(prefix="privacy_scan_")

        # Report output directory
        self.report_dir = Path(args.output_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)

        # Result data
        self.hosts: list[dict] = []           # Phase 1 results
        self.oui_results: list[dict] = []     # Phase 2 results
        self.port_results: list[dict] = []    # Phase 3 results
        self.service_results: list[dict] = [] # Phase 4 results
        self.deep_results: list[dict] = []    # Phase 5 results
        self.classifications: list[dict] = [] # Phase 6 results
        self.traffic_results: list = []       # Phase 5c results (traffic anomalies)
        self.counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0, "INFO": 0}


def phase0_prerequisites(ctx: ScanContext) -> None:
    """Check for required tools and privileges."""
    log_phase("0", "Prerequisites Check")

    if ctx.is_root:
        log_ok("Running with elevated privileges")
    else:
        log_warn("Not running as root/admin — some scans will be limited")
        if SYSTEM == "Windows":
            log_warn("For best results, run as Administrator")
        else:
            log_warn(f"For best results, run: sudo {sys.executable} {__file__}")

    if not ctx.has_nmap:
        log_critical("nmap is NOT installed — cannot proceed")
        print()
        print("  Install nmap:")
        if SYSTEM == "Linux":
            print("    Arch:   sudo pacman -S nmap")
            print("    Debian: sudo apt install nmap")
            print("    Fedora: sudo dnf install nmap")
        elif SYSTEM == "Darwin":
            print("    macOS:  brew install nmap")
        elif SYSTEM == "Windows":
            print("    Windows: Download from https://nmap.org/download.html")
        sys.exit(1)

    stdout, _, _ = run_cmd(["nmap", "--version"])
    nmap_ver = stdout.splitlines()[0] if stdout else "unknown version"
    log_ok(f"nmap: {nmap_ver}")

    if ctx.has_arpscan and SYSTEM != "Windows":
        stdout, _, _ = run_cmd(["arp-scan", "--version"])
        ver = stdout.splitlines()[0] if stdout else "available"
        log_ok(f"arp-scan: {ver}")
    elif SYSTEM != "Windows":
        log_warn("arp-scan not found (recommended for better host discovery)")

    if HAS_ZEROCONF:
        log_ok("zeroconf: available (Python mDNS)")
    else:
        if SYSTEM == "Linux" and shutil.which("avahi-browse"):
            log_ok("avahi-browse: available (mDNS fallback)")
        elif SYSTEM == "Darwin":
            log_ok("dns-sd: available (macOS built-in mDNS)")
        else:
            log_warn("No mDNS tool available (install python zeroconf: pip install zeroconf)")

    if HAS_REQUESTS:
        log_ok("requests: available (HTTP inspection)")
    elif shutil.which("curl"):
        log_ok("curl: available (HTTP inspection fallback)")
    else:
        log_warn("No HTTP client available (install requests: pip install requests)")

    if ctx.nmap_mac_db_path:
        count = len(ctx.nmap_mac_db)
        log_ok(f"nmap MAC database: {count} entries ({ctx.nmap_mac_db_path})")
    else:
        log_warn("nmap MAC database not found — using embedded OUI list only")

    log_ok(f"Platform: {SYSTEM} ({platform.platform()})")


# ===========================================================================
# Phase 0.5: Network Detection
# ===========================================================================

def phase05_network_detection(ctx: ScanContext) -> None:
    """Auto-detect or validate network configuration."""
    log_phase("0.5", "Network Detection")

    net_info = detect_network(ctx.args.interface)

    if not ctx.interface:
        ctx.interface = net_info["interface"]
    if not ctx.interface:
        log_critical("Could not detect network interface")
        print("  Specify manually with: --interface eth0")
        sys.exit(1)
    log_ok(f"Interface: {ctx.interface}")

    ctx.my_ip = net_info["local_ip"]
    ctx.gateway = net_info["gateway"]

    if not ctx.subnet:
        ctx.subnet = net_info["subnet"]
    if not ctx.subnet:
        if ctx.my_ip:
            ctx.subnet = f"{ctx.my_ip.rsplit('.', 1)[0]}.0/24"
            log_warn(f"Subnet guessed: {ctx.subnet}")
        else:
            log_critical("Could not detect subnet — specify with --subnet")
            sys.exit(1)

    log_ok(f"Subnet: {ctx.subnet}")
    log_ok(f"Gateway: {ctx.gateway}")
    log_ok(f"Scanner IP: {ctx.my_ip}")

    ssid_count = count_nearby_ssids(ctx.interface)
    if ssid_count > 2:
        log_warn(f"Detected {ssid_count} WiFi networks nearby — cameras may be on a separate network")


# ===========================================================================
# Phase 1: Host Discovery
# ===========================================================================

def phase1_host_discovery(ctx: ScanContext) -> None:
    """Find all devices on the local network."""
    log_phase("1", "Host Discovery")
    log_info("Finding all devices on the network...")

    seen_ips: set[str] = set()

    # Method 1: arp-scan (Linux/macOS with root)
    if ctx.has_arpscan and ctx.is_root and SYSTEM != "Windows":
        log_info(f"Running arp-scan on {ctx.interface}...")
        stdout, _, rc = run_cmd(
            ["arp-scan", "-l", "-I", ctx.interface], timeout=60
        )
        if rc == 0:
            for line in stdout.splitlines():
                m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)", line)
                if m:
                    ip, mac, vendor = m.group(1), m.group(2), m.group(3).strip()
                    if ip == ctx.my_ip:
                        continue
                    oui = mac_to_oui(mac)
                    ctx.hosts.append({"ip": ip, "mac": mac, "vendor": vendor, "oui": oui})
                    seen_ips.add(ip)
            log_ok(f"arp-scan found {len(ctx.hosts)} devices")

    # Method 2: nmap ping scan
    log_info(f"Running nmap host discovery on {ctx.subnet}...")
    nmap_grepable = os.path.join(ctx.scan_dir, "nmap_discovery.gnmap")
    nmap_args = ["nmap", "-sn"]
    if ctx.is_root and SYSTEM != "Windows":
        nmap_args.append("-PR")
    nmap_args += [ctx.subnet, "-oG", nmap_grepable]
    run_cmd(nmap_args, timeout=120)

    # Parse grepable output
    try:
        with open(nmap_grepable, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m_host = re.match(r"Host:\s+(\d+\.\d+\.\d+\.\d+)", line)
                if not m_host:
                    continue
                ip = m_host.group(1)
                if ip in seen_ips or ip == ctx.my_ip or ip == ctx.gateway:
                    continue

                mac = ""
                vendor = ""
                m_mac = re.search(r"MAC:\s+([0-9A-Fa-f:]+)\s+\(([^)]*)\)", line)
                if m_mac:
                    mac = m_mac.group(1)
                    vendor = m_mac.group(2)
                else:
                    m_mac2 = re.search(r"MAC:\s+([0-9A-Fa-f:]+)", line)
                    if m_mac2:
                        mac = m_mac2.group(1)

                # Fallback: try ARP table
                if not mac:
                    arp_entries = get_arp_table()
                    for aip, amac in arp_entries:
                        if aip == ip:
                            mac = amac
                            break

                if mac and mac.upper() != "INCOMPLETE":
                    oui = mac_to_oui(mac)
                    ctx.hosts.append({"ip": ip, "mac": mac, "vendor": vendor, "oui": oui})
                    seen_ips.add(ip)
    except OSError:
        pass

    # Method 3: Fallback to ARP table alone
    if not ctx.hosts:
        log_warn("No devices found via arp-scan/nmap, falling back to ARP table")
        for ip, mac in get_arp_table():
            if ip == ctx.my_ip or ip in seen_ips:
                continue
            oui = mac_to_oui(mac)
            ctx.hosts.append({"ip": ip, "mac": mac, "vendor": "", "oui": oui})
            seen_ips.add(ip)

    # Add gateway if not already included
    if ctx.gateway and ctx.gateway not in seen_ips:
        for ip, mac in get_arp_table():
            if ip == ctx.gateway:
                oui = mac_to_oui(mac)
                ctx.hosts.append({"ip": ip, "mac": mac, "vendor": "GATEWAY", "oui": oui})
                break

    log_ok(f"Total unique devices found: {len(ctx.hosts)}")
    if not ctx.hosts:
        log_warn("No devices found! The network may use client isolation.")
        log_warn("Try running with elevated privileges for better results.")


# ===========================================================================
# Phase 2: OUI Analysis
# ===========================================================================

def phase2_oui_analysis(ctx: ScanContext) -> None:
    """Identify manufacturers via OUI lookup."""
    log_phase("2", "Manufacturer Identification (OUI Analysis)")

    cam_count = 0
    unknown_count = 0

    for host in ctx.hosts:
        ip = host["ip"]
        mac = host["mac"]
        oui = host["oui"]
        vendor = host.get("vendor", "")

        manufacturer = vendor
        classification = "UNKNOWN"
        randomized = is_mac_randomized(mac)

        if randomized:
            log_warn(f"Randomized MAC: {ip} — {mac} (manufacturer cannot be determined)")

        # Step 1: Tier 1 — dedicated surveillance
        if not randomized and oui in TIER1_OUIS:
            manufacturer = TIER1_OUIS[oui]
            classification = "TIER1_CAMERA"
            cam_count += 1
            log_critical(f"CAMERA MANUFACTURER: {ip} — {manufacturer} ({mac})")

        # Step 2: Tier 2 — consumer camera brands
        elif not randomized and oui in TIER2_OUIS:
            manufacturer = TIER2_OUIS[oui]
            classification = "TIER2_CAMERA"
            cam_count += 1
            log_warn(f"Camera brand: {ip} — {manufacturer} ({mac})")

        elif randomized:
            manufacturer = "(randomized MAC)"
            classification = "MAC_RANDOMIZED"
            unknown_count += 1

        else:
            # Step 3: nmap MAC database
            if not manufacturer and oui in ctx.nmap_mac_db:
                manufacturer = ctx.nmap_mac_db[oui]

            # Step 4: classify by manufacturer name
            if manufacturer:
                if CAMERA_MFR_KEYWORDS.search(manufacturer):
                    classification = "CAMERA_KEYWORD"
                    cam_count += 1
                    log_warn(f"Camera-related manufacturer: {ip} — {manufacturer} ({mac})")
                elif IOT_CHIPSETS.search(manufacturer):
                    classification = "IOT_CHIPSET"
                    log_info(f"IoT chipset: {ip} — {manufacturer} ({mac})")
                elif SAFE_MANUFACTURERS.search(manufacturer):
                    classification = "KNOWN_SAFE"
                    log_dim(f"Known device: {ip} — {manufacturer} ({mac})")
                elif GENERIC_CHIPSETS.search(manufacturer):
                    classification = "GENERIC_CHIPSET"
                    log_info(f"Generic chipset: {ip} — {manufacturer} ({mac})")
                else:
                    classification = "KNOWN_OTHER"
                    log_dim(f"Other device: {ip} — {manufacturer} ({mac})")
            else:
                classification = "UNKNOWN"
                unknown_count += 1
                log_warn(f"UNKNOWN manufacturer: {ip} — {mac}")

        ctx.oui_results.append({
            "ip": ip, "mac": mac, "manufacturer": manufacturer,
            "classification": classification, "oui": oui,
        })

    print()
    log_info(f"Summary: {cam_count} camera manufacturers, {unknown_count} unknown")
    if cam_count > 0:
        log_critical("CAMERA MANUFACTURERS DETECTED — proceeding with detailed port scan")


# ===========================================================================
# Phase 3: Port Scanning
# ===========================================================================

def phase3_port_scan(ctx: ScanContext) -> None:
    """Scan camera-specific ports on all discovered devices."""
    log_phase("3", "Port Scanning (Camera-Specific Ports)")

    if not ctx.oui_results:
        log_warn("No targets to scan")
        return

    targets = [d["ip"] for d in ctx.oui_results]
    log_info(f"Scanning {len(targets)} devices on camera-specific ports...")
    log_info(f"Ports: {CAMERA_PORTS}")

    scan_type = "-sS" if (ctx.is_root and SYSTEM != "Windows") else "-sT"
    nmap_grepable = os.path.join(ctx.scan_dir, "nmap_ports.gnmap")
    nmap_normal = os.path.join(ctx.scan_dir, "nmap_ports.nmap")

    nmap_args = [
        "nmap", scan_type, "-sV",
        "-p", CAMERA_PORTS,
        "-T4", "--open",
        "--version-intensity", "5",
        "-oG", nmap_grepable,
        "-oN", nmap_normal,
    ] + targets

    run_cmd(nmap_args, timeout=300)

    # Parse grepable output
    open_count = 0
    try:
        with open(nmap_grepable, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = re.match(r"Host:\s+(\d+\.\d+\.\d+\.\d+)", line)
                if not m or "Ports:" not in line:
                    continue
                ip = m.group(1)
                ports_section = re.sub(r".*Ports:\s*", "", line)
                ports_section = re.sub(r"\s*Ignored.*", "", ports_section)

                for entry in ports_section.split(","):
                    entry = entry.strip()
                    if not entry:
                        continue
                    fields = entry.split("/")
                    if len(fields) < 5:
                        continue
                    port = fields[0].strip()
                    state = fields[1].strip()
                    service = fields[4].strip() if len(fields) > 4 else ""
                    version = fields[6].strip() if len(fields) > 6 else ""

                    if state == "open":
                        ctx.port_results.append({
                            "ip": ip, "port": port,
                            "service": service, "version": version,
                        })
                        open_count += 1

                        if port in ("554", "8554"):
                            log_critical(f"RTSP port {port} OPEN on {ip} — {service} {version}")
                        elif port == "37777":
                            log_critical(f"Dahua port {port} OPEN on {ip}")
                        elif port == "8000":
                            log_warn(f"Hikvision port {port} open on {ip}")
                        elif port in ("34567", "34599"):
                            log_critical(f"XMEye/Chinese NVR port {port} OPEN on {ip}")
                        elif port == "9000":
                            log_warn(f"Reolink port {port} open on {ip}")
                        else:
                            log_info(f"Port {port} open on {ip}: {service} {version}")
    except OSError:
        log_warn("Could not read nmap port scan results")

    log_ok(f"Found {open_count} open ports across all devices")


# ===========================================================================
# Phase 4: Service Discovery (mDNS / UPnP / ONVIF)
# ===========================================================================

def _mdns_zeroconf(ctx: ScanContext) -> None:
    """Use python zeroconf for mDNS discovery."""
    log_info("Scanning for mDNS/Bonjour services via zeroconf...")

    camera_types = [
        "_rtsp._tcp.local.", "_camera._tcp.local.",
        "_nvr._tcp.local.", "_onvif._tcp.local.",
        "_http._tcp.local.",
    ]

    collected: list[dict] = []

    class Listener:
        def add_service(self, zc, stype, name):
            info = zc.get_service_info(stype, name, timeout=3000)
            if info:
                addrs = info.parsed_addresses()
                ip = addrs[0] if addrs else ""
                collected.append({
                    "ip": ip, "method": "mDNS", "stype": stype,
                    "name": name, "txt": str(info.properties),
                })

        def remove_service(self, zc, stype, name):
            pass

        def update_service(self, zc, stype, name):
            pass

    try:
        zc = Zeroconf()
        listener = Listener()
        browsers = []
        for stype in camera_types:
            browsers.append(ServiceBrowser(zc, stype, listener))
        time.sleep(8)
        zc.close()
    except Exception as exc:
        log_warn(f"zeroconf error: {exc}")
        return

    camera_stypes = {"_rtsp._tcp.local.", "_camera._tcp.local.", "_nvr._tcp.local.", "_onvif._tcp.local."}
    for entry in collected:
        ctx.service_results.append(entry)
        if entry["stype"] in camera_stypes:
            log_critical(f"Camera service via mDNS: {entry['name']} ({entry['stype']}) at {entry['ip']}")
        else:
            log_info(f"HTTP service: {entry['name']} at {entry['ip']}")

    log_ok(f"mDNS services found: {len(collected)}")


def _mdns_avahi(ctx: ScanContext) -> None:
    """Fallback: use avahi-browse for mDNS (Linux)."""
    log_info("Scanning for mDNS/Bonjour services via avahi-browse...")
    stdout, _, _ = run_cmd(["avahi-browse", "-a", "-r", "-t", "-p"], timeout=20)

    camera_service_re = re.compile(r"_rtsp\._tcp|_camera\._tcp|_nvr\._tcp|_onvif\._tcp", re.IGNORECASE)
    count = 0
    for line in stdout.splitlines():
        if not line.startswith("="):
            continue
        fields = line.split(";")
        if len(fields) < 9:
            continue
        stype = fields[4] if len(fields) > 4 else ""
        name = fields[3] if len(fields) > 3 else ""
        ip = fields[7] if len(fields) > 7 else ""
        if not ip:
            continue
        entry = {"ip": ip, "method": "mDNS", "stype": stype, "name": name, "txt": ""}
        ctx.service_results.append(entry)
        count += 1
        if camera_service_re.search(stype):
            log_critical(f"Camera service via mDNS: {name} ({stype}) at {ip}")
        elif "_http._tcp" in stype:
            log_info(f"HTTP service: {name} at {ip}")

    log_ok(f"mDNS services found: {count}")


def _mdns_dnssd(ctx: ScanContext) -> None:
    """Fallback: use dns-sd for mDNS (macOS)."""
    log_info("Scanning for mDNS services via dns-sd (limited)...")
    # dns-sd is interactive; we run a brief browse and kill it
    for stype in ["_rtsp._tcp", "_camera._tcp", "_nvr._tcp", "_onvif._tcp", "_http._tcp"]:
        stdout, _, _ = run_cmd(["dns-sd", "-B", stype, "local."], timeout=6)
        for line in stdout.splitlines():
            if "Add" in line and stype in line:
                parts = line.split()
                name = parts[-1] if parts else stype
                entry = {"ip": "", "method": "mDNS", "stype": stype, "name": name, "txt": ""}
                ctx.service_results.append(entry)
                if stype in ("_rtsp._tcp", "_camera._tcp", "_nvr._tcp", "_onvif._tcp"):
                    log_critical(f"Camera service via mDNS: {name} ({stype})")
                else:
                    log_info(f"Service: {name} ({stype})")


def phase4_service_discovery(ctx: ScanContext) -> None:
    """Discover services via mDNS, UPnP, ONVIF WS-Discovery."""
    if ctx.args.quick:
        log_phase("4", "Service Discovery (SKIPPED — quick mode)")
        return

    log_phase("4", "Service Discovery (mDNS/UPnP/ONVIF)")

    # mDNS
    if HAS_ZEROCONF:
        _mdns_zeroconf(ctx)
    elif SYSTEM == "Linux" and shutil.which("avahi-browse"):
        _mdns_avahi(ctx)
    elif SYSTEM == "Darwin":
        _mdns_dnssd(ctx)
    else:
        log_warn("Skipping mDNS (no discovery tool available)")

    # UPnP via nmap
    log_info("Scanning for UPnP devices...")
    stdout, _, _ = run_cmd(
        ["nmap", "--script=broadcast-upnp-info"], timeout=45,
    )
    for line in stdout.splitlines():
        if re.search(r"camera|webcam|surveillance|DVR|NVR|IPC|NetworkCamera|SecurityCamera", line, re.IGNORECASE):
            ctx.service_results.append({
                "ip": "", "method": "UPnP", "stype": "SSDP", "name": line.strip(), "txt": "",
            })
            log_warn(f"Camera-related UPnP device: {line.strip()}")

    # ONVIF WS-Discovery via nmap
    log_info("Scanning for ONVIF devices...")
    stdout, _, _ = run_cmd(
        ["nmap", "--script=broadcast-wsdd-discover"], timeout=30,
    )
    if re.search(r"NetworkVideoTransmitter|camera|onvif", stdout, re.IGNORECASE):
        log_critical("ONVIF camera(s) detected via WS-Discovery!")
        for line in stdout.splitlines():
            if re.search(r"Address:|NetworkVideoTransmitter|camera|onvif", line, re.IGNORECASE):
                ctx.service_results.append({
                    "ip": "", "method": "ONVIF", "stype": "WSDD",
                    "name": line.strip(), "txt": "",
                })

    log_ok("Service discovery complete")


# ===========================================================================
# Phase 5: Deep Inspection (HTTP / RTSP)
# ===========================================================================

def _http_inspect(ip: str, port: str) -> list[dict]:
    """Inspect an HTTP endpoint for camera indicators. Returns findings."""
    findings: list[dict] = []
    proto = "https" if port in ("443", "8443") else "http"
    url = f"{proto}://{ip}:{port}/"

    headers_text = ""
    body = ""

    if HAS_REQUESTS:
        try:
            resp = requests.get(url, timeout=5, verify=False, allow_redirects=True,
                                stream=True)
            headers_text = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            body = resp.text[:51200]
        except Exception:
            return findings
    elif shutil.which("curl"):
        # Headers
        out, _, _ = run_cmd(["curl", "-s", "-m", "5", "-k", "-I", url], timeout=10)
        headers_text = out
        # Body
        out, _, _ = run_cmd(["curl", "-s", "-m", "5", "-k", "--max-filesize", "51200", url], timeout=10)
        body = out
    else:
        return findings

    # Check server header
    if re.search(CAMERA_HEADERS, headers_text, re.IGNORECASE):
        server = ""
        m = re.search(r"(?i)^Server:\s*(.+)$", headers_text, re.MULTILINE)
        if m:
            server = m.group(1).strip()
        findings.append({"ip": ip, "port": port, "type": "CAMERA_HEADER", "detail": server})

    # Check body for high-confidence keywords
    if re.search(CAMERA_KEYWORDS_HIGH, body, re.IGNORECASE):
        matches = re.findall(CAMERA_KEYWORDS_HIGH, body, re.IGNORECASE)[:5]
        findings.append({"ip": ip, "port": port, "type": "CAMERA_WEBUI", "detail": ",".join(matches)})
    elif re.search(CAMERA_KEYWORDS_MEDIUM, body, re.IGNORECASE):
        matches = re.findall(CAMERA_KEYWORDS_MEDIUM, body, re.IGNORECASE)[:5]
        findings.append({"ip": ip, "port": port, "type": "POSSIBLE_CAMERA", "detail": ",".join(matches)})

    # Check HTML title
    title_m = re.search(r"<title>([^<]+)</title>", body, re.IGNORECASE)
    if title_m:
        title = title_m.group(1)
        if CAMERA_TITLE_RE.search(title):
            findings.append({"ip": ip, "port": port, "type": "CAMERA_TITLE", "detail": title})

    # Spy-device database checks (HTTP Server header + body model strings)
    if HAS_SPYDEVICES:
        srv_hit = spydevices.match_spy_http_server(headers_text)
        if srv_hit:
            findings.append({"ip": ip, "port": port, "type": "SPY_HTTP_SERVER", "detail": srv_hit})
        model_hit = spydevices.match_spy_model(body)
        if model_hit:
            findings.append({"ip": ip, "port": port, "type": "SPY_MODEL", "detail": model_hit})
        if title_m:
            title_model = spydevices.match_spy_model(title_m.group(1))
            if title_model:
                findings.append({"ip": ip, "port": port, "type": "SPY_MODEL", "detail": title_model})

    return findings


def phase5_deep_inspection(ctx: ScanContext) -> None:
    """Verify cameras via HTTP headers/body and RTSP probing."""
    if ctx.args.quick:
        log_phase("5", "Deep Inspection (SKIPPED — quick mode)")
        return

    log_phase("5", "Deep Inspection (HTTP/RTSP Verification)")

    if not ctx.port_results:
        log_info("No open ports found — skipping deep inspection")
        return

    # Suppress InsecureRequestWarning if using requests
    if HAS_REQUESTS:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    # HTTP inspection
    http_targets: set[tuple[str, str]] = set()
    for pr in ctx.port_results:
        if pr["port"] in ("80", "443", "8080", "8443", "8899"):
            http_targets.add((pr["ip"], pr["port"]))

    if http_targets and (HAS_REQUESTS or shutil.which("curl")):
        log_info("Inspecting HTTP services for camera indicators...")
        for ip, port in http_targets:
            log_dim(f"Checking {ip}:{port}...")
            findings = _http_inspect(ip, port)
            for f in findings:
                ctx.deep_results.append(f)
                if f["type"] == "CAMERA_HEADER":
                    log_critical(f"Camera HTTP server header on {ip}:{port} — {f['detail']}")
                elif f["type"] == "CAMERA_WEBUI":
                    log_critical(f"Camera web UI keywords on {ip}:{port} — {f['detail']}")
                elif f["type"] == "CAMERA_TITLE":
                    log_critical(f"Camera web page title on {ip}:{port} — '{f['detail']}'")
                elif f["type"] == "POSSIBLE_CAMERA":
                    log_warn(f"Possible camera keywords on {ip}:{port} — {f['detail']}")
    else:
        log_warn("Skipping HTTP inspection (no HTTP client available)")

    # RTSP verification via nmap scripts
    rtsp_ips: set[str] = set()
    for pr in ctx.port_results:
        if pr["port"] in ("554", "8554"):
            rtsp_ips.add(pr["ip"])

    if rtsp_ips:
        log_info("Verifying RTSP services...")
        for ip in rtsp_ips:
            log_dim(f"Probing RTSP on {ip}...")
            stdout, _, _ = run_cmd(
                ["nmap", "-sV", "-p", "554,8554", "--script=rtsp-methods", ip],
                timeout=30,
            )
            if re.search(r"RTSP|rtsp-methods|OPTIONS|DESCRIBE|SETUP|PLAY", stdout, re.IGNORECASE):
                ctx.deep_results.append({
                    "ip": ip, "port": "554", "type": "RTSP_CONFIRMED",
                    "detail": "Active RTSP service",
                })
                log_critical(f"CONFIRMED RTSP streaming service on {ip}")

    # Vendor-specific port verification
    vendor_targets: list[dict] = [
        pr for pr in ctx.port_results if pr["port"] in ("8000", "37777", "34567", "34599", "9000")
    ]
    if vendor_targets:
        log_info("Checking vendor-specific ports...")
        for pr in vendor_targets:
            ip, port = pr["ip"], pr["port"]
            if port == "8000":
                ctx.deep_results.append({"ip": ip, "port": port, "type": "HIKVISION_PORT", "detail": "Hikvision SDK port open"})
                log_critical(f"Hikvision SDK port confirmed on {ip}:{port}")
            elif port == "37777":
                ctx.deep_results.append({"ip": ip, "port": port, "type": "DAHUA_PORT", "detail": "Dahua protocol port open"})
                log_critical(f"Dahua protocol port confirmed on {ip}:{port}")
            elif port in ("34567", "34599"):
                ctx.deep_results.append({"ip": ip, "port": port, "type": "XMEYE_PORT", "detail": "XMEye/Chinese NVR port open"})
                log_critical(f"XMEye NVR port confirmed on {ip}:{port}")
            elif port == "9000":
                ctx.deep_results.append({"ip": ip, "port": port, "type": "REOLINK_PORT", "detail": "Reolink port open"})
                log_warn(f"Reolink port on {ip}:{port}")

    log_ok(f"Deep inspection complete: {len(ctx.deep_results)} findings")


# ===========================================================================
# Phase 6: Risk Classification
# ===========================================================================

def phase6_classify(ctx: ScanContext) -> None:
    """Assign risk levels based on all gathered evidence."""
    log_phase("6", "Risk Classification")

    # Build lookup helpers
    ip_ports: dict[str, set[str]] = {}
    for pr in ctx.port_results:
        ip_ports.setdefault(pr["ip"], set()).add(pr["port"])

    ip_deep: dict[str, set[str]] = {}
    for dr in ctx.deep_results:
        ip_deep.setdefault(dr["ip"], set()).add(dr["type"])

    ip_services: dict[str, set[str]] = {}
    for sr in ctx.service_results:
        ip_services.setdefault(sr["ip"], set()).add(sr.get("stype", ""))

    # Traffic anomaly lookup
    ip_traffic: set[str] = set()
    for ta in ctx.traffic_results:
        if ta.ip and ta.ip != "(DNS)":
            ip_traffic.add(ta.ip)

    for device in ctx.oui_results:
        ip = device["ip"]
        mac = device["mac"]
        manufacturer = device["manufacturer"]
        classification = device["classification"]

        open_ports_set = ip_ports.get(ip, set())
        open_ports_str = ",".join(sorted(open_ports_set))
        deep_types = ip_deep.get(ip, set())
        svc_types = ip_services.get(ip, set())

        has_rtsp = bool(open_ports_set & RTSP_PORTS)
        has_http = bool(open_ports_set & HTTP_PORTS)
        has_vendor_port = bool(open_ports_set & VENDOR_PORTS)
        has_camera_webui = bool(deep_types & {"CAMERA_WEBUI", "CAMERA_TITLE"})
        has_camera_header = "CAMERA_HEADER" in deep_types
        has_rtsp_confirmed = "RTSP_CONFIRMED" in deep_types
        has_hikvision_port = "HIKVISION_PORT" in deep_types
        has_dahua_port = "DAHUA_PORT" in deep_types
        has_xmeye_port = "XMEYE_PORT" in deep_types
        has_mdns_camera = bool(svc_types & {
            "_rtsp._tcp", "_camera._tcp", "_nvr._tcp", "_onvif._tcp",
            "_rtsp._tcp.local.", "_camera._tcp.local.", "_nvr._tcp.local.", "_onvif._tcp.local.",
        })

        if has_hikvision_port or has_dahua_port or has_xmeye_port:
            has_vendor_port = True

        # Spy-device database checks
        has_spy_brand = False
        spy_brand_name = ""
        has_spy_combo = False
        spy_combo_desc = ""
        has_spy_model = "SPY_MODEL" in deep_types
        has_spy_server = "SPY_HTTP_SERVER" in deep_types
        if HAS_SPYDEVICES:
            spy_brand_name, has_spy_brand = spydevices.match_spy_oui(mac)
            port_ints = {int(p) for p in open_ports_set if p.isdigit()}
            spy_combo_desc = spydevices.match_spy_port_combo(port_ints) or ""
            has_spy_combo = bool(spy_combo_desc)

        # Classification logic
        risk = "INFO"
        device_type = "Unknown"
        evidence = ""
        recommendation = ""

        # -- CRITICAL (spy-device database matches) --
        if has_spy_brand and (has_rtsp or has_vendor_port or has_spy_combo):
            risk = "CRITICAL"
            device_type = f"Known Spy Camera ({spy_brand_name})"
            evidence = f"Spy-cam manufacturer {spy_brand_name} + streaming ports ({open_ports_str})"
            recommendation = "KNOWN SPY CAMERA HARDWARE. Photograph and document immediately."
        elif has_spy_combo and has_spy_model:
            risk = "CRITICAL"
            device_type = "Spy Camera (confirmed by firmware)"
            evidence = f"Spy-cam port combo ({spy_combo_desc}) + firmware model match"
            recommendation = "CONFIRMED SPY CAMERA FIRMWARE. Document and report."
        elif has_spy_brand:
            risk = "HIGH"
            device_type = f"Known Spy Camera Brand ({spy_brand_name})"
            evidence = f"MAC matches known spy-camera manufacturer: {spy_brand_name}"
            recommendation = "Known spy-camera hardware. Investigate this device."
        elif has_spy_combo:
            risk = "HIGH"
            device_type = "Likely Spy Camera (port signature)"
            evidence = f"Port combination matches: {spy_combo_desc}"
            recommendation = "Port combination matches known spy camera. Investigate."
        elif has_spy_model or has_spy_server:
            risk = "HIGH"
            device_type = "Spy Camera Firmware Detected"
            evidence = "HTTP response matches known spy-camera firmware"
            recommendation = "Spy-camera firmware fingerprint detected. Investigate."

        # -- CRITICAL (original) --
        elif classification == "TIER1_CAMERA" and (has_rtsp or has_vendor_port):
            risk = "CRITICAL"
            device_type = "Surveillance Camera (confirmed)"
            evidence = f"Surveillance manufacturer ({manufacturer}) + streaming/control ports open ({open_ports_str})"
            recommendation = "LIKELY ACTIVE CAMERA. Photograph device location. Contact Airbnb support immediately."
        elif has_rtsp_confirmed:
            risk = "CRITICAL"
            device_type = "RTSP Streaming Device (confirmed)"
            evidence = "Active RTSP streaming service detected"
            recommendation = "CONFIRMED VIDEO STREAMING. Locate and photograph the device. Contact Airbnb."
        elif has_camera_webui or has_camera_header:
            risk = "CRITICAL"
            device_type = "Camera Web Interface (confirmed)"
            evidence = "Camera web UI or server header detected on HTTP"
            recommendation = "CAMERA WEB INTERFACE FOUND. Photograph evidence. Contact Airbnb."
        elif classification == "TIER1_CAMERA" and has_camera_webui:
            risk = "CRITICAL"
            device_type = "Surveillance Camera (confirmed)"
            evidence = "Surveillance manufacturer + camera web interface"
            recommendation = "CONFIRMED CAMERA. Document and report to Airbnb immediately."
        elif has_mdns_camera:
            risk = "CRITICAL"
            device_type = "Camera Service (mDNS)"
            evidence = "Camera/RTSP service advertising via mDNS"
            recommendation = "CAMERA ANNOUNCING ON NETWORK. Locate device. Contact Airbnb."

        # -- HIGH --
        elif classification == "TIER1_CAMERA":
            risk = "HIGH"
            device_type = "Surveillance Equipment"
            evidence = f"Known surveillance manufacturer: {manufacturer}"
            recommendation = "Surveillance manufacturer device on network. Try to locate it physically."
        elif classification == "TIER2_CAMERA":
            risk = "HIGH"
            device_type = "Consumer Camera"
            evidence = f"Known camera brand: {manufacturer}"
            recommendation = "Consumer camera brand detected. Check if disclosed in listing."
        elif classification == "CAMERA_KEYWORD":
            risk = "HIGH"
            device_type = "Camera-Related Device"
            evidence = f"Manufacturer name suggests camera/surveillance: {manufacturer}"
            recommendation = "Camera-related manufacturer. Investigate further."
        elif classification == "UNKNOWN" and has_rtsp:
            risk = "HIGH"
            device_type = "Unknown Device with RTSP"
            evidence = "Unknown manufacturer + RTSP port open"
            recommendation = "Unknown device with video streaming port. Investigate immediately."
        elif classification == "UNKNOWN" and has_vendor_port:
            risk = "HIGH"
            device_type = "Unknown Device with Camera Port"
            evidence = "Unknown manufacturer + vendor-specific camera port open"
            recommendation = "Unknown device with camera-specific port. Investigate."
        elif classification == "MAC_RANDOMIZED" and (has_rtsp or has_vendor_port):
            risk = "HIGH"
            device_type = "Randomized MAC (suspicious ports)"
            evidence = f"Randomized MAC address + camera-related ports ({open_ports_str})"
            recommendation = "Device hiding identity with camera ports open. Investigate immediately."

        # -- MODERATE --
        elif classification == "MAC_RANDOMIZED" and has_http:
            risk = "MODERATE"
            device_type = "Randomized MAC (with web interface)"
            evidence = "Randomized MAC address + HTTP service"
            recommendation = "Device with hidden identity and web server. Likely a phone, but verify."
        elif classification == "IOT_CHIPSET" and (has_rtsp or has_vendor_port):
            risk = "MODERATE"
            device_type = "IoT Device (suspicious ports)"
            evidence = f"IoT chipset ({manufacturer}) + camera-related ports ({open_ports_str})"
            recommendation = "IoT device with suspicious ports. Could be a camera using generic chipset."
        elif classification == "IOT_CHIPSET" and has_http:
            risk = "MODERATE"
            device_type = "IoT Device (with web interface)"
            evidence = f"IoT chipset ({manufacturer}) + HTTP service"
            recommendation = "IoT device with web interface. Check if it's a camera."
        elif classification == "UNKNOWN" and has_http:
            risk = "MODERATE"
            device_type = "Unknown Device (with web interface)"
            evidence = f"Unknown manufacturer + HTTP service on port {open_ports_str}"
            recommendation = "Unidentified device with web server. Try accessing its web interface."
        elif classification == "GENERIC_CHIPSET" and (has_rtsp or has_vendor_port):
            risk = "MODERATE"
            device_type = "Generic Chipset (suspicious ports)"
            evidence = f"Generic chipset ({manufacturer}) + camera ports ({open_ports_str})"
            recommendation = "Generic device with camera-specific ports. Investigate."
        elif classification == "UNKNOWN":
            risk = "MODERATE"
            device_type = "Unidentified Device"
            evidence = f"Unknown manufacturer, MAC: {mac}"
            recommendation = "Cannot identify this device. Try to locate it physically."

        # -- LOW --
        elif classification == "MAC_RANDOMIZED":
            risk = "LOW"
            device_type = "Randomized MAC (likely phone/laptop)"
            evidence = "MAC randomization active — typically modern phone, tablet, or laptop"
            recommendation = "Likely a personal device using privacy MAC. Common on iOS/Android."
        elif classification == "IOT_CHIPSET":
            risk = "LOW"
            device_type = "IoT Device"
            evidence = f"IoT chipset ({manufacturer}), no camera ports"
            recommendation = "Likely a smart home device (plug, sensor, etc.)"
        elif classification == "GENERIC_CHIPSET":
            risk = "LOW"
            device_type = "Network Device"
            evidence = f"Generic chipset ({manufacturer})"
            recommendation = "Likely a router, switch, or network adapter"

        # -- INFO --
        elif classification in ("KNOWN_SAFE", "KNOWN_OTHER"):
            risk = "INFO"
            device_type = "Known Device"
            evidence = f"Identified manufacturer: {manufacturer}"
            recommendation = "Known device type, no camera indicators"

        ctx.counts[risk] += 1
        ctx.classifications.append({
            "risk": risk, "ip": ip, "mac": mac, "manufacturer": manufacturer,
            "device_type": device_type, "open_ports": open_ports_str,
            "evidence": evidence, "recommendation": recommendation,
        })

    # Write pipe-delimited files for report_html.py
    class_path = os.path.join(ctx.scan_dir, "classifications.txt")
    with open(class_path, "w", encoding="utf-8") as fh:
        for c in ctx.classifications:
            fh.write(
                f"{c['risk']}|{c['ip']}|{c['mac']}|{c['manufacturer']}|"
                f"{c['device_type']}|{c['open_ports']}|{c['evidence']}|{c['recommendation']}\n"
            )

    summary_path = os.path.join(ctx.scan_dir, "summary_counts.txt")
    with open(summary_path, "w", encoding="utf-8") as fh:
        fh.write(
            f"{ctx.counts['CRITICAL']}|{ctx.counts['HIGH']}|"
            f"{ctx.counts['MODERATE']}|{ctx.counts['LOW']}|{ctx.counts['INFO']}\n"
        )

    # Print classification summary
    print()
    log_info("Classification complete:")
    cc, hc, mc, lc, ic = (
        ctx.counts["CRITICAL"], ctx.counts["HIGH"],
        ctx.counts["MODERATE"], ctx.counts["LOW"], ctx.counts["INFO"],
    )
    if cc > 0:
        log_critical(f"{ICON_CRITICAL} CRITICAL: {cc}")
    if hc > 0:
        log_warn(f"{ICON_HIGH} HIGH: {hc}")
    if mc > 0:
        log_info(f"{ICON_MODERATE} MODERATE: {mc}")
    if lc > 0:
        log_ok(f"{ICON_LOW} LOW: {lc}")
    if ic > 0:
        log_dim(f"{ICON_INFO} INFO: {ic}")


# ===========================================================================
# Phase 7: Reports (terminal + HTML)
# ===========================================================================

def phase7_report_terminal(ctx: ScanContext) -> None:
    """Print the final report to the terminal."""
    log_phase("7", "Report")

    duration = int(time.time() - ctx.start_time)
    mode = "Quick" if ctx.args.quick else "Full"

    print()
    print(f"{BOLD}{WHITE}{'=' * 62}{NC}")
    print(f"{BOLD}{WHITE}        SURVEILLANCE DEVICE SCAN REPORT{NC}")
    print(f"{BOLD}{WHITE}{'=' * 62}{NC}")
    print()
    print(f"  {DIM}Date:      {time.strftime('%Y-%m-%d %H:%M:%S')}{NC}")
    print(f"  {DIM}Network:   {ctx.subnet} via {ctx.interface}{NC}")
    print(f"  {DIM}Gateway:   {ctx.gateway}{NC}")
    print(f"  {DIM}Scanner:   {ctx.my_ip}{NC}")
    print(f"  {DIM}Duration:  {duration}s{NC}")
    print(f"  {DIM}Mode:      {mode}{NC}")
    print()

    cc = ctx.counts["CRITICAL"]
    hc = ctx.counts["HIGH"]
    mc = ctx.counts["MODERATE"]
    lc = ctx.counts["LOW"]
    ic = ctx.counts["INFO"]

    print(f"  {BOLD}--- RISK SUMMARY ---{NC}")
    print(f"  {ICON_CRITICAL} Critical:  {cc}")
    print(f"  {ICON_HIGH} High:      {hc}")
    print(f"  {ICON_MODERATE} Moderate:  {mc}")
    print(f"  {ICON_LOW} Low:       {lc}")
    print(f"  {ICON_INFO} Info:      {ic}")
    print(f"  {BOLD}{'─' * 55}{NC}")
    print()

    if cc > 0:
        print(f"  {RED}{BOLD}!!!  SURVEILLANCE DEVICES LIKELY PRESENT  !!!{NC}")
        print()
    elif hc > 0:
        print(f"  {ORANGE}{BOLD}!!!  SUSPICIOUS DEVICES DETECTED — Investigation needed{NC}")
        print()

    # Device details sorted by risk
    print(f"  {BOLD}--- DEVICE DETAILS ---{NC}")
    print()

    risk_order = ["CRITICAL", "HIGH", "MODERATE", "LOW", "INFO"]
    risk_colors = {
        "CRITICAL": RED, "HIGH": ORANGE, "MODERATE": YELLOW,
        "LOW": GREEN, "INFO": BLUE,
    }
    risk_icons = {
        "CRITICAL": ICON_CRITICAL, "HIGH": ICON_HIGH, "MODERATE": ICON_MODERATE,
        "LOW": ICON_LOW, "INFO": ICON_INFO,
    }

    for level in risk_order:
        devices = [c for c in ctx.classifications if c["risk"] == level]
        if not devices:
            continue
        color = risk_colors[level]
        icon = risk_icons[level]
        for d in devices:
            print(f"  {icon} {color}{BOLD}[{d['risk']}]{NC} {BOLD}{d['ip']}{NC}")
            print(f"      MAC:           {d['mac']}")
            print(f"      Manufacturer:  {d['manufacturer'] or 'Unknown'}")
            print(f"      Device Type:   {d['device_type']}")
            if d["open_ports"]:
                print(f"      Open Ports:    {d['open_ports']}")
            print(f"      Evidence:      {d['evidence']}")
            print(f"      {color}Action:        {d['recommendation']}{NC}")
            print()

    # Action guide
    if cc > 0 or hc > 0:
        print(f"  {BOLD}{RED}--- WHAT TO DO NOW ---{NC}")
        print()
        print(f"  {RED}1.{NC} Do NOT disconnect or tamper with the device")
        print(f"  {RED}2.{NC} Photograph the device and its location")
        print(f"  {RED}3.{NC} Save this scan report as evidence")
        print(f"  {RED}4.{NC} Contact Airbnb Support:")
        print(f"      - Open the Airbnb app > Your Trips > Select reservation")
        print(f"      - Tap 'Get Help' > 'Report a safety concern'")
        print(f"      - Or call Airbnb Emergency: +1-855-424-7262")
        print(f"  {RED}5.{NC} If you feel unsafe, leave the property immediately")
        print(f"  {RED}6.{NC} Consider contacting local law enforcement")
        print(f"      (hidden cameras are illegal in most jurisdictions)")
        print()

    # Limitations
    print(f"  {BOLD}--- LIMITATIONS ---{NC}")
    print()
    print(f"  {DIM}This scan covers devices connected to the same WiFi network.{NC}")
    print(f"  {DIM}The following are NOT detected:{NC}")
    print(f"  {DIM}  - Cameras on a separate VLAN or wired-only network{NC}")
    print(f"  {DIM}  - Cellular-connected cameras (4G/LTE){NC}")
    print(f"  {DIM}  - Cameras that are powered off or in standby{NC}")
    print(f"  {DIM}  - Devices using MAC address randomization{NC}")
    print(f"  {DIM}  - Local storage cameras not connected to any network{NC}")
    print(f"  {DIM}  - Audio-only recording devices (bugs){NC}")
    print(f"  {DIM}For comprehensive detection, also perform a physical inspection.{NC}")
    print()
    print(f"  {BOLD}--- RENTAL POLICY ---{NC}")
    print()
    print(f"  {DIM}Major rental platforms prohibit indoor surveillance cameras:{NC}")
    print()
    print(f"  {RED}▪{NC} {DIM}Airbnb — All indoor cameras prohibited, even if off.{NC}")
    print(f"    {DIM}https://www.airbnb.com/help/article/3061{NC}")
    print(f"  {ORANGE}▪{NC} {DIM}Booking.com — Cameras only in common areas, must be disclosed.{NC}")
    print(f"    {DIM}https://partner.booking.com/en-us/help/legal-security/security/requirements-and-regulations-surveillance-devices{NC}")
    print(f"  {YELLOW}▪{NC} {DIM}Vrbo — Indoor cameras prohibited. Outdoor must be disclosed.{NC}")
    print(f"    {DIM}https://www.vrbo.com/tlp/trust-and-safety/use-of-surveillance-policy{NC}")
    print()


def phase7_report_html(ctx: ScanContext) -> None:
    """Generate HTML report via report_html.py."""
    if ctx.args.no_html:
        return

    script_dir = Path(__file__).resolve().parent
    report_script = script_dir / "report_html.py"

    if not report_script.exists():
        log_warn(f"HTML report script not found: {report_script}")
        return

    html_output = ctx.report_dir / f"privacy-scan-{ctx.timestamp}.html"
    class_file = os.path.join(ctx.scan_dir, "classifications.txt")
    summary_file = os.path.join(ctx.scan_dir, "summary_counts.txt")
    duration = int(time.time() - ctx.start_time)
    mode = "Quick" if ctx.args.quick else "Full"
    lang = ctx.args.lang

    cmd = [
        sys.executable, str(report_script),
        "--classifications", class_file,
        "--summary", summary_file,
        "--output", str(html_output),
        "--subnet", ctx.subnet,
        "--interface", ctx.interface,
        "--gateway", ctx.gateway,
        "--scanner-ip", ctx.my_ip,
        "--duration", str(duration),
        "--mode", mode,
        "--lang", lang,
    ]

    stdout, stderr, rc = run_cmd(cmd, timeout=30)
    if rc == 0:
        log_ok(f"HTML report saved to: {html_output}")
    else:
        log_warn(f"HTML report generation failed: {stderr}")


# ===========================================================================
# CLI entry point
# ===========================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Privacy Scanner — WiFi Surveillance Device Detector (Cross-Platform)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 scan.py                       # Full auto-detect scan\n"
            "  sudo python3 scan.py --quick                # Skip deep inspection\n"
            "  sudo python3 scan.py --interface wlan0      # Specify interface\n"
            "  sudo python3 scan.py --subnet 10.0.0.0/24   # Specify subnet\n"
            "  python3 scan.py --no-html --lang en          # English, no HTML report\n"
        ),
    )
    parser.add_argument("--interface", default="", help="Network interface (auto-detected)")
    parser.add_argument("--subnet", default="", help="Subnet to scan in CIDR (auto-detected)")
    parser.add_argument("--output-dir", default="./privacy-scan-results",
                        help="Output directory (default: ./privacy-scan-results)")
    parser.add_argument("--quick", action="store_true",
                        help="Skip phases 4-5 (service discovery and deep inspection)")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report generation")
    parser.add_argument("--lang", default="pt", choices=["pt", "en", "es"],
                        help="Report language (default: pt)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print()
    print(f"{BOLD}{CYAN}{'=' * 58}{NC}")
    print(f"{BOLD}{WHITE}  Privacy Scanner — WiFi Surveillance Device Detector{NC}")
    print(f"{BOLD}{WHITE}  Cross-Platform Edition ({SYSTEM}){NC}")
    print(f"{BOLD}{CYAN}{'=' * 58}{NC}")

    ctx = ScanContext(args)

    # Phase 0: prerequisites
    phase0_prerequisites(ctx)

    # Phase 0.5: network detection
    phase05_network_detection(ctx)

    # Phase 1: host discovery
    phase1_host_discovery(ctx)

    # Phase 2: OUI analysis
    phase2_oui_analysis(ctx)

    # Phase 3: port scanning
    phase3_port_scan(ctx)

    # Phase 4: service discovery (skipped in --quick mode)
    phase4_service_discovery(ctx)

    # Phase 5: deep inspection (skipped in --quick mode)
    phase5_deep_inspection(ctx)

    # Phase 5c: traffic anomaly detection
    if HAS_TRAFFIC:
        log_phase("5c", "Traffic Anomaly Detection")
        ctx.traffic_results = traffic_mod.scan_traffic(
            interface=ctx.interface, quick=ctx.args.quick,
        )
        if ctx.traffic_results:
            for ta in ctx.traffic_results:
                log_warn(f"Traffic anomaly: {ta.detail}")
        else:
            log_ok("No suspicious traffic patterns detected")

    # Phase 6: risk classification
    phase6_classify(ctx)

    # Phase 7: terminal report
    phase7_report_terminal(ctx)

    # Phase 7: HTML report
    phase7_report_html(ctx)

    # Final summary
    duration = int(time.time() - ctx.start_time)
    print(f"  {BOLD}Scan completed in {duration}s{NC}")
    print(f"  {DIM}Results saved to: {ctx.scan_dir}{NC}")
    if not args.no_html:
        print(f"  {DIM}HTML reports in:  {ctx.report_dir}{NC}")
    print()


if __name__ == "__main__":
    main()
