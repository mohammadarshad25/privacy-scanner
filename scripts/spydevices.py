#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Known spy-device database — MAC OUI prefixes, model strings, default ports,
and HTTP fingerprints for cheap P2P cameras that evade standard brand detection.

These are devices specifically marketed for covert use or widely used as hidden
cameras: V380 Pro, XMEye/DVR, CamHi, generic ESP32-CAM boards, Tuya smart-home
cameras with cloud relay, and similar.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# P2P relay ports and domains used by cheap camera firmware
# ---------------------------------------------------------------------------
P2P_PORTS: set[int] = {
    32100,   # Tutk / IOTC (V380 Pro, many P2P cameras)
    34567,   # XMEye / NetSurveillance DVR
    34568,   # XMEye media port
    6000,    # CamHi / HiP2P
    8089,    # Tuya camera MQTT
    6668,    # Tuya camera video
    9090,    # PPPP generic P2P
    12323,   # XMEye telnet backdoor
    23456,   # Generic P2P pairing
}

P2P_DOMAINS: list[str] = [
    "tutk.iotcplatform.com",
    "p2p.xiongmaitech.com",
    "p2p.xmcsrv.net",
    "cltdv.bc-br.com",
    "a1.tuyacn.com",
    "a1.tuyaus.com",
    "a1.tuyaeu.com",
    "p2p-1.ipcamera.info",
    "cloud.eye4.cn",
    "openapi.tuyaus.com",
]

P2P_DOMAIN_RE = re.compile(
    r"tutk\.iotcplatform|xiongmaitech|xmcsrv|tuyacn|tuyaus|tuyaeu|"
    r"ipcamera\.info|eye4\.cn|bc-br\.com",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Spy-device OUI prefixes (Tier 3 — covert / P2P only cameras)
# ---------------------------------------------------------------------------
SPY_OUIS: dict[str, str] = {}

# V380 / V380 Pro (uses Tutk P2P, very common on AliExpress as "mini camera")
for _o in "B09FBA E868E7 E0F89B 2C26C5 48EA63".split():
    SPY_OUIS[_o] = "V380 Pro"

# XMEye / Xiongmai (NetSurveillance DVR chipset, backdoors documented)
for _o in "00126C 9C1465 E03E44 00121E 001210 00301A".split():
    SPY_OUIS[_o] = "XMEye/Xiongmai"

# CamHi / HiP2P (another mass-market P2P firmware)
for _o in "FC7C02 E8AB4A 44EF43".split():
    SPY_OUIS[_o] = "CamHi/HiP2P"

# ESP32-CAM boards (Espressif — used in many DIY hidden cameras)
for _o in "24D7EB 246F28 3CE90E 080027 30AEA4 A4CF12 BCDD61 D8BFC0 CC50E3 847D6C".split():
    SPY_OUIS[_o] = "ESP32-CAM (Espressif)"

# Tuya smart-home cameras
for _o in "D8F15B 68572D 842E14 7CF666 10D561".split():
    SPY_OUIS[_o] = "Tuya Camera"

# Goke/Ingenic chipset cameras (SoC in many no-brand spy cams)
for _o in "00E09E 7C2400".split():
    SPY_OUIS[_o] = "Goke/Ingenic SoC Camera"

# ---------------------------------------------------------------------------
# Model-string patterns found in HTTP pages of spy cameras
# ---------------------------------------------------------------------------
SPY_MODEL_PATTERNS = re.compile(
    r"V380|XMEye|NetSurveillance|NETSurveillanceWEB|CamHi|HiP2P|"
    r"TENVIS|Wansview|Besder|ANRAN|Hiseeu|Sricam|VStarcam|Yoosee|"
    r"P6SLite|CamHipro|Eye4|ESeeCloud",
    re.IGNORECASE,
)

# HTTP Server headers specific to spy camera firmware
SPY_HTTP_SERVERS = re.compile(
    r"DVRDVS-Webs|Boa/0\.9[34]|thttpd|GoAhead-Webs|mini_httpd|"
    r"uhttpd|JAWS/1\.|Netwave IP Camera|alphapd",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Port combinations — a device with THIS set of ports is almost certainly a camera
# ---------------------------------------------------------------------------
SPY_PORT_COMBOS: list[tuple[set[int], str]] = [
    ({554, 80, 8899},       "Hikvision-style (RTSP + HTTP + SDK)"),
    ({37777, 80, 554},      "Dahua-style (control + HTTP + RTSP)"),
    ({34567, 80},           "XMEye DVR (cmd + HTTP)"),
    ({32100, 80},           "V380/Tutk P2P camera"),
    ({6000, 80},            "CamHi/HiP2P camera"),
    ({554, 8080},           "Generic IP camera (RTSP + alt HTTP)"),
    ({9090, 80},            "PPPP P2P camera"),
    ({6668, 8089, 80},      "Tuya camera (video + MQTT + HTTP)"),
]

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------
UPLOAD_THRESHOLD_BPS = 100_000   # 100 KB/s sustained → likely video
VIDEO_STREAMING_PORTS: set[int] = {554, 8554, 8080, 32100, 34567, 6000, 6668}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def match_spy_oui(mac: str) -> tuple[str, bool]:
    """Return (brand, True) if MAC prefix is a known spy-device OUI."""
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    brand = SPY_OUIS.get(prefix, "")
    return brand, bool(brand)


def match_spy_model(text: str) -> str | None:
    """Return model name if text contains a spy camera model string."""
    m = SPY_MODEL_PATTERNS.search(text)
    return m.group(0) if m else None


def match_spy_http_server(header: str) -> str | None:
    """Return server name if HTTP Server header matches spy camera firmware."""
    m = SPY_HTTP_SERVERS.search(header)
    return m.group(0) if m else None


def match_p2p_domain(domain: str) -> bool:
    """Return True if domain is a known P2P camera relay."""
    return bool(P2P_DOMAIN_RE.search(domain))


def match_spy_port_combo(open_ports: set[int]) -> str | None:
    """Return description if the open port set matches a known spy-camera combo."""
    for combo, desc in SPY_PORT_COMBOS:
        if combo <= open_ports:
            return desc
    return None


def is_p2p_port(port: int) -> bool:
    """Return True if port is a known P2P camera relay port."""
    return port in P2P_PORTS


def is_video_streaming_port(port: int) -> bool:
    """Return True if port is commonly used for video streaming."""
    return port in VIDEO_STREAMING_PORTS
