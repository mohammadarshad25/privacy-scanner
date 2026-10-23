#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Network traffic anomaly detection — catch cameras uploading to cloud relays.

Three detection tiers (lightest to heaviest):
  1. DNS cache check     — parse systemd-resolved journal for P2P domain lookups
  2. Conntrack check     — scan connection tracking table for outbound camera traffic
  3. Upload bandwidth    — short tcpdump capture to find sustained upload streams

All checks are passive / read-only and require root on Linux.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field

try:
    import spydevices
except ImportError:
    from . import spydevices  # type: ignore[no-redef]

SYSTEM = platform.system()


@dataclass
class TrafficAnomaly:
    ip: str
    mac: str = ""
    anomaly_type: str = ""           # DNS_P2P, CONNTRACK_P2P, UPLOAD_SUSTAINED
    detail: str = ""
    bytes_out: int = 0
    duration: float = 0
    destinations: list[str] = field(default_factory=list)


def _run(cmd: list[str], timeout: int = 15) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Tier 1: DNS cache — did anyone on this network resolve P2P camera domains?
# ---------------------------------------------------------------------------

def check_dns_cache() -> list[TrafficAnomaly]:
    """Parse systemd-resolved journal for P2P camera domain queries."""
    anomalies: list[TrafficAnomaly] = []
    if SYSTEM != "Linux":
        return anomalies
    if not shutil.which("journalctl"):
        return anomalies

    out = _run(["journalctl", "-u", "systemd-resolved", "--since", "-1h",
                "--no-pager", "-q"], timeout=10)
    for line in out.splitlines():
        for domain in spydevices.P2P_DOMAINS:
            if domain in line.lower():
                anomalies.append(TrafficAnomaly(
                    ip="(DNS)",
                    anomaly_type="DNS_P2P",
                    detail=f"P2P camera domain resolved: {domain}",
                    destinations=[domain],
                ))
                break
    return anomalies


# ---------------------------------------------------------------------------
# Tier 2: Conntrack — outbound connections to camera ports / P2P relays
# ---------------------------------------------------------------------------

def check_conntrack() -> list[TrafficAnomaly]:
    """Parse conntrack for outbound connections to camera ports/relays."""
    anomalies: list[TrafficAnomaly] = []
    if SYSTEM != "Linux":
        return anomalies
    if not shutil.which("conntrack"):
        return anomalies
    if os.geteuid() != 0:
        return anomalies

    out = _run(["conntrack", "-L", "-o", "extended"], timeout=10)
    seen: set[str] = set()
    for line in out.splitlines():
        m = re.search(r"src=(\d+\.\d+\.\d+\.\d+).*dst=(\d+\.\d+\.\d+\.\d+).*dport=(\d+)", line)
        if not m:
            continue
        src, dst, dport = m.group(1), m.group(2), int(m.group(3))
        if spydevices.is_p2p_port(dport):
            key = f"{src}->{dst}:{dport}"
            if key not in seen:
                seen.add(key)
                anomalies.append(TrafficAnomaly(
                    ip=src,
                    anomaly_type="CONNTRACK_P2P",
                    detail=f"{src} → {dst}:{dport} (P2P camera port)",
                    destinations=[dst],
                ))
    return anomalies


# ---------------------------------------------------------------------------
# Tier 3: tcpdump upload bandwidth — find devices pushing sustained uploads
# ---------------------------------------------------------------------------

def monitor_upload_bandwidth(interface: str = "", duration: int = 30) -> list[TrafficAnomaly]:
    """Short tcpdump capture to find sustained outbound upload streams."""
    anomalies: list[TrafficAnomaly] = []
    if SYSTEM != "Linux":
        return anomalies
    if not shutil.which("tcpdump"):
        return anomalies
    if os.geteuid() != 0:
        return anomalies

    cmd = ["tcpdump", "-c", "10000", "-nn", "-q", "-l"]
    if interface:
        cmd += ["-i", interface]
    cmd += ["-w", "-"]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        return anomalies

    # Parse with tcpdump -r
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        pcap_path = f.name

    cmd2 = ["tcpdump", "-nn", "-q", "-l"]
    if interface:
        cmd2 += ["-i", interface]

    # Count bytes per source IP
    ip_bytes: dict[str, int] = {}
    out = _run(["tcpdump", "-nn", "-r", pcap_path, "-q"], timeout=30) if os.path.exists(pcap_path) else ""
    for line in out.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\.\d+ > .* length (\d+)", line)
        if m:
            src_ip = m.group(1)
            length = int(m.group(2))
            ip_bytes[src_ip] = ip_bytes.get(src_ip, 0) + length

    try:
        os.unlink(pcap_path)
    except OSError:
        pass

    threshold = spydevices.UPLOAD_THRESHOLD_BPS * duration
    for ip, total in ip_bytes.items():
        if total > threshold:
            rate_kbps = total / duration / 1024
            anomalies.append(TrafficAnomaly(
                ip=ip,
                anomaly_type="UPLOAD_SUSTAINED",
                detail=f"{ip} uploaded {total // 1024} KB in {duration}s ({rate_kbps:.0f} KB/s avg)",
                bytes_out=total,
                duration=duration,
            ))
    return anomalies


# ---------------------------------------------------------------------------
# Combined scan
# ---------------------------------------------------------------------------

def scan_traffic(interface: str = "", quick: bool = False) -> list[TrafficAnomaly]:
    """Run all traffic anomaly checks and return combined results."""
    results: list[TrafficAnomaly] = []
    results.extend(check_dns_cache())
    results.extend(check_conntrack())
    if not quick:
        results.extend(monitor_upload_bandwidth(interface))
    return results
