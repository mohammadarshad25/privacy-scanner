#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# ============================================================================
# Privacy Scanner — WiFi Surveillance Device Detector (Linux-only)
# Defensive security tool for detecting hidden cameras in rental accommodations
#
# NOTE: This script is Linux-only. For macOS and Windows, use:
#   sudo python3 scripts/scan.py
#
# Usage: sudo bash scan.sh [OPTIONS]
#   --interface IFACE    Network interface (auto-detected if omitted)
#   --subnet CIDR        Subnet to scan (auto-detected if omitted)
#   --output-dir DIR     Output directory (default: ./privacy-scan-results)
#   --quick              Skip service discovery and deep inspection (phases 4-5)
#   --no-html            Skip HTML report generation
#   --help               Show this help
#
# Requires: nmap (mandatory), arp-scan (recommended), avahi-browse (optional),
#           curl (optional), python3 (optional, for HTML report)
# ============================================================================

set -euo pipefail

# ── Colors & Formatting ─────────────────────────────────────────────────────
RED='\033[0;31m'
ORANGE='\033[0;33m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Risk level icons ────────────────────────────────────────────────────────
ICON_CRITICAL="🔴"
ICON_HIGH="🟠"
ICON_MODERATE="🟡"
ICON_LOW="🟢"
ICON_INFO="🔵"

# ── Global Configuration ────────────────────────────────────────────────────
SCAN_DIR=""
REPORT_DIR="./privacy-scan-results"
IFACE=""
SUBNET=""
GATEWAY=""
MY_IP=""
QUICK_MODE=0
NO_HTML=0
LANG_CODE="pt"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
START_TIME=$(date +%s)

# Tools availability flags
HAS_ARPSCAN=0
HAS_AVAHI=0
HAS_CURL=0
HAS_PYTHON3=0
HAS_NMAP_MACDB=0
IS_ROOT=0

# Camera ports to scan
CAMERA_PORTS="554,8554,80,443,8080,8443,8000,8200,37777,34567,34599,9000,3702,1935,5000,6667,8899,49152,7070,9527"

# ── Tier 1: Dedicated Surveillance OUI prefixes (uppercase, no colons) ──────
# These are ALWAYS cameras/surveillance equipment
declare -A TIER1_OUIS
# Hikvision
for oui in 00BC99 040312 04EECD 083BC1 085411 08A189 08CC81 0C75D2 1012FB \
           1868CB 188025 240F9B 2428FD 2432AE 244845 2857BE 2CA59C 340962 \
           3C1BF8 40ACBF 4419B6 4447CC 44A642 48785B 4C1F86 4C62DF 4CBD8F \
           4CF5DC 50E538 548C81 54C415 5803FB 5850ED 5C345B 64DB8B 686DBC \
           743FC2 80489F 807C62 80BEAF 80F5AE 849459 849A40 88DE39 8C22D2 \
           8CE748 94E1AC 988B0A 989DE5 98DF82 98F112 A0FF0C A41437 A42902 \
           A44BD9 A4A459 A4D5C2 ACCB51 ACB92F B4A382 BC2978 BC5E33 BC9B5E \
           BCAD28 BCBAC2 C0517E C056E3 C06DED C42F90 C8A702 D4E853 DC07F8 \
           DCD26A E0BAAD E0CA3C E0DF13 E4D58B E8A0ED ECA971 ECC89C F84DFC \
           FC9FFD; do
    TIER1_OUIS[$oui]="Hikvision"
done
# EZVIZ (Hikvision consumer brand)
for oui in 0CA64C 20BBBC 34C6DD 54D60D 588FCF 64244D 64F2FB 78A6A0 78C1AE \
           94EC13 AC1C26 EC97E0 F47018; do
    TIER1_OUIS[$oui]="EZVIZ"
done
# Dahua
for oui in 08EDED 14A78B 24526A 30DDAA 38AF29 3CE36B 3CEF8C 407AA4 4C11BF \
           4C99E8 5CF51A 64FD29 6C1C71 74C929 8CE9B4 9002A9 98F9CC 9C1463 \
           A0BD1D A8CA87 B44C3B BC325F C0395A C4AAC4 D4430E E02EFE E0508B \
           E4246C F4B1C2 F8CE07 FC5F49 FCB69D; do
    TIER1_OUIS[$oui]="Dahua"
done
# Amcrest
for oui in 00651E 9C8ECD A06032; do
    TIER1_OUIS[$oui]="Amcrest"
done
# Uniview
for oui in 48EA63 6CF17E 88263F C47905; do
    TIER1_OUIS[$oui]="Uniview"
done
# Axis Communications
for oui in 00408C ACCC8E B8A44F E82725; do
    TIER1_OUIS[$oui]="Axis"
done
# Reolink
TIER1_OUIS[EC71DB]="Reolink"
# Prama Hikvision India
TIER1_OUIS[24B105]="Hikvision-India"

# ── Tier 2: Consumer Camera Brands ──────────────────────────────────────────
declare -A TIER2_OUIS
# Wyze
for oui in 2CAA8E 7C78B2 80482C D03F27 F0C88B; do
    TIER2_OUIS[$oui]="Wyze"
done
# Blink
for oui in 3CA070 70AD43 74AB93 F074C1; do
    TIER2_OUIS[$oui]="Blink"
done
# Arlo
for oui in 486264 A41162 FC9C98; do
    TIER2_OUIS[$oui]="Arlo"
done
# Nest Labs
for oui in 18B430 641666; do
    TIER2_OUIS[$oui]="NestLabs"
done
# Foscam (missing from nmap DB)
for oui in C0562D C8D719 008E10 E0B9E5 001EF2; do
    TIER2_OUIS[$oui]="Foscam"
done
# Yi/Xiaomi cameras
for oui in 78025E 7811DC 34CE00 04CF8C 28D127 58A60B 641327; do
    TIER2_OUIS[$oui]="Yi-Xiaomi"
done
# Eufy
for oui in 98F1B1 78C57D 8CEEA7; do
    TIER2_OUIS[$oui]="Eufy"
done

# ── Camera HTTP keywords ────────────────────────────────────────────────────
CAMERA_KEYWORDS_HIGH="camera|webcam|ipcam|ip.cam|ipcamera|netcam|DVR|NVR|surveillance|security.cam|CCTV|hikvision|dahua|amcrest|reolink|foscam|wyze|ONVIF|onvif|rtsp://|live.view|liveview|snapshot|motion.detect|pan.tilt|PTZ|night.vision|DNVRS-Webs|App-webs|XMEye|NETSurveillance|IPCamera|IPCam|webcamXP|Yawcam|Blue.Iris|ZoneMinder|Shinobi|MotionEye|Frigate|ISAPI|Streaming/Channels|cam/realmonitor"

# Whole words only: generic terms otherwise match inside identifiers (e.g. "qrCodeContainer")
CAMERA_KEYWORDS_MEDIUM="\\b(stream|video|media.server|MJPEG|H\\.264|H\\.265|codec|bitrate|firmware|device.info)\\b"

# ── HTTP Server headers that indicate cameras ───────────────────────────────
CAMERA_HEADERS="DNVRS-Webs|App-webs|Hikvision|Dahua|DH-IPC|uc-httpd|GoAhead-Webs|JAWS/|Boa/"

# ── Helper Functions ────────────────────────────────────────────────────────

log_phase() {
    local phase=$1
    local name=$2
    echo ""
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${WHITE}  Phase ${phase}: ${name}${NC}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

log_info() {
    echo -e "  ${BLUE}[*]${NC} $1"
}

log_ok() {
    echo -e "  ${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "  ${YELLOW}[!]${NC} $1"
}

log_critical() {
    echo -e "  ${RED}[!!!]${NC} ${BOLD}$1${NC}"
}

log_dim() {
    echo -e "  ${DIM}$1${NC}"
}

mac_to_oui() {
    # Convert MAC address to OUI format (uppercase, no separators)
    local mac="$1"
    echo "$mac" | tr -d ':-' | tr 'a-f' 'A-F' | cut -c1-6
}

is_mac_randomized() {
    # Check if MAC has the "locally administered" bit set (bit 1 of first octet)
    # This indicates MAC randomization (common on modern phones/laptops)
    local mac="$1"
    local first_octet
    first_octet=$(echo "$mac" | tr -d ':-' | cut -c1-2 | tr 'a-f' 'A-F')
    local decimal
    decimal=$((16#$first_octet))
    # Bit 1 (second-least-significant) = locally administered
    if (( (decimal & 2) != 0 )); then
        return 0  # true: randomized
    fi
    return 1  # false: globally unique (real OUI)
}

# ── Phase 0: Prerequisites ──────────────────────────────────────────────────

check_prerequisites() {
    log_phase "0" "Prerequisites Check"

    # Check root
    if [[ $EUID -eq 0 ]]; then
        IS_ROOT=1
        log_ok "Running as root"
    else
        log_warn "Not running as root — some scans will be limited"
        log_warn "For best results, run: sudo bash $0"
    fi

    # Check nmap (mandatory)
    if command -v nmap &>/dev/null; then
        local nmap_ver
        nmap_ver=$(nmap --version 2>/dev/null | head -1)
        log_ok "nmap: ${nmap_ver}"
    else
        echo -e "  ${RED}[X] nmap is NOT installed — cannot proceed${NC}"
        echo ""
        echo "  Install nmap:"
        echo "    Arch:   sudo pacman -S nmap"
        echo "    Debian: sudo apt install nmap"
        echo "    Fedora: sudo dnf install nmap"
        echo "    macOS:  brew install nmap"
        exit 1
    fi

    # Check arp-scan
    if command -v arp-scan &>/dev/null; then
        HAS_ARPSCAN=1
        log_ok "arp-scan: $(arp-scan --version 2>/dev/null | head -1)"
    else
        log_warn "arp-scan not found (recommended for better host discovery)"
    fi

    # Check avahi-browse
    if command -v avahi-browse &>/dev/null; then
        HAS_AVAHI=1
        log_ok "avahi-browse: available"
    else
        log_warn "avahi-browse not found (optional, for mDNS discovery)"
    fi

    # Check curl
    if command -v curl &>/dev/null; then
        HAS_CURL=1
        log_ok "curl: available"
    else
        log_warn "curl not found (optional, for HTTP inspection)"
    fi

    # Check python3
    if command -v python3 &>/dev/null; then
        HAS_PYTHON3=1
        log_ok "python3: available (for HTML report)"
    else
        log_warn "python3 not found (HTML report will use simplified format)"
    fi

    # Check nmap MAC database
    if [[ -f /usr/share/nmap/nmap-mac-prefixes ]]; then
        HAS_NMAP_MACDB=1
        local db_count
        db_count=$(wc -l < /usr/share/nmap/nmap-mac-prefixes)
        log_ok "nmap MAC database: ${db_count} entries"
    else
        log_warn "nmap MAC database not found — using embedded OUI list only"
    fi
}

# ── Network Detection ────────────────────────────────────────────────────────

detect_network() {
    log_phase "0.5" "Network Detection"

    if [[ -z "$IFACE" ]]; then
        IFACE=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -1)
        if [[ -z "$IFACE" ]]; then
            echo -e "  ${RED}[X] Could not detect network interface${NC}"
            echo "  Specify manually with: --interface eth0"
            exit 1
        fi
        log_ok "Interface: ${IFACE} (auto-detected)"
    else
        log_ok "Interface: ${IFACE} (user-specified)"
    fi

    if [[ -z "$SUBNET" ]]; then
        # Get IP and CIDR from interface
        MY_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
        local cidr
        cidr=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP 'inet \K[\d./]+' | head -1)
        # Calculate network address
        SUBNET=$(python3 -c "import ipaddress; print(ipaddress.ip_interface('${cidr}').network)" 2>/dev/null || echo "${MY_IP%.*}.0/24")
        log_ok "Subnet: ${SUBNET} (auto-detected)"
    else
        MY_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
        log_ok "Subnet: ${SUBNET} (user-specified)"
    fi

    GATEWAY=$(ip route 2>/dev/null | grep default | awk '{print $3}' | head -1)
    log_ok "Gateway: ${GATEWAY}"
    log_ok "Scanner IP: ${MY_IP}"

    # Check for multiple SSIDs (hint at separate camera network)
    if command -v nmcli &>/dev/null; then
        local ssid_count
        ssid_count=$(nmcli -t -f SSID dev wifi list 2>/dev/null | sort -u | grep -c . || echo "0")
        if [[ "$ssid_count" -gt 2 ]]; then
            log_warn "Detected ${ssid_count} WiFi networks nearby — cameras may be on a separate network"
        fi
    elif command -v iwlist &>/dev/null; then
        local ssid_count
        ssid_count=$(iwlist "$IFACE" scan 2>/dev/null | grep -c "ESSID:" || echo "0")
        if [[ "$ssid_count" -gt 2 ]]; then
            log_warn "Detected ${ssid_count} WiFi networks nearby — cameras may be on a separate network"
        fi
    fi
}

# ── Phase 1: Host Discovery ─────────────────────────────────────────────────

phase1_host_discovery() {
    log_phase "1" "Host Discovery"
    log_info "Finding all devices on the network..."

    local hosts_file="$SCAN_DIR/hosts.txt"
    local arp_file="$SCAN_DIR/arp_raw.txt"
    local nmap_file="$SCAN_DIR/nmap_discovery.txt"
    > "$hosts_file"

    # Method 1: arp-scan (best for local segment)
    if [[ $HAS_ARPSCAN -eq 1 && $IS_ROOT -eq 1 ]]; then
        log_info "Running arp-scan on ${IFACE}..."
        arp-scan -l -I "$IFACE" 2>/dev/null | grep -E '^[0-9]+\.' > "$arp_file" || true
        while IFS=$'\t' read -r ip mac vendor; do
            [[ -z "$ip" || "$ip" == "$MY_IP" ]] && continue
            local oui
            oui=$(mac_to_oui "$mac")
            echo "${ip}|${mac}|${vendor}|${oui}" >> "$hosts_file"
        done < "$arp_file"
        local arp_count
        arp_count=$(wc -l < "$hosts_file")
        log_ok "arp-scan found ${arp_count} devices"
    fi

    # Method 2: nmap ping scan (catches hosts arp-scan misses)
    log_info "Running nmap host discovery on ${SUBNET}..."
    if [[ $IS_ROOT -eq 1 ]]; then
        nmap -sn -PR "$SUBNET" -oG "$nmap_file" >/dev/null 2>&1 || true
    else
        nmap -sn "$SUBNET" -oG "$nmap_file" >/dev/null 2>&1 || true
    fi

    # Parse nmap grepable output and merge with arp results
    local re_host='^Host: ([0-9.]+)'
    local re_mac_vendor='MAC: ([0-9A-Fa-f:]+) \(([^)]*)\)'
    local re_mac_only='MAC: ([0-9A-Fa-f:]+)'
    while IFS= read -r line; do
        if [[ "$line" =~ $re_host ]]; then
            local ip="${BASH_REMATCH[1]}"
            [[ "$ip" == "$MY_IP" || "$ip" == "$GATEWAY" ]] && continue
            # Check if already found by arp-scan
            if ! grep -q "^${ip}|" "$hosts_file" 2>/dev/null; then
                local mac=""
                local vendor=""
                # Try MAC from nmap grepable output
                if [[ "$line" =~ $re_mac_vendor ]]; then
                    mac="${BASH_REMATCH[1]}"
                    vendor="${BASH_REMATCH[2]}"
                elif [[ "$line" =~ $re_mac_only ]]; then
                    mac="${BASH_REMATCH[1]}"
                fi
                # Fallback: get MAC from ARP table (ip neigh)
                if [[ -z "$mac" ]]; then
                    mac=$(ip neigh show "$ip" 2>/dev/null | awk '/lladdr/{print $5}' | head -1)
                fi
                if [[ -n "$mac" && "$mac" != "INCOMPLETE" ]]; then
                    local oui
                    oui=$(mac_to_oui "$mac")
                    echo "${ip}|${mac}|${vendor}|${oui}" >> "$hosts_file"
                fi
            fi
        fi
    done < "$nmap_file"

    # Method 3: Fallback to ip neigh if no results yet
    if [[ $(wc -l < "$hosts_file") -eq 0 ]]; then
        log_warn "No devices found via arp-scan/nmap, falling back to ARP table"
        ip neigh show 2>/dev/null | grep -v "FAILED" | while read -r ip _ _ _ mac _; do
            [[ "$ip" == "$MY_IP" || -z "$mac" || "$mac" == "INCOMPLETE" ]] && continue
            local oui
            oui=$(mac_to_oui "$mac")
            echo "${ip}|${mac}||${oui}" >> "$hosts_file"
        done
    fi

    # Also add the gateway (it could be a camera-equipped router/hub)
    if [[ -n "$GATEWAY" ]] && ! grep -q "^${GATEWAY}|" "$hosts_file" 2>/dev/null; then
        local gw_mac
        gw_mac=$(ip neigh show "$GATEWAY" 2>/dev/null | awk '{print $5}' | head -1)
        if [[ -n "$gw_mac" && "$gw_mac" != "INCOMPLETE" ]]; then
            local oui
            oui=$(mac_to_oui "$gw_mac")
            echo "${GATEWAY}|${gw_mac}|GATEWAY|${oui}" >> "$hosts_file"
        fi
    fi

    local total
    total=$(wc -l < "$hosts_file")
    log_ok "Total unique devices found: ${total}"

    if [[ $total -eq 0 ]]; then
        log_warn "No devices found! The network may be isolated or using client isolation."
        log_warn "Try running with sudo for better results."
    fi
}

# ── Phase 2: OUI Analysis ───────────────────────────────────────────────────

phase2_oui_analysis() {
    log_phase "2" "Manufacturer Identification (OUI Analysis)"

    local hosts_file="$SCAN_DIR/hosts.txt"
    local oui_file="$SCAN_DIR/oui_results.txt"
    > "$oui_file"

    local cam_count=0
    local unknown_count=0

    while IFS='|' read -r ip mac vendor oui; do
        [[ -z "$ip" ]] && continue

        local manufacturer="$vendor"
        local classification="UNKNOWN"
        local mac_randomized=0

        # Step 0: Check for MAC randomization (locally administered bit)
        if is_mac_randomized "$mac"; then
            mac_randomized=1
            log_warn "Randomized MAC: ${ip} — ${mac} (manufacturer cannot be determined from OUI)"
        fi

        # Step 1: Check Tier 1 (surveillance manufacturers)
        if [[ $mac_randomized -eq 0 ]] && [[ -n "${TIER1_OUIS[$oui]+x}" ]]; then
            manufacturer="${TIER1_OUIS[$oui]}"
            classification="TIER1_CAMERA"
            cam_count=$((cam_count + 1))
            log_critical "CAMERA MANUFACTURER: ${ip} — ${manufacturer} (${mac})"
        # Step 2: Check Tier 2 (consumer camera brands)
        elif [[ $mac_randomized -eq 0 ]] && [[ -n "${TIER2_OUIS[$oui]+x}" ]]; then
            manufacturer="${TIER2_OUIS[$oui]}"
            classification="TIER2_CAMERA"
            cam_count=$((cam_count + 1))
            log_warn "Camera brand: ${ip} — ${manufacturer} (${mac})"
        else
            # Handle randomized MACs — OUI lookup is meaningless
            if [[ $mac_randomized -eq 1 ]]; then
                manufacturer="(randomized MAC)"
                classification="MAC_RANDOMIZED"
                unknown_count=$((unknown_count + 1))
            else
            # Step 3: Look up in nmap MAC database
            if [[ $HAS_NMAP_MACDB -eq 1 && -z "$manufacturer" ]]; then
                manufacturer=$(grep -i "^${oui}" /usr/share/nmap/nmap-mac-prefixes 2>/dev/null | head -1 | sed "s/^${oui} //" || echo "")
            fi

            # Step 4: Check if manufacturer name suggests camera/IoT
            if [[ -n "$manufacturer" ]]; then
                local mfr_lower
                mfr_lower=$(echo "$manufacturer" | tr 'A-Z' 'a-z')
                if echo "$mfr_lower" | grep -qiE "camera|surveillance|security|cctv|dvr|nvr|vision"; then
                    classification="CAMERA_KEYWORD"
                    cam_count=$((cam_count + 1))
                    log_warn "Camera-related manufacturer: ${ip} — ${manufacturer} (${mac})"
                elif echo "$mfr_lower" | grep -qiE "espressif|tuya|smartlife|beken"; then
                    classification="IOT_CHIPSET"
                    log_info "IoT chipset: ${ip} — ${manufacturer} (${mac})"
                elif echo "$mfr_lower" | grep -qiE "apple|samsung electronics|intel|dell|hewlett|lenovo|huawei device|xiaomi comm|google|amazon|sonos|roku|brother|canon|philips|ecobee|honeywell|microsoft"; then
                    classification="KNOWN_SAFE"
                    log_dim "Known device: ${ip} — ${manufacturer} (${mac})"
                elif echo "$mfr_lower" | grep -qiE "realtek|mediatek|qualcomm|broadcom|marvell|ralink"; then
                    classification="GENERIC_CHIPSET"
                    log_info "Generic chipset: ${ip} — ${manufacturer} (${mac})"
                else
                    classification="KNOWN_OTHER"
                    log_dim "Other device: ${ip} — ${manufacturer} (${mac})"
                fi
            else
                classification="UNKNOWN"
                unknown_count=$((unknown_count + 1))
                log_warn "UNKNOWN manufacturer: ${ip} — ${mac}"
            fi
            fi  # end mac_randomized else
        fi

        echo "${ip}|${mac}|${manufacturer}|${classification}|${oui}" >> "$oui_file"
    done < "$hosts_file"

    echo ""
    log_info "Summary: ${cam_count} camera manufacturers, ${unknown_count} unknown"
    if [[ $cam_count -gt 0 ]]; then
        log_critical "⚠️  CAMERA MANUFACTURERS DETECTED — proceeding with detailed port scan"
    fi
}

# ── Phase 3: Port Scanning ──────────────────────────────────────────────────

phase3_port_scan() {
    log_phase "3" "Port Scanning (Camera-Specific Ports)"

    local oui_file="$SCAN_DIR/oui_results.txt"
    local port_file="$SCAN_DIR/port_results.txt"
    local nmap_grepable="$SCAN_DIR/nmap_ports.gnmap"
    local nmap_normal="$SCAN_DIR/nmap_ports.nmap"
    > "$port_file"

    # Build target list — scan ALL devices (cameras can use generic chipset MACs)
    local targets=""
    while IFS='|' read -r ip mac manufacturer classification oui; do
        [[ -z "$ip" ]] && continue
        targets="${targets} ${ip}"
    done < "$oui_file"

    if [[ -z "$targets" ]]; then
        log_warn "No targets to scan"
        return
    fi

    local target_count
    target_count=$(echo "$targets" | wc -w)
    log_info "Scanning ${target_count} devices on camera-specific ports..."
    log_info "Ports: ${CAMERA_PORTS}"

    # Choose scan type based on privileges
    local scan_type="-sT"
    if [[ $IS_ROOT -eq 1 ]]; then
        scan_type="-sS"
    fi

    # Run nmap with service version detection on camera ports
    nmap $scan_type -sV \
        -p "$CAMERA_PORTS" \
        -T4 --open \
        --version-intensity 5 \
        -oG "$nmap_grepable" \
        -oN "$nmap_normal" \
        $targets >/dev/null 2>&1 || true

    # Parse grepable output
    local open_count=0
    while IFS= read -r line; do
        if [[ "$line" =~ ^Host:\ ([0-9.]+) ]] && [[ "$line" == *"Ports:"* ]]; then
            local ip="${BASH_REMATCH[1]}"
            # Extract port info
            local ports_section
            ports_section=$(echo "$line" | sed 's/.*Ports: //' | sed 's/Ignored.*//')
            IFS=',' read -ra port_entries <<< "$ports_section"
            for entry in "${port_entries[@]}"; do
                entry=$(echo "$entry" | xargs)
                # Format: port/state/protocol/owner/service/rpc_info/version/
                IFS='/' read -r port state proto _ service _ version <<< "$entry"
                port=$(echo "$port" | xargs)
                state=$(echo "$state" | xargs)
                service=$(echo "$service" | xargs)
                version=$(echo "$version" | xargs)
                if [[ "$state" == "open" ]]; then
                    echo "${ip}|${port}|${service}|${version}" >> "$port_file"
                    open_count=$((open_count + 1))

                    # Highlight critical findings
                    if [[ "$port" == "554" || "$port" == "8554" ]]; then
                        log_critical "RTSP port ${port} OPEN on ${ip} — ${service} ${version}"
                    elif [[ "$port" == "37777" ]]; then
                        log_critical "Dahua port ${port} OPEN on ${ip}"
                    elif [[ "$port" == "8000" ]]; then
                        log_warn "Hikvision port ${port} open on ${ip}"
                    elif [[ "$port" == "34567" || "$port" == "34599" ]]; then
                        log_critical "XMEye/Chinese NVR port ${port} OPEN on ${ip}"
                    elif [[ "$port" == "9000" ]]; then
                        log_warn "Reolink port ${port} open on ${ip}"
                    else
                        log_info "Port ${port} open on ${ip}: ${service} ${version}"
                    fi
                fi
            done
        fi
    done < "$nmap_grepable"

    log_ok "Found ${open_count} open ports across all devices"
}

# ── Phase 4: Service Discovery ──────────────────────────────────────────────

phase4_service_discovery() {
    if [[ $QUICK_MODE -eq 1 ]]; then
        log_phase "4" "Service Discovery (SKIPPED — quick mode)"
        return
    fi

    log_phase "4" "Service Discovery (mDNS/UPnP/ONVIF)"

    local service_file="$SCAN_DIR/service_results.txt"
    > "$service_file"

    # mDNS discovery via avahi-browse
    if [[ $HAS_AVAHI -eq 1 ]]; then
        log_info "Scanning for mDNS/Bonjour services..."
        local avahi_file="$SCAN_DIR/avahi_raw.txt"

        # Browse all services with timeout
        timeout 15 avahi-browse -a -r -t -p 2>/dev/null > "$avahi_file" || true

        # Filter for camera-related services
        local camera_services="_rtsp._tcp|_camera._tcp|_nvr._tcp|_onvif._tcp"
        while IFS=';' read -r _ iface proto name stype domain hostname ip port txt; do
            [[ -z "$ip" || "$ip" == "" ]] && continue
            if echo "$stype" | grep -qiE "$camera_services"; then
                echo "${ip}|mDNS|${stype}|${name}|${txt}" >> "$service_file"
                log_critical "Camera service via mDNS: ${name} (${stype}) at ${ip}"
            elif echo "$stype" | grep -qiE "_http._tcp"; then
                # HTTP service — note for deeper inspection
                echo "${ip}|mDNS|${stype}|${name}|${txt}" >> "$service_file"
                log_info "HTTP service: ${name} at ${ip}"
            fi
        done < <(grep "^=" "$avahi_file" 2>/dev/null || true)

        local mdns_count
        mdns_count=$(wc -l < "$service_file")
        log_ok "mDNS services found: ${mdns_count}"
    else
        log_warn "Skipping mDNS (avahi-browse not available)"
    fi

    # UPnP/SSDP discovery via nmap
    log_info "Scanning for UPnP devices..."
    local upnp_file="$SCAN_DIR/upnp_raw.txt"
    if [[ $IS_ROOT -eq 1 ]]; then
        timeout 30 nmap --script=broadcast-upnp-info 2>/dev/null > "$upnp_file" || true
    else
        timeout 30 nmap --script=broadcast-upnp-info 2>/dev/null > "$upnp_file" || true
    fi

    # Parse UPnP results for camera keywords
    if [[ -f "$upnp_file" ]]; then
        while IFS= read -r line; do
            if echo "$line" | grep -qiE "camera|webcam|surveillance|DVR|NVR|IPC|NetworkCamera|SecurityCamera"; then
                echo "UPnP|SSDP|${line}" >> "$service_file"
                log_warn "Camera-related UPnP device: ${line}"
            fi
        done < "$upnp_file"
    fi

    # ONVIF WS-Discovery via nmap
    log_info "Scanning for ONVIF devices..."
    local wsdd_file="$SCAN_DIR/wsdd_raw.txt"
    timeout 20 nmap --script=broadcast-wsdd-discover 2>/dev/null > "$wsdd_file" || true

    if [[ -f "$wsdd_file" ]] && grep -qiE "NetworkVideoTransmitter|camera|onvif" "$wsdd_file" 2>/dev/null; then
        log_critical "ONVIF camera(s) detected via WS-Discovery!"
        while IFS= read -r line; do
            if echo "$line" | grep -qiE "Address:|NetworkVideoTransmitter|camera|onvif"; then
                echo "ONVIF|WSDD|${line}" >> "$service_file"
            fi
        done < "$wsdd_file"
    fi

    log_ok "Service discovery complete"
}

# ── Phase 5: Deep Inspection ────────────────────────────────────────────────

phase5_deep_inspection() {
    if [[ $QUICK_MODE -eq 1 ]]; then
        log_phase "5" "Deep Inspection (SKIPPED — quick mode)"
        return
    fi

    log_phase "5" "Deep Inspection (HTTP/RTSP Verification)"

    local port_file="$SCAN_DIR/port_results.txt"
    local deep_file="$SCAN_DIR/deep_results.txt"
    > "$deep_file"

    if [[ ! -s "$port_file" ]]; then
        log_info "No open ports found — skipping deep inspection"
        return
    fi

    # HTTP inspection
    if [[ $HAS_CURL -eq 1 ]]; then
        log_info "Inspecting HTTP services for camera indicators..."

        # Get unique IPs with HTTP ports
        local http_targets
        http_targets=$(grep -E '\|(80|443|8080|8443|8899)\|' "$port_file" 2>/dev/null | cut -d'|' -f1,2 | sort -u || true)

        while IFS='|' read -r ip port; do
            [[ -z "$ip" ]] && continue
            local proto="http"
            [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
            local url="${proto}://${ip}:${port}/"

            log_dim "Checking ${url}..."

            # Get headers
            local headers
            headers=$(curl -s -m 5 -k -I "$url" 2>/dev/null || echo "")

            # Get body (limited to 50KB)
            local body
            body=$(curl -s -m 5 -k --max-filesize 51200 "$url" 2>/dev/null || echo "")

            # Check server header
            if echo "$headers" | grep -qiE "$CAMERA_HEADERS"; then
                local server_header
                server_header=$(echo "$headers" | grep -i "^Server:" | head -1)
                echo "${ip}|${port}|CAMERA_HEADER|${server_header}" >> "$deep_file"
                log_critical "Camera HTTP server header on ${ip}:${port} — ${server_header}"
            fi

            # Check body for high-confidence keywords
            if echo "$body" | grep -qiE "$CAMERA_KEYWORDS_HIGH"; then
                local matches
                matches=$(echo "$body" | grep -oiE "$CAMERA_KEYWORDS_HIGH" | head -5 | tr '\n' ',' | sed 's/,$//')
                echo "${ip}|${port}|CAMERA_WEBUI|${matches}" >> "$deep_file"
                log_critical "Camera web UI keywords on ${ip}:${port} — ${matches}"
            elif echo "$body" | grep -qiE "$CAMERA_KEYWORDS_MEDIUM"; then
                local matches
                matches=$(echo "$body" | grep -oiE "$CAMERA_KEYWORDS_MEDIUM" | head -5 | tr '\n' ',' | sed 's/,$//')
                echo "${ip}|${port}|POSSIBLE_CAMERA|${matches}" >> "$deep_file"
                log_warn "Possible camera keywords on ${ip}:${port} — ${matches}"
            fi

            # Check HTML title
            local title
            title=$(echo "$body" | grep -oiP '<title>\K[^<]+' | head -1 || echo "")
            if [[ -n "$title" ]]; then
                if echo "$title" | grep -qiE "NETSurveillance|DVR|NVR|IPCamera|IP Camera|Network Camera|iVMS|SADP|webcamXP|Yawcam|Blue.Iris|ZoneMinder|Shinobi|MotionEye|Frigate"; then
                    echo "${ip}|${port}|CAMERA_TITLE|${title}" >> "$deep_file"
                    log_critical "Camera web page title on ${ip}:${port} — '${title}'"
                fi
            fi

        done <<< "$http_targets"
    else
        log_warn "Skipping HTTP inspection (curl not available)"
    fi

    # RTSP verification via nmap scripts
    local rtsp_targets
    rtsp_targets=$(grep -E '\|(554|8554)\|' "$port_file" 2>/dev/null | cut -d'|' -f1 | sort -u || true)

    if [[ -n "$rtsp_targets" ]]; then
        log_info "Verifying RTSP services..."
        for ip in $rtsp_targets; do
            log_dim "Probing RTSP on ${ip}..."
            local rtsp_result
            rtsp_result=$(nmap -sV -p 554,8554 --script=rtsp-methods "$ip" 2>/dev/null || echo "")
            if echo "$rtsp_result" | grep -qiE "RTSP|rtsp-methods|OPTIONS|DESCRIBE|SETUP|PLAY"; then
                echo "${ip}|554|RTSP_CONFIRMED|Active RTSP service" >> "$deep_file"
                log_critical "CONFIRMED RTSP streaming service on ${ip}"
            fi
        done
    fi

    # Vendor-specific port verification
    local vendor_targets
    vendor_targets=$(grep -E '\|(8000|37777|34567|34599|9000)\|' "$port_file" 2>/dev/null || true)

    if [[ -n "$vendor_targets" ]]; then
        log_info "Checking vendor-specific ports..."
        while IFS='|' read -r ip port service version; do
            case "$port" in
                8000)
                    echo "${ip}|${port}|HIKVISION_PORT|Hikvision SDK port open" >> "$deep_file"
                    log_critical "Hikvision SDK port confirmed on ${ip}:${port}"
                    ;;
                37777)
                    echo "${ip}|${port}|DAHUA_PORT|Dahua protocol port open" >> "$deep_file"
                    log_critical "Dahua protocol port confirmed on ${ip}:${port}"
                    ;;
                34567|34599)
                    echo "${ip}|${port}|XMEYE_PORT|XMEye/Chinese NVR port open" >> "$deep_file"
                    log_critical "XMEye NVR port confirmed on ${ip}:${port}"
                    ;;
                9000)
                    echo "${ip}|${port}|REOLINK_PORT|Reolink port open" >> "$deep_file"
                    log_warn "Reolink port on ${ip}:${port}"
                    ;;
            esac
        done <<< "$vendor_targets"
    fi

    local finding_count
    finding_count=$(wc -l < "$deep_file")
    log_ok "Deep inspection complete: ${finding_count} findings"
}

# ── Phase 6: Risk Classification ────────────────────────────────────────────

phase6_classify() {
    log_phase "6" "Risk Classification"

    local oui_file="$SCAN_DIR/oui_results.txt"
    local port_file="$SCAN_DIR/port_results.txt"
    local service_file="$SCAN_DIR/service_results.txt"
    local deep_file="$SCAN_DIR/deep_results.txt"
    local class_file="$SCAN_DIR/classifications.txt"
    > "$class_file"

    local critical_count=0
    local high_count=0
    local moderate_count=0
    local low_count=0
    local info_count=0

    while IFS='|' read -r ip mac manufacturer classification oui; do
        [[ -z "$ip" ]] && continue

        local risk="INFO"
        local evidence=""
        local device_type="Unknown"
        local recommendation=""
        local open_ports=""

        # Gather port evidence for this IP
        if [[ -f "$port_file" ]]; then
            open_ports=$(grep "^${ip}|" "$port_file" 2>/dev/null | cut -d'|' -f2 | tr '\n' ',' | sed 's/,$//' || echo "")
        fi

        local has_rtsp=0
        local has_http=0
        local has_vendor_port=0
        local has_camera_webui=0
        local has_camera_header=0
        local has_rtsp_confirmed=0
        local has_mdns_camera=0

        # Check port evidence
        [[ "$open_ports" =~ (^|,)(554|8554)(,|$) ]] && has_rtsp=1
        [[ "$open_ports" =~ (^|,)(80|443|8080|8443)(,|$) ]] && has_http=1
        [[ "$open_ports" =~ (^|,)(8000|8200|37777|34567|34599|9000)(,|$) ]] && has_vendor_port=1

        # Check deep inspection evidence (use grep -F for literal pipe matching)
        if [[ -f "$deep_file" ]] && [[ -s "$deep_file" ]]; then
            grep -F "${ip}|" "$deep_file" | grep -qF "|CAMERA_WEBUI|"   2>/dev/null && has_camera_webui=1
            grep -F "${ip}|" "$deep_file" | grep -qF "|CAMERA_HEADER|"  2>/dev/null && has_camera_header=1
            grep -F "${ip}|" "$deep_file" | grep -qF "|RTSP_CONFIRMED|" 2>/dev/null && has_rtsp_confirmed=1
            grep -F "${ip}|" "$deep_file" | grep -qF "|CAMERA_TITLE|"   2>/dev/null && has_camera_webui=1
            grep -F "${ip}|" "$deep_file" | grep -qF "|HIKVISION_PORT|" 2>/dev/null && has_vendor_port=1
            grep -F "${ip}|" "$deep_file" | grep -qF "|DAHUA_PORT|"     2>/dev/null && has_vendor_port=1
            grep -F "${ip}|" "$deep_file" | grep -qF "|XMEYE_PORT|"     2>/dev/null && has_vendor_port=1
        fi

        # Check service discovery evidence
        if [[ -f "$service_file" ]] && [[ -s "$service_file" ]]; then
            grep -F "${ip}|" "$service_file" | grep -qF "|_rtsp._tcp|"   2>/dev/null && has_mdns_camera=1
            grep -F "${ip}|" "$service_file" | grep -qF "|_camera._tcp|" 2>/dev/null && has_mdns_camera=1
            grep -F "${ip}|" "$service_file" | grep -qF "|_nvr._tcp|"    2>/dev/null && has_mdns_camera=1
            grep -F "${ip}|" "$service_file" | grep -qF "|_onvif._tcp|"  2>/dev/null && has_mdns_camera=1
        fi

        # ── CLASSIFICATION LOGIC ──

        # CRITICAL: Confirmed camera with active streaming
        if [[ "$classification" == "TIER1_CAMERA" && ($has_rtsp -eq 1 || $has_vendor_port -eq 1) ]]; then
            risk="CRITICAL"
            device_type="Surveillance Camera (confirmed)"
            evidence="Surveillance manufacturer (${manufacturer}) + streaming/control ports open (${open_ports})"
            recommendation="LIKELY ACTIVE CAMERA. Photograph device location. Contact Airbnb support immediately."
        elif [[ $has_rtsp_confirmed -eq 1 ]]; then
            risk="CRITICAL"
            device_type="RTSP Streaming Device (confirmed)"
            evidence="Active RTSP streaming service detected"
            recommendation="CONFIRMED VIDEO STREAMING. Locate and photograph the device. Contact Airbnb."
        elif [[ ($has_camera_webui -eq 1 || $has_camera_header -eq 1) ]]; then
            risk="CRITICAL"
            device_type="Camera Web Interface (confirmed)"
            evidence="Camera web UI or server header detected on HTTP"
            recommendation="CAMERA WEB INTERFACE FOUND. Photograph evidence. Contact Airbnb."
        elif [[ "$classification" == "TIER1_CAMERA" && $has_camera_webui -eq 1 ]]; then
            risk="CRITICAL"
            device_type="Surveillance Camera (confirmed)"
            evidence="Surveillance manufacturer + camera web interface"
            recommendation="CONFIRMED CAMERA. Document and report to Airbnb immediately."
        elif [[ $has_mdns_camera -eq 1 ]]; then
            risk="CRITICAL"
            device_type="Camera Service (mDNS)"
            evidence="Camera/RTSP service advertising via mDNS"
            recommendation="CAMERA ANNOUNCING ON NETWORK. Locate device. Contact Airbnb."

        # HIGH: Strong camera indicators
        elif [[ "$classification" == "TIER1_CAMERA" ]]; then
            risk="HIGH"
            device_type="Surveillance Equipment"
            evidence="Known surveillance manufacturer: ${manufacturer}"
            recommendation="Surveillance manufacturer device on network. Try to locate it physically."
        elif [[ "$classification" == "TIER2_CAMERA" ]]; then
            risk="HIGH"
            device_type="Consumer Camera"
            evidence="Known camera brand: ${manufacturer}"
            recommendation="Consumer camera brand detected. Check if disclosed in listing."
        elif [[ "$classification" == "CAMERA_KEYWORD" ]]; then
            risk="HIGH"
            device_type="Camera-Related Device"
            evidence="Manufacturer name suggests camera/surveillance: ${manufacturer}"
            recommendation="Camera-related manufacturer. Investigate further."
        elif [[ "$classification" == "UNKNOWN" && $has_rtsp -eq 1 ]]; then
            risk="HIGH"
            device_type="Unknown Device with RTSP"
            evidence="Unknown manufacturer + RTSP port open"
            recommendation="Unknown device with video streaming port. Investigate immediately."
        elif [[ "$classification" == "UNKNOWN" && $has_vendor_port -eq 1 ]]; then
            risk="HIGH"
            device_type="Unknown Device with Camera Port"
            evidence="Unknown manufacturer + vendor-specific camera port open"
            recommendation="Unknown device with camera-specific port. Investigate."
        elif [[ "$classification" == "MAC_RANDOMIZED" && ($has_rtsp -eq 1 || $has_vendor_port -eq 1) ]]; then
            risk="HIGH"
            device_type="Randomized MAC (suspicious ports)"
            evidence="Randomized MAC address + camera-related ports (${open_ports})"
            recommendation="Device hiding identity with camera ports open. Investigate immediately."

        # MODERATE: Suspicious but not confirmed
        elif [[ "$classification" == "MAC_RANDOMIZED" && $has_http -eq 1 ]]; then
            risk="MODERATE"
            device_type="Randomized MAC (with web interface)"
            evidence="Randomized MAC address + HTTP service"
            recommendation="Device with hidden identity and web server. Likely a phone, but verify."
        elif [[ "$classification" == "MAC_RANDOMIZED" ]]; then
            risk="LOW"
            device_type="Randomized MAC (likely phone/laptop)"
            evidence="MAC randomization active — typically modern phone, tablet, or laptop"
            recommendation="Likely a personal device using privacy MAC. Common on iOS/Android."
        elif [[ "$classification" == "IOT_CHIPSET" && ($has_rtsp -eq 1 || $has_vendor_port -eq 1) ]]; then
            risk="MODERATE"
            device_type="IoT Device (suspicious ports)"
            evidence="IoT chipset (${manufacturer}) + camera-related ports (${open_ports})"
            recommendation="IoT device with suspicious ports. Could be a camera using generic chipset."
        elif [[ "$classification" == "IOT_CHIPSET" && $has_http -eq 1 ]]; then
            risk="MODERATE"
            device_type="IoT Device (with web interface)"
            evidence="IoT chipset (${manufacturer}) + HTTP service"
            recommendation="IoT device with web interface. Check if it's a camera."
        elif [[ "$classification" == "UNKNOWN" && $has_http -eq 1 ]]; then
            risk="MODERATE"
            device_type="Unknown Device (with web interface)"
            evidence="Unknown manufacturer + HTTP service on port ${open_ports}"
            recommendation="Unidentified device with web server. Try accessing its web interface."
        elif [[ "$classification" == "GENERIC_CHIPSET" && ($has_rtsp -eq 1 || $has_vendor_port -eq 1) ]]; then
            risk="MODERATE"
            device_type="Generic Chipset (suspicious ports)"
            evidence="Generic chipset (${manufacturer}) + camera ports (${open_ports})"
            recommendation="Generic device with camera-specific ports. Investigate."
        elif [[ "$classification" == "UNKNOWN" ]]; then
            risk="MODERATE"
            device_type="Unidentified Device"
            evidence="Unknown manufacturer, MAC: ${mac}"
            recommendation="Cannot identify this device. Try to locate it physically."

        # LOW: Probably safe
        elif [[ "$classification" == "IOT_CHIPSET" ]]; then
            risk="LOW"
            device_type="IoT Device"
            evidence="IoT chipset (${manufacturer}), no camera ports"
            recommendation="Likely a smart home device (plug, sensor, etc.)"
        elif [[ "$classification" == "GENERIC_CHIPSET" ]]; then
            risk="LOW"
            device_type="Network Device"
            evidence="Generic chipset (${manufacturer})"
            recommendation="Likely a router, switch, or network adapter"

        # INFO: Known safe
        elif [[ "$classification" == "KNOWN_SAFE" || "$classification" == "KNOWN_OTHER" ]]; then
            risk="INFO"
            device_type="Known Device"
            evidence="Identified manufacturer: ${manufacturer}"
            recommendation="Known device type, no camera indicators"
        fi

        # Count
        case "$risk" in
            CRITICAL) critical_count=$((critical_count + 1)) ;;
            HIGH)     high_count=$((high_count + 1)) ;;
            MODERATE) moderate_count=$((moderate_count + 1)) ;;
            LOW)      low_count=$((low_count + 1)) ;;
            INFO)     info_count=$((info_count + 1)) ;;
        esac

        echo "${risk}|${ip}|${mac}|${manufacturer}|${device_type}|${open_ports}|${evidence}|${recommendation}" >> "$class_file"

    done < "$oui_file"

    # Save summary counts
    echo "${critical_count}|${high_count}|${moderate_count}|${low_count}|${info_count}" > "$SCAN_DIR/summary_counts.txt"

    echo ""
    log_info "Classification complete:"
    [[ $critical_count -gt 0 ]] && log_critical "${ICON_CRITICAL} CRITICAL: ${critical_count}"
    [[ $high_count -gt 0 ]]     && log_warn "${ICON_HIGH} HIGH: ${high_count}"
    [[ $moderate_count -gt 0 ]] && log_info "${ICON_MODERATE} MODERATE: ${moderate_count}"
    [[ $low_count -gt 0 ]]      && log_ok "${ICON_LOW} LOW: ${low_count}"
    [[ $info_count -gt 0 ]]     && log_dim "${ICON_INFO} INFO: ${info_count}"
}

# ── Phase 7: Report Generation ──────────────────────────────────────────────

phase7_report_terminal() {
    log_phase "7" "Report"

    local class_file="$SCAN_DIR/classifications.txt"
    local end_time
    end_time=$(date +%s)
    local duration=$(( end_time - START_TIME ))

    echo ""
    echo -e "${BOLD}${WHITE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${WHITE}║        SURVEILLANCE DEVICE SCAN REPORT                       ║${NC}"
    echo -e "${BOLD}${WHITE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${DIM}Date:      $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "  ${DIM}Network:   ${SUBNET} via ${IFACE}${NC}"
    echo -e "  ${DIM}Gateway:   ${GATEWAY}${NC}"
    echo -e "  ${DIM}Scanner:   ${MY_IP}${NC}"
    echo -e "  ${DIM}Duration:  ${duration}s${NC}"
    echo -e "  ${DIM}Mode:      $([ $QUICK_MODE -eq 1 ] && echo 'Quick' || echo 'Full')${NC}"
    echo ""

    # Summary
    if [[ -f "$SCAN_DIR/summary_counts.txt" ]]; then
        IFS='|' read -r cc hc mc lc ic < "$SCAN_DIR/summary_counts.txt"
        echo -e "  ${BOLD}─── RISK SUMMARY ──────────────────────────────────────${NC}"
        echo -e "  ${ICON_CRITICAL} Critical:  ${cc:-0}"
        echo -e "  ${ICON_HIGH} High:      ${hc:-0}"
        echo -e "  ${ICON_MODERATE} Moderate:  ${mc:-0}"
        echo -e "  ${ICON_LOW} Low:       ${lc:-0}"
        echo -e "  ${ICON_INFO} Info:      ${ic:-0}"
        echo -e "  ${BOLD}───────────────────────────────────────────────────────${NC}"
        echo ""

        if [[ "${cc:-0}" -gt 0 ]]; then
            echo -e "  ${RED}${BOLD}⚠️  SURVEILLANCE DEVICES LIKELY PRESENT ⚠️${NC}"
            echo ""
        elif [[ "${hc:-0}" -gt 0 ]]; then
            echo -e "  ${ORANGE}${BOLD}⚠️  SUSPICIOUS DEVICES DETECTED — Investigation needed${NC}"
            echo ""
        fi
    fi

    # Detailed device list (sorted by risk: CRITICAL first)
    echo -e "  ${BOLD}─── DEVICE DETAILS ────────────────────────────────────${NC}"
    echo ""

    for risk_level in CRITICAL HIGH MODERATE LOW INFO; do
        local devices
        devices=$(grep "^${risk_level}|" "$class_file" 2>/dev/null || true)
        [[ -z "$devices" ]] && continue

        local icon=""
        local color=""
        case "$risk_level" in
            CRITICAL) icon="$ICON_CRITICAL"; color="$RED" ;;
            HIGH)     icon="$ICON_HIGH";     color="$ORANGE" ;;
            MODERATE) icon="$ICON_MODERATE"; color="$YELLOW" ;;
            LOW)      icon="$ICON_LOW";      color="$GREEN" ;;
            INFO)     icon="$ICON_INFO";     color="$BLUE" ;;
        esac

        while IFS='|' read -r risk ip mac manufacturer device_type open_ports evidence recommendation; do
            echo -e "  ${icon} ${color}${BOLD}[${risk}]${NC} ${BOLD}${ip}${NC}"
            echo -e "      MAC:           ${mac}"
            echo -e "      Manufacturer:  ${manufacturer:-Unknown}"
            echo -e "      Device Type:   ${device_type}"
            [[ -n "$open_ports" ]] && echo -e "      Open Ports:    ${open_ports}"
            echo -e "      Evidence:      ${evidence}"
            echo -e "      ${color}Action:        ${recommendation}${NC}"
            echo ""
        done <<< "$devices"
    done

    # Action guide for critical/high findings
    if [[ -f "$SCAN_DIR/summary_counts.txt" ]]; then
        IFS='|' read -r cc hc mc lc ic < "$SCAN_DIR/summary_counts.txt"
        if [[ "${cc:-0}" -gt 0 || "${hc:-0}" -gt 0 ]]; then
            echo -e "  ${BOLD}${RED}─── WHAT TO DO NOW ────────────────────────────────────${NC}"
            echo ""
            echo -e "  ${RED}1.${NC} Do NOT disconnect or tamper with the device"
            echo -e "  ${RED}2.${NC} Photograph the device and its location"
            echo -e "  ${RED}3.${NC} Save this scan report as evidence"
            echo -e "  ${RED}4.${NC} Contact Airbnb Support:"
            echo -e "      • Open the Airbnb app → Your Trips → Select reservation"
            echo -e "      • Tap 'Get Help' → 'Report a safety concern'"
            echo -e "      • Or call Airbnb Emergency: +1-855-424-7262"
            echo -e "  ${RED}5.${NC} If you feel unsafe, leave the property immediately"
            echo -e "  ${RED}6.${NC} Consider contacting local law enforcement"
            echo -e "      (hidden cameras are illegal in most jurisdictions)"
            echo ""
        fi
    fi

    # Limitations
    echo -e "  ${BOLD}─── LIMITATIONS ───────────────────────────────────────${NC}"
    echo ""
    echo -e "  ${DIM}This scan covers devices connected to the same WiFi network.${NC}"
    echo -e "  ${DIM}The following are NOT detected:${NC}"
    echo -e "  ${DIM}  • Cameras on a separate VLAN or wired-only network${NC}"
    echo -e "  ${DIM}  • Cellular-connected cameras (4G/LTE)${NC}"
    echo -e "  ${DIM}  • Cameras that are powered off or in standby${NC}"
    echo -e "  ${DIM}  • Devices using MAC address randomization${NC}"
    echo -e "  ${DIM}  • Local storage cameras not connected to any network${NC}"
    echo -e "  ${DIM}  • Audio-only recording devices (bugs)${NC}"
    echo -e "  ${DIM}For comprehensive detection, also perform a physical inspection.${NC}"
    echo ""
    echo -e "  ${BOLD}─── RENTAL POLICY ─────────────────────────────────────${NC}"
    echo ""
    echo -e "  ${DIM}Major rental platforms prohibit indoor surveillance cameras:${NC}"
    echo ""
    echo -e "  ${RED}▪${NC} ${DIM}Airbnb — All indoor cameras prohibited, even if off.${NC}"
    echo -e "    ${DIM}https://www.airbnb.com/help/article/3061${NC}"
    echo -e "  ${ORANGE}▪${NC} ${DIM}Booking.com — Cameras only in common areas, must be disclosed.${NC}"
    echo -e "    ${DIM}https://partner.booking.com/en-us/help/legal-security/security/requirements-and-regulations-surveillance-devices${NC}"
    echo -e "  ${YELLOW}▪${NC} ${DIM}Vrbo — Indoor cameras prohibited. Outdoor must be disclosed.${NC}"
    echo -e "    ${DIM}https://www.vrbo.com/tlp/trust-and-safety/use-of-surveillance-policy${NC}"
    echo ""
}

phase7_report_html() {
    if [[ $NO_HTML -eq 1 ]]; then
        return
    fi

    mkdir -p "$REPORT_DIR"
    local html_file="${REPORT_DIR}/privacy-scan-${TIMESTAMP}.html"
    local class_file="$SCAN_DIR/classifications.txt"
    local end_time
    end_time=$(date +%s)
    local duration=$(( end_time - START_TIME ))
    local mode_str="Full"
    [[ $QUICK_MODE -eq 1 ]] && mode_str="Quick"

    # Resolve path to report_html.py (same directory as scan.sh)
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local report_script="${script_dir}/report_html.py"

    if [[ $HAS_PYTHON3 -eq 1 && -f "$report_script" ]]; then
        python3 "$report_script" \
            --classifications "$class_file" \
            --summary "$SCAN_DIR/summary_counts.txt" \
            --output "$html_file" \
            --subnet "$SUBNET" \
            --interface "$IFACE" \
            --gateway "$GATEWAY" \
            --scanner-ip "$MY_IP" \
            --duration "$duration" \
            --mode "$mode_str" \
            --lang "$LANG_CODE" \
            2>/dev/null
        log_ok "HTML report: ${html_file}"
    elif [[ $HAS_PYTHON3 -eq 1 ]]; then
        log_warn "report_html.py not found at ${report_script}"
        log_warn "Generating simplified HTML report"
        {
            echo "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Privacy Scan Report</title>"
            echo "<style>body{font-family:sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}pre{white-space:pre-wrap}</style></head><body>"
            echo "<h1>Privacy Surveillance Device Scan Report</h1>"
            echo "<p>Date: $(date) | Network: ${SUBNET} | Duration: ${duration}s</p>"
            echo "<h2>Devices</h2><pre>"
            cat "$class_file"
            echo "</pre></body></html>"
        } > "$html_file"
        log_ok "HTML report (simplified): ${html_file}"
    else
        log_warn "Python3 not available — skipping HTML report"
    fi
}

# ── Cleanup ─────────────────────────────────────────────────────────────────

cleanup() {
    if [[ -n "$SCAN_DIR" && -d "$SCAN_DIR" ]]; then
        # Copy raw data to report dir for reference
        if [[ -d "$REPORT_DIR" ]]; then
            cp -r "$SCAN_DIR" "${REPORT_DIR}/raw-data-${TIMESTAMP}" 2>/dev/null || true
        fi
        rm -rf "$SCAN_DIR"
    fi
}

# ── Argument Parsing ────────────────────────────────────────────────────────

show_help() {
    echo "Privacy Scanner — WiFi Surveillance Device Detector"
    echo ""
    echo "Usage: sudo bash scan.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --interface IFACE    Network interface (auto-detected if omitted)"
    echo "  --subnet CIDR        Subnet to scan, e.g. 192.168.1.0/24"
    echo "  --output-dir DIR     Report output directory (default: ./privacy-scan-results)"
    echo "  --quick              Quick scan — skip service discovery & deep inspection"
    echo "  --no-html            Skip HTML report generation"
    echo "  --lang LANG          Report language: pt (default), en, es"
    echo "  --help               Show this help"
    echo ""
    echo "Examples:"
    echo "  sudo bash scan.sh                          # Full auto-detected scan"
    echo "  sudo bash scan.sh --quick                  # Fast scan (~2 min)"
    echo "  sudo bash scan.sh --interface wlan0        # Specify WiFi interface"
    echo "  sudo bash scan.sh --subnet 10.0.0.0/24     # Specify subnet"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface)
                IFACE="$2"
                shift 2
                ;;
            --subnet)
                SUBNET="$2"
                shift 2
                ;;
            --output-dir)
                REPORT_DIR="$2"
                shift 2
                ;;
            --quick)
                QUICK_MODE=1
                shift
                ;;
            --no-html)
                NO_HTML=1
                shift
                ;;
            --lang)
                LANG_CODE="$2"
                if [[ ! "$LANG_CODE" =~ ^(pt|en|es)$ ]]; then
                    echo "Invalid language: $LANG_CODE (use pt, en, or es)"
                    exit 1
                fi
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    echo ""
    echo -e "${BOLD}${WHITE}🛡️  Privacy Scanner — WiFi Surveillance Device Detector${NC}"
    echo -e "${DIM}   Defensive privacy audit tool${NC}"
    echo ""

    # Create temp directory
    SCAN_DIR=$(mktemp -d /tmp/privacy-scan-XXXXXX)
    trap cleanup EXIT

    # Run all phases
    check_prerequisites
    detect_network
    phase1_host_discovery
    phase2_oui_analysis
    phase3_port_scan
    phase4_service_discovery
    phase5_deep_inspection
    phase6_classify
    phase7_report_terminal
    phase7_report_html

    echo -e "${BOLD}${GREEN}Scan complete.${NC}"
    echo ""
}

main "$@"
