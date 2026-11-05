# Ghost-Scan

> Async port scanner and service fingerprinter with CVE correlation, OS detection, and Nmap XML export.

```
  GHOST-SCAN  v1.0.0  |  Async Port Scanner & Service Fingerprinter
  By Gh0st-Bx1        |  github.com/Ghost-Bx1
```

![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat-square)
![Category](https://img.shields.io/badge/Category-Port%20Scanner-blue?style=flat-square)

---

## Overview

Ghost-Scan is a high-performance async TCP/UDP port scanner built on pure Python stdlib. It runs port-specific banner probes, estimates OS from TTL, correlates banners against a built-in CVE database, supports CIDR ranges, and exports results in Nmap XML format for compatibility with existing toolchains.

| Feature          | Description                                                        |
|------------------|--------------------------------------------------------------------|
| TCP async        | Semaphore-controlled async scanner with configurable rate          |
| Banner grabbing  | Port-specific probes for accurate service identification           |
| OS detection     | OS estimation from ICMP TTL (Linux / Windows / Cisco)             |
| UDP scan         | Probes for DNS, SNMP, NTP, TFTP                                   |
| CVE correlation  | Banner matched against built-in CVE database                       |
| CIDR support     | Target expansion for network ranges (limit /16)                    |
| Nmap XML export  | Compatible with Nmap parsers and pentest frameworks                |
| JSON output      | Structured results for downstream processing                       |

---

## Requirements

```
Python 3.7+
No external dependencies (stdlib only: asyncio, socket, subprocess)
```

---

## Installation

```bash
git clone https://github.com/Ghost-Bx1/ghost-scan
cd ghost-scan
python ghost-scan.py --help
```

---

## Usage

```bash
# Quick scan - top 100 ports
python ghost-scan.py -t 192.168.1.1

# Full scan with banner grabbing and OS detection
python ghost-scan.py -t 192.168.1.1 -p full --banner --os-detect

# Port range scan with UDP
python ghost-scan.py -t 10.0.0.1 -p 1-1024 --udp --banner

# CIDR range scan with Nmap XML export
python ghost-scan.py -t 192.168.1.0/24 -p top100 --nmap-xml scan.xml

# Specific ports with JSON output
python ghost-scan.py -t 192.168.1.1 -p 22,80,443,8080,8443 -o result.json

# High-speed scan with custom rate and timeout
python ghost-scan.py -t 10.0.0.1 -p full --rate 1000 --timeout 0.5
```

---

## OS Detection via TTL

| TTL    | Estimated OS          |
|--------|-----------------------|
| <= 64  | Linux / Unix          |
| <= 128 | Windows               |
| <= 255 | Cisco / Router        |

---

## CVE Correlation

When a banner is captured, Ghost-Scan checks it against a built-in database of known vulnerable product versions. Examples covered: OpenSSH, Apache, IIS, Exim, Postfix, WordPress, phpMyAdmin.

---

## Reference

| Flag              | Description                                                |
|-------------------|------------------------------------------------------------|
| `-t / --target`   | IP, hostname, or CIDR range (e.g. 192.168.1.0/24)         |
| `-p / --ports`    | Port set: top100, full, 1-1024, or 22,80,443 (default: top100) |
| `--rate N`        | Concurrent connections (default: 500)                      |
| `--timeout N`     | Per-port timeout in seconds (default: 1.0)                 |
| `--banner`        | Enable banner grabbing                                     |
| `--udp`           | Enable UDP scan                                            |
| `--os-detect`     | OS detection via TTL                                       |
| `-o / --output`   | Save results to JSON                                       |
| `--nmap-xml FILE` | Export results in Nmap XML format                          |
| `--verbose`       | Verbose output                                             |

---

## Roadmap

Improvements planned based on analysis of rustscan, masscan and naabu:

| Priority | Feature | Description |
|----------|---------|-------------|
| High | Shodan InternetDB passive mode | Pull known open ports from `api.internetdb.shodan.io` without touching the host (`--passive`) |
| High | Pipeline/stdin mode | Read targets from stdin (`echo 10.0.0.1 \| ghost-scan`); pipe results to other tools |
| High | Scripting engine | Trigger a module per open port: smb-enum on 445, http-titles on 80/443, redis-info on 6379 |
| High | HTTP title + favicon grabber | On ports 80/443/8080: grab `<title>` and status code without running full HTTP module |
| Medium | JSON lines streaming output | Emit each result as it arrives (compatible with `jq` piping), not buffered at the end |
| Medium | SYN scan mode | Raw socket SYN scan (`--syn`, requires root/admin) - faster than full connect |
| Medium | Timing templates T0-T5 | Preset profiles that adjust rate + timeout together: paranoid (T0) to insane (T5) |
| Medium | ASN input | `--asn AS14421` expands to all prefixes via BGP data and scans them |
| Medium | Exclude CDN ranges | Built-in CIDR list for Cloudflare/Akamai/Incapsula/Sucuri to skip or flag (`--exclude-cdn`) |
| Low | Distributed sharding | `--shard 1/3` to divide a large range across multiple instances running in parallel |
| Low | SSL certificate inspection | Per-port TLS: expiry date, issuer, SANs, weak cipher detection on discovered HTTPS services |
| Low | Service confidence scoring | Weight banner match confidence (0-100) based on number of matched patterns per service |

## Disclaimer

For use in authorized environments only. Penetration testing, CTF competitions, and offensive security research with explicit permission from the environment owner. The author is not responsible for misuse.

---

**By [Gh0st-Bx1](https://github.com/Ghost-Bx1)**
