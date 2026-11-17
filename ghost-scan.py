#!/usr/bin/env python3
"""
Ghost-Scan - Async Port Scanner & Service Fingerprinter
By Gh0st-Bx1 | github.com/Ghost-Bx1
"""

import sys
import os
import socket
import asyncio
import json
import re
import struct
import argparse
import ipaddress
import time
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import urllib.request
import urllib.error

VERSAO = "2.0.0"

# ──────────────────────────────────────────────────────────────────
# BANNER
# ──────────────────────────────────────────────────────────────────

def _build_banner():
    import re as _re
    G = "\033[92m"; Cy = "\033[96m"; D = "\033[2m"; N = "\033[1m"
    W = "\033[97m"; X = "\033[0m"
    IW = 68; eq = "═" * IW; sp = " " * IW
    TL = "╔"; TR = "╗"; BL = "╚"; BR = "╝"; VB = "║"
    hl = "─" * 44; bar = "│"
    vl = lambda s: len(_re.sub(r"\x1b\[[0-9;]*m", "", s))

    def _row(s):
        n = vl(s); p = max(0, IW - n); l = p // 2; r = p - l
        return f"{G}{VB}{X}{' ' * l}{s}{' ' * r}{G}{VB}{X}"

    def _row_l(s):
        n = vl(s); p = max(0, IW - n - 2)
        return f"{G}{VB}{X}  {s}{' ' * p}{G}{VB}{X}"

    ga = [
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠛⠛⠿⠟⠉⠛⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠉⢀⣠⣤⣶⣶⣶⣶⣶⣶⣤⣀⠢⢝⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⡡⢀⣴⡿⢋⡴⢿⣿⣿⣿⣿⣿⣿⣿⢷⣦⡑⠈⡛⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⡜⢠⣾⣿⣤⣋⣴⣿⣿⣿⣿⣿⣿⣿⣿⣷⣌⠻⣶⣦⣤⣤⣀⠉⠻⣿⣿⣿⡿⠿⢛⢛⡻⠿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⠿⠟⠟⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⢀⣿⣿⣿⡿⠛⠛⠻⣿⣿⣿⡿⠛⠛⢿⣿⣿⣧⠉⠉⣁⣈⣉⣁⢀⣿⣿⢋⠄⣁⣴⣶⣄⠐⢌⢻⣿⣿{X}", ""),
        ("", f"{G}⡏⠀⣴⣦⣄⠢⡙⢿⣿⣿⣿⣿⣿⣿⡇⠀⣼⣿⣿⣿⠅⠀⠀  ⢹⣿⡿⠁⠀⠀⠀⢹⣿⣿⡆⠀⣿⣿⣿⣿⣿⡟⠁⢀⣴⣿⣿⣿⣿⣷⡈⠎⢿⣿{X}", ""),
        ("", f"{G}⡇⠀⣿⣿⣿⣷⣌⠀⠙⢿⣿⣿⣿⣿⠀⢀⣿⣿⣿⣿⠀⠀⠀  ⠀⠈⣿⡇⠀⠀⠀⠀⠈⢿⣿⡇⠁⢻⣿⣿⣿⡿⠁⢠⣾⣿⣿⣿⡿⢿⣿⣷⠀⠘⣿{X}", ""),
        ("", f"{G}⣇⠀⢿⣿⣿⡟⣿⣷⣄⠀⠙⢿⣿⡇⠀⣸⣿⣿⡿⣿⡀⠀⠀⠀  ⢸⣿⣧⠀⠀⠀⠀⣸⡈⣿⣷⠀⡈⣿⣿⡿⠁⢀⣾⣿⣿⢩⣿⠁⣾⣿⣿⡆⠀⢿{X}", ""),
        ("", f"{G}⣿⡀⠘⣿⣿⣿⡘⣿⣿⣷⣌⠂⠉⠁⢠⣿⣿⡟⣰⢿⣷⣤⣤⣴⣿⣿⣿⣷⣄⣠⣴⣿⣧⠸⣿⣧⡐⠢⠉⠁⢀⣾⣿⣿⡇⣼⣿⢸⣿⣿⣿⣇⠀⢸{X}", ""),
        ("", f"{G}⣿⣷⡀⠸⣿⣿⣧⠸⣿⣿⣿⣿⣶⣶⣿⣿⠏⡰⢃⣾⣿⣿⣿⣿⡏⠀⠈⣿⣿⣿⣿⣿⣏⠳⣘⣿⣿⣷⣶⣾⣿⣿⣿⣿⢠⣿⣿⣿⣿⣿⣿⣿⠀⢸{X}", ""),
        ("", f"{G}⣿⣿⡇⠀⣿⣿⣿⡄⡿⢿⣿⣿⣿⣿⣿⣷⣾⣷⣿⣿⣿⣿⣿⣿⣧⣀⣠⣿⣿⣿⣿⣿⣿⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⡇⠸⠋⢉⠉⡉⠛⠿⣿⠀⢸{X}", ""),
        ("", f"{G}⣿⣿⡇⢀⣿⣿⣿⣧⢸⡘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⢠⣾⣿⡄⠈⠀⠀⠀⠀ ⣾{X}", ""),
        ("", f"{G}⣿⡟⠀⣸⣿⣿⣿⣿⣜⡇⢿⣧⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡉⠻⠇⠀⠰⠀⠀ ⣀⣾{X}", ""),
        ("", f"{G}⣿⠃⢠⣿⣿⠿⠿⠿⢿⣿⠸⣿⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢻⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⢣⢸⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⢰⠜⠋⠀⢀⡄⢰⣤⡀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠃⢻⣿⣿{X}", ""),
        ("", f"{G}⣿⣆⠠⠀⡀⠀⠁⣿⣿⠟⠀⣽⣿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢻⣿⣿⣿⣿⣿⢃⣿⣿⣿⡟⣸⣿⣿⣿⣿⡿⠋⢠⢃⣾⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣷⣶⠆⡄⠈⢉⣠⣴⣾⣿⢿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢋⣴⣿⣿⣿⣿⣿⣿⢸⣿⣿⣿⠇⠛⢏⠉⠉⠁⠤⢊⣥⣾⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⢄⠀⢾⣿⣿⣿⣿⡇⢸⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣶⣬⣭⣶⣾⣿⣿⠏⣼⣿⣿⣿⡇⣸⣿⣿⣿⠀⣰⣿⡁⢠⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣤⣀⡀⠀⠀⠉⠉⠁⢸⣿⣿⣿⢸⣿⣿⣿⣿⡹⣿⣿⣿⣿⣿⣿⣿⣿⠋⣼⣿⣿⣿⣿⠇⣿⣿⣿⣿⡀⠹⢿⡇⠀⢿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠛⠀⣼⣿⣿⣿⢸⣿⣿⢻⣿⣷⣌⠻⣿⣿⣿⣿⠟⣡⣾⣿⡟⣼⣿⣿⠀⣿⣿⣿⣿⣿⣶⣤⡀⠀⢸⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⠈⠀⣴⣾⣿⣿⣿⡇⢸⣿⣿⣇⢻⣿⣿⣷⣦⣭⣭⣴⣾⣿⣿⣿⢡⣿⣿⣿⠀⣿⣿⣿⣿⣿⠿⠟⠃⡀⢸⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⡐⠠⢈⡉⠛⠛⠿⡇⢸⣿⣿⣿⡜⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⣼⣿⣿⣿⠀⣁⣤⡄⠀⣀⣒⣀⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⡌⠀⣦⠀⣼⣿⣿⣿⣇⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⢁⣿⣿⣿⣿⣄⡈⠛⠃⠐⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⢁⣤⣿⣿⣿⣿⣿⠘⣿⣿⣿⣿⣿⣿⣿⣿⡟⢸⣿⣿⣿⣿⣿⣿⣦⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠠⣿⣿⣿⣿⣿⣿⣿⠀⣿⣿⣿⣿⣿⣿⣿⣿⡇⢼⠿⠿⣿⣿⣿⣿⠟⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠈⣙⠛⠛⣛⣛⠛⠀⠻⢿⣿⣿⣿⣿⣿⣿⡃⢠⣤⠀⠀⣀⣉⣁⣀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣶⣶⣶⣶⣶⣤⡀⢀⠈⢿⣿⣿⣿⣿⣷⣄⠁⠀⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠁⠈⣿⣿⣿⣿⣿⣿⡆⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠠⢠⣿⣿⣿⣿⣿⠟⢀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡗⠀⢸⣿⣿⣿⡿⢁⡄⣡⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠰⠘⣿⣿⣿⠁⠎⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡑⠈⠻⠇⠈⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
        ("", f"{G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{X}", ""),
    ]

    info = [
        f"{G}{N}GHOST-SCAN{X}",
        f"{Cy}v{VERSAO}  {D}Async Port Scanner & Service Fingerprinter{X}",
        f"{D}{hl}{X}",
        f"{W}By Gh0st-Bx1  {D}{bar}  github.com/Ghost-Bx1{X}",
        f"{D}{hl}{X}",
        f"{D}--target --ports --rate --banner --udp --passive{X}",
        f"{D}--os-detect --cidr --nmap-xml --http-fp --ssl{X}",
        f"{D}-T0-T5 --exclude-cdn --ipv6 --json --html-output{X}",
    ]

    out = [f"{G}{TL}{eq}{TR}{X}", f"{G}{VB}{sp}{VB}{X}"]
    for left, center, right in ga:
        combined = left + center + right
        out.append(_row(combined))
    out.append(f"{G}{VB}{sp}{VB}{X}")
    for i in info:
        out.append(_row_l(i))
    out += [f"{G}{VB}{sp}{VB}{X}", f"{G}{BL}{eq}{BR}{X}"]
    return "\n".join(out)


BANNER = _build_banner()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "curl/8.5.0",
    "python-requests/2.31.0",
    "GhostScan/2.0 (compatible; Recon)",
]

_PROXY = None

C = {
    "R": "\033[91m", "G": "\033[92m", "Y": "\033[93m",
    "B": "\033[94m", "M": "\033[95m", "C": "\033[96m",
    "W": "\033[97m", "X": "\033[0m",  "N": "\033[1m", "D": "\033[2m",
}


def _log(msg, nivel="INFO"):
    cores = {
        "CRITICO": C["R"] + C["N"], "ALERTA": C["Y"], "OK": C["G"],
        "INFO": C["D"], "TITULO": C["C"] + C["N"], "ERRO": C["R"],
    }
    prefix = cores.get(nivel, C["D"])
    X = C["X"]
    icons = {"CRITICO": "[!!!]", "ALERTA": "[!]", "OK": "[+]",
             "INFO": "[*]", "TITULO": "[>]", "ERRO": "[-]"}
    icon = icons.get(nivel, "[*]")
    print(f"  {prefix}{icon}{X} {msg}")


def _secao(titulo):
    X = C["X"]; C2 = C["C"]; N2 = C["N"]
    print(f"\n  {C2}{N2}{'─' * 10} {titulo} {'─' * 10}{X}\n")


# ──────────────────────────────────────────────────────────────────
# Porta / Servico mapping
# ──────────────────────────────────────────────────────────────────

SERVICOS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 119: "NNTP", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    554: "RTSP", 587: "SMTP-Submission", 631: "IPP", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    2121: "FTP-alt", 2375: "Docker-API", 2376: "Docker-TLS",
    2379: "etcd", 3000: "Grafana/NodeJS", 3306: "MySQL",
    3389: "RDP", 3690: "SVN", 4200: "Angular", 4444: "Metasploit",
    4848: "GlassFish", 5000: "Flask/Dev", 5432: "PostgreSQL",
    5601: "Kibana", 5672: "RabbitMQ", 5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS", 6379: "Redis", 6443: "K8s-API",
    7001: "WebLogic", 7077: "Spark", 8080: "HTTP-alt",
    8081: "HTTP-alt2", 8443: "HTTPS-alt", 8888: "Jupyter",
    9000: "SonarQube/PHP-FPM", 9042: "Cassandra", 9090: "Prometheus",
    9200: "Elasticsearch", 9300: "Elasticsearch-Cluster",
    10250: "Kubelet", 10255: "Kubelet-RO", 11211: "Memcached",
    15672: "RabbitMQ-Mgmt", 27017: "MongoDB", 27018: "MongoDB",
    50070: "Hadoop-NameNode", 50075: "Hadoop-DataNode",
}

PORTAS_TOP_100 = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389,
    443, 445, 465, 514, 554, 587, 631, 636, 993, 995, 1080, 1194,
    1433, 1521, 1723, 2049, 2121, 2375, 2376, 2379, 3000, 3306,
    3389, 3690, 4200, 4444, 4848, 5000, 5432, 5601, 5672, 5985,
    5986, 6379, 6443, 7001, 7077, 8080, 8081, 8443, 8888, 9000,
    9042, 9090, 9200, 9300, 10250, 10255, 11211, 15672, 27017,
    27018, 50070, 50075,
]

PORTAS_FULL = list(range(1, 65536))

# Banners para servicos comuns (enviamos uma sonda e lemos a resposta)
SONDAS_BANNER = {
    21:   b"",
    22:   b"",
    25:   b"EHLO ghost\r\n",
    80:   b"HEAD / HTTP/1.0\r\n\r\n",
    110:  b"",
    143:  b"",
    443:  b"",
    3306: b"",
    5432: b"",
    6379: b"INFO\r\n",
    9200: b"",
    11211:b"stats\r\n",
    27017:b"",
}

# CVE database simplificada (servico, versao_regex) -> [CVE, score, descricao]
CVE_DB = {
    "OpenSSH": [
        ("7\\.2", "CVE-2016-6515", 7.8, "DoS via large passwords (auth disabled)"),
        ("7\\.4", "CVE-2018-15473", 5.3, "User enumeration via timing attack"),
        ("8\\.2", "CVE-2023-38408", 9.8, "Remote code execution via ssh-agent forwarding"),
    ],
    "Apache": [
        ("2\\.4\\.4[89]", "CVE-2021-41773", 9.8, "Path traversal + RCE (mod_cgi)"),
        ("2\\.4\\.50", "CVE-2021-42013", 9.8, "Path traversal bypass"),
        ("2\\.4\\.\\d+", "CVE-2022-31813", 9.8, "Forwarded headers bypass"),
    ],
    "nginx": [
        ("1\\.18\\.0", "CVE-2021-23017", 7.7, "DNS resolver off-by-one"),
        ("1\\.\\d+\\.\\d+", "CVE-2013-2028", 7.5, "Stack overflow (old nginx)"),
    ],
    "ProFTPD": [
        ("1\\.3\\.[45]", "CVE-2019-12815", 9.8, "Arbitrary file copy via site cpfr/cpto"),
    ],
    "vsftpd": [
        ("2\\.3\\.4", "CVE-2011-2523", 10.0, "Backdoor command execution"),
    ],
    "Redis": [
        (".*", "CVE-2022-0543", 10.0, "Lua sandbox escape -> RCE (Debian/Ubuntu)"),
        (".*", "INFO-NOAUTH", 7.5, "Redis acessivel sem autenticacao"),
    ],
    "Elasticsearch": [
        (".*", "INFO-NOAUTH", 9.8, "Elasticsearch sem autenticacao - dados expostos"),
    ],
    "MongoDB": [
        (".*", "INFO-NOAUTH", 9.8, "MongoDB sem autenticacao - dados expostos"),
    ],
    "Memcached": [
        (".*", "INFO-NOAUTH", 9.8, "Memcached sem autenticacao + UDP amplification DDoS"),
    ],
    "Docker": [
        (".*", "INFO-SOCK", 9.9, "Docker API exposta sem autenticacao - RCE trivial"),
    ],
}


# ──────────────────────────────────────────────────────────────────
# Async TCP Scanner
# ──────────────────────────────────────────────────────────────────

async def _scan_porta_async(host, porta, timeout=1.0, grab_banner=False):
    """Tenta conexao TCP assincrona. Retorna dict com resultado."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, porta), timeout=timeout
        )
        resultado = {"porta": porta, "aberta": True, "banner": "", "servico": SERVICOS.get(porta, "unknown")}

        if grab_banner:
            sonda = SONDAS_BANNER.get(porta, b"")
            if sonda:
                try:
                    writer.write(sonda)
                    await writer.drain()
                except Exception:
                    pass
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                if data:
                    resultado["banner"] = data.decode("utf-8", errors="ignore").strip()[:200]
            except Exception:
                pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return resultado
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def scan_tcp_async(host, portas, timeout=1.0, rate=10000, grab_banner=False, verbose=False):
    """Varre lista de portas assincronamente, respeitando rate limit."""
    abertos = []
    sem = asyncio.Semaphore(min(rate, len(portas)))

    async def _com_sem(p):
        async with sem:
            return await _scan_porta_async(host, p, timeout=timeout, grab_banner=grab_banner)

    tasks = [asyncio.create_task(_com_sem(p)) for p in portas]
    total = len(tasks)
    concluido = 0

    for fut in asyncio.as_completed(tasks):
        r = await fut
        concluido += 1
        if r and r["aberta"]:
            abertos.append(r)
            svc = r["servico"]
            banner = f" | {r['banner'][:60]}" if r["banner"] else ""
            _log(f"ABERTA  {host}:{r['porta']:5}  {svc:20}{banner}", "OK")
        if verbose and concluido % 1000 == 0:
            _log(f"Progresso: {concluido}/{total} portas verificadas", "INFO")

    return sorted(abertos, key=lambda x: x["porta"])


# ──────────────────────────────────────────────────────────────────
# OS Deteccao via TTL / TCP Window
# ──────────────────────────────────────────────────────────────────

def detectar_os_ttl(host, timeout=3):
    """Estima SO alvo via TTL do ping ICMP (socket raw) ou TTL do TCP."""
    try:
        # Usa socket TCP para obter TTL (via getpeername e getsockopt nao funciona em Python facilmente)
        # Usa ping do sistema como fallback
        import subprocess as _sub
        import platform as _pl
        param = "-n" if _pl.system().lower() == "windows" else "-c"
        saida = _sub.check_output(
            ["ping", param, "1", "-W", "2", host],
            stderr=_sub.DEVNULL, timeout=timeout
        ).decode("utf-8", errors="ignore")

        m = re.search(r"[Tt][Tt][Ll]=?(\d+)", saida)
        if m:
            ttl = int(m.group(1))
            # TTL em roteadores diminui por hop; estimativa de hop ~1-5
            if ttl <= 64:
                return {"ttl": ttl, "os_estimado": "Linux/Unix/macOS", "confianca": "media"}
            elif ttl <= 128:
                return {"ttl": ttl, "os_estimado": "Windows", "confianca": "media"}
            elif ttl <= 255:
                return {"ttl": ttl, "os_estimado": "Cisco/Solaris/FreeBSD", "confianca": "baixa"}
        return {"ttl": None, "os_estimado": "Desconhecido", "confianca": "nenhuma"}
    except Exception:
        return {"ttl": None, "os_estimado": "Ping falhou", "confianca": "nenhuma"}


# ──────────────────────────────────────────────────────────────────
# UDP Scanner
# ──────────────────────────────────────────────────────────────────

UDP_SERVICOS = {
    53:  ("DNS", b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                  b"\x05ghost\x02bx\x00\x00\x01\x00\x01"),
    161: ("SNMP", b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19"
                   b"\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30"
                   b"\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"),
    123: ("NTP", b"\x1b" + b"\x00" * 47),
    69:  ("TFTP", b"\x00\x01test.txt\x00octet\x00"),
}


def scan_udp(host, portas=None, timeout=2):
    """Sonda portas UDP comuns e verifica respostas."""
    if portas is None:
        portas = list(UDP_SERVICOS.keys())
    resultados = []
    for porta in portas:
        if porta not in UDP_SERVICOS:
            continue
        nome, sonda = UDP_SERVICOS[porta]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(sonda, (host, porta))
            data, _ = sock.recvfrom(1024)
            resultados.append({
                "porta": porta, "protocolo": "UDP",
                "servico": nome, "resposta": data[:64].hex()
            })
            _log(f"UDP ABERTA  {host}:{porta}  {nome}  resposta={data[:20].hex()}", "ALERTA")
        except socket.timeout:
            # Sem resposta nao significa fechada em UDP
            pass
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return resultados


# ──────────────────────────────────────────────────────────────────
# Correlacao CVE
# ──────────────────────────────────────────────────────────────────

def correlacionar_cves(portas_abertas):
    """Cruza banners com CVE_DB e reporta vulnerabilidades potenciais."""
    _secao("CORRELACAO CVE")
    achados = []
    for p in portas_abertas:
        banner = p.get("banner", "")
        if not banner:
            continue
        for produto, cves in CVE_DB.items():
            if produto.lower() in banner.lower():
                for ver_regex, cve_id, score, descricao in cves:
                    if re.search(ver_regex, banner, re.IGNORECASE):
                        nivel = "CRITICO" if score >= 9 else "ALERTA" if score >= 7 else "INFO"
                        _log(f"{cve_id} [{score}] porta {p['porta']} ({produto}): {descricao}", nivel)
                        achados.append({
                            "porta": p["porta"], "cve": cve_id,
                            "score": score, "descricao": descricao, "banner": banner[:100]
                        })
    if not achados:
        _log("Nenhuma CVE correlacionada nos banners coletados", "INFO")
    return achados


# ──────────────────────────────────────────────────────────────────
# CIDR Expansion
# ──────────────────────────────────────────────────────────────────

def expandir_cidr(alvo):
    """Expande CIDR ou retorna lista com host unico."""
    try:
        net = ipaddress.ip_network(alvo, strict=False)
        if net.num_addresses > 65536:
            _log(f"Rede muito grande ({net.num_addresses} hosts) - limitando a /16", "ALERTA")
            return []
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [alvo]


# ──────────────────────────────────────────────────────────────────
# Export Nmap XML
# ──────────────────────────────────────────────────────────────────

def exportar_nmap_xml(host, portas_abertas, udp_resultados, os_info, caminho):
    """Exporta resultados em formato Nmap XML (compativel com ferramentas que parseiam nmap)."""
    ts = int(time.time())
    linhas = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<!DOCTYPE nmaprun>',
        f'<nmaprun scanner="ghost-scan" args="ghost-scan -t {host}" start="{ts}" version="{VERSAO}">',
        f'  <host starttime="{ts}" endtime="{ts}">',
        f'    <address addr="{host}" addrtype="ipv4"/>',
        f'    <status state="up" reason="syn-ack"/>',
        f'    <os><osmatch name="{os_info.get("os_estimado", "Unknown")}" accuracy="50"/></os>',
        f'    <ports>',
    ]
    for p in portas_abertas:
        svc = p.get("servico", "unknown")
        banner = p.get("banner", "").replace("<", "&lt;").replace(">", "&gt;")[:100]
        linhas.append(f'      <port protocol="tcp" portid="{p["porta"]}">')
        linhas.append(f'        <state state="open" reason="syn-ack"/>')
        linhas.append(f'        <service name="{svc}"><banner><![CDATA[{banner}]]></banner></service>')
        linhas.append(f'      </port>')
    for u in udp_resultados:
        linhas.append(f'      <port protocol="udp" portid="{u["porta"]}">')
        linhas.append(f'        <state state="open" reason="udp-response"/>')
        linhas.append(f'        <service name="{u["servico"]}"/>')
        linhas.append(f'      </port>')
    linhas += ['    </ports>', '  </host>', '</nmaprun>']
    with open(caminho, "w") as f:
        f.write("\n".join(linhas))
    _log(f"Nmap XML salvo: {caminho}", "OK")


# ──────────────────────────────────────────────────────────────────
# HTTP FINGERPRINT
# ──────────────────────────────────────────────────────────────────

def http_fingerprint(host, porta, timeout=5, ssl_ctx=None):
    """Captura titulo, Server header e tecnologias de uma porta web."""
    esquema = "https" if (porta in (443, 8443, 4443) or ssl_ctx) else "http"
    url = f"{esquema}://{host}:{porta}/"
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    ua = random.choice(USER_AGENTS)
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    if _PROXY:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": _PROXY, "https": _PROXY}),
            urllib.request.HTTPSHandler(context=ctx)
        )
        urllib.request.install_opener(opener)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            headers = dict(r.headers)
            body = r.read(4096).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        headers = dict(e.headers) if e.headers else {}
        body = ""
    except Exception:
        return None

    # Titulo
    titulo = ""
    import re as _re
    m = _re.search(r"<title[^>]*>([^<]{0,120})</title>", body, _re.I)
    if m:
        titulo = m.group(1).strip()

    # Tecnologias
    techs = []
    server = headers.get("server") or headers.get("Server", "")
    powered = headers.get("x-powered-by") or headers.get("X-Powered-By", "")
    if server:
        techs.append(f"Server: {server}")
    if powered:
        techs.append(f"X-Powered-By: {powered}")
    # Framework hints no body/headers
    for sig, nome in [("wp-content", "WordPress"), ("Joomla", "Joomla"),
                      ("drupal", "Drupal"), ("Laravel", "Laravel"),
                      ("React", "React"), ("Angular", "Angular"),
                      ("jquery", "jQuery"), ("bootstrap", "Bootstrap"),
                      ("phpMyAdmin", "phpMyAdmin"), ("jenkins", "Jenkins"),
                      ("Tomcat", "Tomcat"), ("grafana", "Grafana")]:
        if sig.lower() in body.lower():
            techs.append(nome)

    # Favicon hash (MurmurHash3-inspired: simple 32-bit XOR rotate for fingerprinting)
    favicon_fp = None
    try:
        fav_url = f"{esquema}://{host}:{porta}/favicon.ico"
        fav_req = urllib.request.Request(fav_url, headers={"User-Agent": ua})
        with urllib.request.urlopen(fav_req, timeout=timeout, context=ctx) as fr:
            fav_data = fr.read(65536)
        if fav_data:
            h = 0x9747b28c
            for b in fav_data:
                h ^= b; h = ((h << 5) | (h >> 27)) & 0xFFFFFFFF; h ^= (h >> 16)
            favicon_fp = h if h <= 0x7FFFFFFF else h - 0x100000000
    except Exception:
        pass

    return {"url": url, "titulo": titulo, "server": server, "techs": techs,
            "status": headers.get("status", ""), "x-powered-by": powered,
            "favicon_hash": favicon_fp}


def fingerprint_portas_web(host, portas_abertas, timeout=5, verbose=False):
    """Roda HTTP fingerprint em todas as portas web abertas."""
    portas_web = {80, 443, 8080, 8443, 8008, 8888, 3000, 4000, 5000, 9000, 9090, 9200}
    resultados = {}
    for p_info in portas_abertas:
        porta = p_info["porta"] if isinstance(p_info, dict) else p_info
        if porta in portas_web:
            fp = http_fingerprint(host, porta, timeout=timeout)
            if fp:
                resultados[porta] = fp
                nivel = "OK"
                titulo_str = f" | {fp['titulo']}" if fp["titulo"] else ""
                server_str = f" | {fp['server']}" if fp["server"] else ""
                techs_str = f" | {', '.join(fp['techs'])}" if fp["techs"] else ""
                _log(f"HTTP:{porta}{titulo_str}{server_str}{techs_str}", nivel)
            elif verbose:
                _log(f"HTTP:{porta} sem resposta", "INFO")
    return resultados


# ──────────────────────────────────────────────────────────────────
# SSL/TLS ANALYSIS
# ──────────────────────────────────────────────────────────────────

def analisar_ssl(host, porta=443, timeout=5):
    """Analisa certificado SSL/TLS e cipher suite de uma porta."""
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    try:
        conn = _ssl.SSLSocket
        with _ssl.wrap_socket(socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET),
                               server_hostname=host, ssl_version=_ssl.PROTOCOL_TLS_CLIENT if hasattr(_ssl, 'PROTOCOL_TLS_CLIENT') else _ssl.PROTOCOL_SSLv23) as s:
            s.settimeout(timeout)
            s.connect((host, porta))
            cipher = s.cipher()
            cert = s.getpeercert()
    except Exception:
        # Fallback sem SNI
        try:
            ctx2 = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT if hasattr(_ssl, 'PROTOCOL_TLS_CLIENT') else _ssl.PROTOCOL_SSLv23)
            ctx2.check_hostname = False
            ctx2.verify_mode = _ssl.CERT_NONE
            with ctx2.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(timeout)
                s.connect((host, porta))
                cipher = s.cipher()
                cert = s.getpeercert()
        except Exception as e:
            return {"erro": str(e)}

    resultado = {
        "porta": porta,
        "cipher_name": cipher[0] if cipher else "desconhecido",
        "protocol": cipher[1] if cipher else "desconhecido",
        "bits": cipher[2] if cipher else 0,
    }

    if cert:
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        resultado["cn"] = subject.get("commonName", "")
        resultado["issuer"] = issuer.get("organizationName", "")
        resultado["not_before"] = cert.get("notBefore", "")
        resultado["not_after"]  = cert.get("notAfter", "")
        resultado["sans"] = [v for _, v in cert.get("subjectAltName", [])]

    # Flags de fraqueza
    weak = []
    if cipher and cipher[1] in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
        weak.append(f"Protocolo fraco: {cipher[1]}")
    if cipher and cipher[2] and cipher[2] < 128:
        weak.append(f"Chave fraca: {cipher[2]} bits")
    if cipher and cipher[0] and any(w in cipher[0].upper() for w in ("RC4", "MD5", "DES", "NULL", "EXPORT")):
        weak.append(f"Cipher inseguro: {cipher[0]}")
    resultado["fraquezas"] = weak

    return resultado


def ssl_scan_portas(host, portas_abertas, timeout=5, verbose=False):
    """Roda analise SSL nas portas 443/8443 abertas."""
    portas_ssl = {443, 8443, 4443, 9443}
    resultados = {}
    for p_info in portas_abertas:
        porta = p_info["porta"] if isinstance(p_info, dict) else p_info
        if porta in portas_ssl:
            r = analisar_ssl(host, porta, timeout=timeout)
            resultados[porta] = r
            if "erro" in r:
                if verbose:
                    _log(f"SSL:{porta} erro: {r['erro']}", "INFO")
            else:
                nivel = "ALERTA" if r.get("fraquezas") else "OK"
                cn = r.get("cn", "")
                proto = r.get("protocol", "")
                bits = r.get("bits", 0)
                fraq = " | FRACO: " + "; ".join(r["fraquezas"]) if r.get("fraquezas") else ""
                _log(f"SSL:{porta} {proto} {bits}b CN={cn}{fraq}", nivel)
                if r.get("sans") and verbose:
                    _log(f"  SANs: {', '.join(r['sans'][:5])}", "INFO")
                if r.get("not_after"):
                    _log(f"  Expira: {r['not_after']}", "INFO")
    return resultados


# ──────────────────────────────────────────────────────────────────
# IPv6 support helper
# ──────────────────────────────────────────────────────────────────

def resolver_ipv6(host, timeout=3):
    """Resolve AAAA record e retorna primeiro IPv6 ou None."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET6, socket.SOCK_STREAM)
        if infos:
            return infos[0][4][0]
    except Exception:
        pass
    return None


# ──────────────────────────────────────────────────────────────────
# Scan de host unico
# ──────────────────────────────────────────────────────────────────

def scan_host(host, portas, args):
    """Executa scan completo em um host."""
    _secao(f"SCAN: {host}")
    t_inicio = time.time()

    # Resolve DNS se for nome
    try:
        ip = socket.gethostbyname(host)
        if ip != host:
            _log(f"Resolvido: {host} -> {ip}", "INFO")
    except socket.gaierror:
        _log(f"Nao foi possivel resolver {host}", "ERRO")
        return {}

    # OS detection
    os_info = {}
    if args.os_detect:
        _secao("OS DETECTION (TTL)")
        os_info = detectar_os_ttl(ip, timeout=args.timeout)
        nivel = "ALERTA" if os_info["confianca"] != "nenhuma" else "INFO"
        _log(f"OS estimado: {os_info['os_estimado']} (TTL={os_info['ttl']}, confianca={os_info['confianca']})", nivel)

    # TCP scan
    _secao(f"TCP SCAN ({len(portas)} portas)")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        portas_abertas = loop.run_until_complete(
            scan_tcp_async(ip, portas, timeout=args.timeout,
                           rate=args.rate, grab_banner=args.banner,
                           verbose=args.verbose)
        )
    finally:
        loop.close()

    _log(f"TCP: {len(portas_abertas)} porta(s) abertas de {len(portas)} verificadas", "OK")

    # UDP scan
    udp_resultados = []
    if args.udp:
        _secao("UDP SCAN")
        udp_resultados = scan_udp(ip, timeout=args.timeout)
        _log(f"UDP: {len(udp_resultados)} servico(s) responderam", "OK" if udp_resultados else "INFO")

    # CVE correlacao
    cves = []
    if args.banner and portas_abertas:
        cves = correlacionar_cves(portas_abertas)

    # HTTP fingerprint
    http_fp = {}
    if getattr(args, "http_fp", False) and portas_abertas:
        _secao("HTTP FINGERPRINT")
        http_fp = fingerprint_portas_web(ip, portas_abertas, timeout=args.timeout,
                                         verbose=args.verbose)

    # SSL/TLS analysis
    ssl_info = {}
    if getattr(args, "ssl", False) and portas_abertas:
        _secao("SSL/TLS ANALYSIS")
        ssl_info = ssl_scan_portas(ip, portas_abertas, timeout=args.timeout,
                                   verbose=args.verbose)

    # IPv6 resolve
    ipv6_addr = None
    if getattr(args, "ipv6", False):
        ipv6_addr = resolver_ipv6(host, timeout=args.timeout)
        if ipv6_addr:
            _log(f"IPv6: {ipv6_addr}", "OK")
        else:
            _log("IPv6: sem resposta AAAA", "INFO")

    # Web vulnerability scan
    vuln_findings = []
    if getattr(args, "vuln", False) and portas_abertas:
        vuln_findings = vuln_scan_http(ip, portas_abertas,
                                       timeout=max(args.timeout, 8),
                                       verbose=args.verbose)

    elapsed = time.time() - t_inicio
    _log(f"Scan concluido em {elapsed:.1f}s", "INFO")

    return {
        "host": host, "ip": ip,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "portas_tcp": portas_abertas,
        "portas_udp": udp_resultados,
        "os": os_info,
        "cves": cves,
        "http_fingerprint": http_fp,
        "ssl": ssl_info,
        "ipv6": ipv6_addr,
        "vulns": vuln_findings,
        "duracao_s": round(elapsed, 2),
    }


# ──────────────────────────────────────────────────────────────────
# HTML Report
# ──────────────────────────────────────────────────────────────────

def gerar_html(resultados: list, output_path: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    linhas_hosts = ""
    for r in resultados:
        host = r.get("host", "?")
        ip = r.get("ip", "?")
        portas = r.get("portas_tcp", [])
        cves = r.get("cves", [])
        os_est = r.get("os", {}).get("os_estimado", "?")
        rows = "".join(
            f"<tr><td>{p['porta']}/tcp</td><td>{p.get('servico','?')}</td>"
            f"<td style='color:#39d353'>open</td>"
            f"<td style='font-size:11px;color:#8b949e'>{p.get('banner','')[:80]}</td></tr>"
            for p in portas
        )
        cve_rows = "".join(
            f"<tr><td style='color:#f85149'>{c['cve']}</td><td>{c['porta']}</td>"
            f"<td>{c['score']}</td><td style='font-size:11px'>{c['descricao']}</td></tr>"
            for c in cves
        )
        linhas_hosts += f"""
<div class="host-box">
  <h3>{host} ({ip}) &mdash; OS: {os_est} &mdash; {len(portas)} porta(s) TCP</h3>
  <table><thead><tr><th>Porta</th><th>Servico</th><th>Estado</th><th>Banner</th></tr></thead>
  <tbody>{rows or '<tr><td colspan=4>Sem portas abertas</td></tr>'}</tbody></table>
  {'<h4 style="color:#f85149">CVEs Detectadas</h4><table><thead><tr><th>CVE</th><th>Porta</th><th>CVSS</th><th>Descricao</th></tr></thead><tbody>' + cve_rows + '</tbody></table>' if cve_rows else ''}
</div>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Ghost-Scan Report</title>
<style>body{{background:#0d1117;color:#e6edf3;font-family:monospace;padding:20px;}}
h1,h2{{color:#39d353;}} h3{{color:#58a6ff;}} h4{{color:#f0883e;}}
table{{width:100%;border-collapse:collapse;margin:8px 0;}}
th{{background:#161b22;padding:6px 10px;text-align:left;border-bottom:1px solid #30363d;color:#8b949e;}}
td{{padding:5px 10px;border-bottom:1px solid #21262d;font-size:12px;}}
.host-box{{background:#161b22;padding:15px;border-radius:6px;border-left:4px solid #58a6ff;margin:12px 0;}}
</style></head><body>
<h1>Ghost-Scan Report</h1>
<p>By Gh0st-Bx1 | github.com/Ghost-Bx1 | {ts} | {len(resultados)} host(s)</p>
{linhas_hosts}
</body></html>"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    _log(f"Relatorio HTML: {output_path}", "OK")


# ──────────────────────────────────────────────────────────────────
# Web Vulnerability Scanner
# ──────────────────────────────────────────────────────────────────

_SQLI_PAYLOADS = [
    "'", "''", "`", "\"", "\\",
    "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
    "1' AND SLEEP(3)--", "1'; WAITFOR DELAY '0:0:3'--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' AND 1=CONVERT(int,@@version)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
]
_SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-", "pg_query", "sqlite_",
    "syntax error", "unclosed quotation", "quoted string not properly",
    "you have an error in your sql", "warning: mysql", "sqlstate",
    "microsoft ole db", "odbc drivers error", "db2 sql error",
    "supplied argument is not a valid mysql", "division by zero",
]
_LFI_PAYLOADS = [
    "../../../etc/passwd", "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd", "..//..//..//etc/passwd",
    "..%252f..%252fetc%252fpasswd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "file:///etc/passwd", "/etc/passwd%00",
    "C:\\Windows\\win.ini", "..\\..\\..\\Windows\\win.ini",
]
_LFI_SIGNATURES = ["root:x:0:0", "daemon:", "bin:x:", "[extensions]", "for 16-bit app"]
_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "{{7*7}}",  # SSTI detection
    "${7*7}",
]
_SSRF_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/metadata/instance",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/info",
]
_AUTH_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
]
_SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/config.php", "/wp-config.php",
    "/web.config", "/appsettings.json", "/.aws/credentials",
    "/phpinfo.php", "/info.php", "/server-status", "/server-info",
    "/.DS_Store", "/backup.zip", "/backup.tar.gz", "/dump.sql",
    "/robots.txt", "/sitemap.xml", "/.htpasswd", "/crossdomain.xml",
    "/swagger.json", "/api/swagger.json", "/openapi.json",
    "/actuator", "/actuator/env", "/actuator/health",
    "/.well-known/security.txt", "/debug", "/console",
    "/admin", "/administrator", "/manager", "/phpmyadmin",
]


def _http_vuln(url, method="GET", body=None, headers=None, timeout=8):
    """HTTP helper minimo para vuln scan."""
    import urllib.request as _ur, urllib.parse as _up, ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    h = {"User-Agent": "Mozilla/5.0 (compatible; GhostScan/1.0)"}
    if headers:
        h.update(headers)
    req = _ur.Request(url, data=body, method=method)
    for k, v in h.items():
        req.add_header(k, v)
    try:
        with _ur.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(32768)
    except _ur.error.HTTPError as e:
        return e.code, dict(e.headers), b""
    except Exception:
        return 0, {}, b""


def _base_urls(host, portas_abertas):
    """Monta lista de base URLs HTTP/HTTPS a partir das portas abertas."""
    urls = []
    for p in portas_abertas:
        porta = p.get("porta", 0)
        if porta in (443, 8443, 4443):
            urls.append(f"https://{host}:{porta}")
        elif porta in (80, 8080, 8000, 8008, 3000, 5000, 9090):
            urls.append(f"http://{host}:{porta}")
    if not urls:
        urls.append(f"http://{host}")
    return list(dict.fromkeys(urls))


def _encontrar_params(url, timeout=8):
    """Busca parametros GET/POST na pagina principal e forms."""
    params = []
    try:
        status, headers, body = _http_vuln(url, timeout=timeout)
        if status == 0:
            return params
        texto = body.decode("utf-8", errors="ignore")
        # Parametros na URL de redirecionamento
        import re
        params += re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{0,30})=', texto)
        # Input fields em forms
        params += re.findall(r'<input[^>]+name=["\']([^"\']{1,30})["\']', texto, re.I)
        # JSON keys
        params += re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]{0,20})":\s*"', texto)
    except Exception:
        pass
    seen = set()
    result = []
    for p in params:
        if p.lower() not in seen and p.lower() not in ("submit", "button", "action", "token", "csrf"):
            seen.add(p.lower())
            result.append(p)
    return result[:10]


def vuln_scan_sqli(base_url, params, timeout=8, verbose=False):
    """Testa SQLi em parametros GET encontrados."""
    achados = []
    test_params = params if params else ["id", "page", "cat", "user", "q", "search", "item", "product"]

    for param in test_params[:8]:
        for payload in _SQLI_PAYLOADS[:6]:
            import urllib.parse as _up
            url = f"{base_url}/?{param}={_up.quote(payload)}"
            status, _, body = _http_vuln(url, timeout=timeout)
            texto = body.decode("utf-8", errors="ignore").lower()
            for err in _SQLI_ERRORS:
                if err in texto:
                    achados.append({
                        "tipo": "sqli", "severidade": "CRITICO",
                        "url": url, "param": param, "payload": payload,
                        "evidencia": err,
                    })
                    _log(f"SQLi [{param}]: {err[:60]}", "CRITICO")
                    break
            if verbose and status:
                _log(f"SQLi probe {param}: HTTP {status}", "INFO")
    return achados


def vuln_scan_lfi(base_url, params, timeout=8, verbose=False):
    """Testa LFI em parametros de arquivo/pagina."""
    achados = []
    file_params = [p for p in params if any(k in p.lower() for k in
                   ("file", "path", "page", "include", "template", "load", "dir", "doc", "view"))]
    if not file_params:
        file_params = ["file", "page", "path", "include", "template"]

    for param in file_params[:5]:
        for payload in _LFI_PAYLOADS[:8]:
            import urllib.parse as _up
            url = f"{base_url}/?{param}={_up.quote(payload)}"
            status, _, body = _http_vuln(url, timeout=timeout)
            texto = body.decode("utf-8", errors="ignore")
            for sig in _LFI_SIGNATURES:
                if sig in texto:
                    achados.append({
                        "tipo": "lfi", "severidade": "CRITICO",
                        "url": url, "param": param, "payload": payload,
                        "evidencia": sig,
                    })
                    _log(f"LFI [{param}]: '{sig}' encontrado", "CRITICO")
                    break
            if verbose and status:
                _log(f"LFI probe {param}: HTTP {status}", "INFO")
    return achados


def vuln_scan_xss(base_url, params, timeout=8, verbose=False):
    """Testa XSS refletido em parametros GET."""
    achados = []
    test_params = params if params else ["q", "search", "name", "msg", "text", "input", "s"]

    for param in test_params[:8]:
        for payload in _XSS_PAYLOADS[:5]:
            import urllib.parse as _up
            url = f"{base_url}/?{param}={_up.quote(payload)}"
            status, _, body = _http_vuln(url, timeout=timeout)
            texto = body.decode("utf-8", errors="ignore")
            # Verifica reflexao do payload
            if payload in texto or payload.lower() in texto.lower():
                achados.append({
                    "tipo": "xss", "severidade": "ALTO",
                    "url": url, "param": param, "payload": payload,
                    "evidencia": "payload refletido na resposta",
                })
                _log(f"XSS refletido [{param}]: payload na resposta", "ALERTA")
            # SSTI
            if "{{7*7}}" in payload or "${7*7}" in payload:
                if "49" in texto:
                    achados.append({
                        "tipo": "ssti", "severidade": "CRITICO",
                        "url": url, "param": param, "payload": payload,
                        "evidencia": "7*7=49 calculado pelo template engine",
                    })
                    _log(f"SSTI [{param}]: template injection confirmado!", "CRITICO")
            if verbose and status:
                _log(f"XSS probe {param}: HTTP {status}", "INFO")
    return achados


def vuln_scan_ssrf(base_url, params, timeout=8, verbose=False):
    """Testa SSRF em parametros de URL/redirect."""
    achados = []
    ssrf_params = [p for p in params if any(k in p.lower() for k in
                   ("url", "uri", "redirect", "next", "return", "link", "src", "dest", "proxy", "callback", "fetch"))]
    if not ssrf_params:
        ssrf_params = ["url", "redirect", "next", "return", "link", "src"]

    for param in ssrf_params[:5]:
        for ssrf_url in _SSRF_URLS[:4]:
            import urllib.parse as _up
            url = f"{base_url}/?{param}={_up.quote(ssrf_url)}"
            status, headers, body = _http_vuln(url, timeout=timeout)
            texto = body.decode("utf-8", errors="ignore")
            # Indicadores de SSRF bem-sucedido
            if any(sig in texto for sig in ["ami-id", "instance-id", "compute.internal",
                                             "root:x:0", "metadata", "iam/security"]):
                achados.append({
                    "tipo": "ssrf", "severidade": "CRITICO",
                    "url": url, "param": param, "ssrf_target": ssrf_url,
                    "evidencia": texto[:100],
                })
                _log(f"SSRF [{param}]: metadados internos acessados!", "CRITICO")
            if verbose and status:
                _log(f"SSRF probe {param}: HTTP {status}", "INFO")
    return achados


def vuln_scan_auth_bypass(base_url, timeout=8, verbose=False):
    """Testa bypass de autenticacao via headers e paths sensiveis."""
    achados = []
    admin_paths = ["/admin", "/administrator", "/manager", "/api/admin", "/dashboard", "/console"]

    for path in admin_paths:
        url = f"{base_url}{path}"
        # Requisicao normal
        status_normal, _, _ = _http_vuln(url, timeout=timeout)
        if status_normal in (401, 403):
            # Tentar bypass com headers
            for bypass_headers in _AUTH_BYPASS_HEADERS:
                s, _, body = _http_vuln(url, headers=bypass_headers, timeout=timeout)
                if s == 200 and len(body) > 100:
                    achados.append({
                        "tipo": "auth_bypass", "severidade": "CRITICO",
                        "url": url, "headers_usados": bypass_headers,
                        "evidencia": f"HTTP 403 -> HTTP 200 com header {list(bypass_headers.keys())[0]}",
                    })
                    _log(f"Auth Bypass [{path}]: {list(bypass_headers.keys())[0]} -> HTTP 200", "CRITICO")
                    break
            if verbose:
                _log(f"Auth bypass probe {path}: HTTP {status_normal}", "INFO")
    return achados


def vuln_scan_exposed_files(base_url, timeout=8, verbose=False):
    """Busca arquivos e endpoints sensiveis expostos."""
    achados = []
    for path in _SENSITIVE_PATHS:
        url = f"{base_url}{path}"
        status, headers, body = _http_vuln(url, timeout=timeout)
        if status in (200, 206):
            tamanho = len(body)
            ct = headers.get("Content-Type", "")
            if tamanho > 20:
                sev = "CRITICO" if any(k in path for k in (".env", ".git", "credentials", "config", "dump", "backup", "shadow")) else "ALTO"
                achados.append({
                    "tipo": "exposed_file", "severidade": sev,
                    "url": url, "status": status,
                    "tamanho": tamanho, "content_type": ct,
                    "evidencia": body[:80].decode("utf-8", errors="ignore"),
                })
                _log(f"Arquivo exposto [{path}]: HTTP {status} ({tamanho}B)", sev)
        if verbose and status and status != 404:
            _log(f"Path probe {path}: HTTP {status}", "INFO")
    return achados


def vuln_scan_waf(base_url, timeout=8, verbose=False):
    """Detecta presenca de WAF via fingerprint de headers e respostas a payloads."""
    achados = []
    WAF_HEADERS = {
        "server": {
            "cloudflare": "Cloudflare", "sucuri": "Sucuri", "mod_security": "ModSecurity",
            "akamai": "Akamai", "imperva": "Imperva", "f5 big-ip": "F5 BIG-IP",
            "barracuda": "Barracuda", "fastly": "Fastly",
        },
        "x-powered-by": {"imperva": "Imperva"},
        "x-sucuri-id": {"sucuri": "Sucuri"},
        "cf-ray": {"cloudflare": "Cloudflare"},
        "x-waf-event-info": {"barracuda": "Barracuda"},
        "x-akamai-transformed": {"akamai": "Akamai"},
        "x-fw-block-reason": {"fortiweb": "FortiWeb"},
    }
    WAF_PAYLOADS = [
        "?q=<script>alert(1)</script>",
        "?id=1' OR '1'='1",
        "?file=../../../etc/passwd",
    ]
    detected = set()
    try:
        # Probe 1: normal request - check headers
        status, headers, body = _http(base_url, timeout=timeout)
        for hdr_name, patterns in WAF_HEADERS.items():
            hdr_val = headers.get(hdr_name, "").lower()
            for sig, waf_name in patterns.items():
                if sig in hdr_val:
                    detected.add(waf_name)

        # Probe 2: inject attack payloads and look for WAF block pages
        for path in WAF_PAYLOADS:
            try:
                st, hdrs, bd = _http(base_url.rstrip("/") + path, timeout=timeout)
                body_s = bd.decode(errors="replace").lower()
                # Common WAF block signatures
                if any(sig in body_s for sig in ["access denied", "request blocked",
                        "security check", "waf", "malicious", "forbidden by policy",
                        "attack detected", "mod_security", "sucuri cloudproxy"]):
                    detected.add("WAF (generic block page)")
                # HTTP 403/406/419/429 from WAF
                if st in (403, 406, 419, 429) and not detected:
                    detected.add("WAF (suspicious HTTP status)")
                for hdr_name, patterns in WAF_HEADERS.items():
                    hdr_val = hdrs.get(hdr_name, "").lower()
                    for sig, waf_name in patterns.items():
                        if sig in hdr_val:
                            detected.add(waf_name)
            except Exception:
                pass

        if detected:
            for waf in detected:
                _log(f"WAF detectado: {waf} em {base_url}", "ALERTA")
                achados.append({
                    "tipo": "waf", "severidade": "INFO",
                    "url": base_url, "detalhe": f"WAF: {waf}",
                    "evidencia": waf,
                })
        else:
            if verbose:
                _log(f"Nenhum WAF detectado em {base_url}", "INFO")
    except Exception as e:
        if verbose:
            _log(f"Erro WAF scan: {e}", "ERRO")
    return achados


def vuln_scan_cors(base_url, timeout=8, verbose=False):
    """Detecta misconfiguracao CORS (Access-Control-Allow-Origin: *)."""
    achados = []
    EVIL_ORIGINS = [
        "https://evil.com",
        "null",
        "https://attacker.com",
        f"{base_url.rstrip('/')}.evil.com",
    ]
    for origin in EVIL_ORIGINS:
        try:
            hdrs = {"Origin": origin}
            status, resp_headers, body = _http(base_url, headers=hdrs, timeout=timeout)
            acao = resp_headers.get("access-control-allow-origin", "")
            acac = resp_headers.get("access-control-allow-credentials", "")
            if acao == "*":
                _log(f"CORS wildcard: {base_url} - ACAO: *", "ALERTA")
                achados.append({
                    "tipo": "cors", "severidade": "MEDIO",
                    "url": base_url, "detalhe": "CORS wildcard - ACAO: *",
                    "evidencia": "Access-Control-Allow-Origin: *",
                })
                break
            if origin in acao:
                sev = "CRITICO" if acac.lower() == "true" else "ALTO"
                _log(f"CORS reflected origin: {base_url} - Origem refletida, credentials={acac}", sev)
                achados.append({
                    "tipo": "cors", "severidade": sev,
                    "url": base_url,
                    "detalhe": f"CORS reflete origem arbitraria - credentials={acac}",
                    "evidencia": f"ACAO: {acao} | ACAC: {acac}",
                })
                break
            if "null" in acao:
                _log(f"CORS null origin aceito: {base_url}", "ALTO")
                achados.append({
                    "tipo": "cors", "severidade": "ALTO",
                    "url": base_url, "detalhe": "CORS aceita 'null' origin (iframe sandbox bypass)",
                    "evidencia": f"ACAO: {acao}",
                })
                break
        except Exception:
            pass
    return achados


def vuln_scan_graphql(base_url, timeout=8, verbose=False):
    """Detecta endpoint GraphQL exposto e testa introspection."""
    achados = []
    GRAPHQL_PATHS = [
        "/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql",
        "/query", "/api", "/gql", "/graphiql", "/playground",
    ]
    INTROSPECTION_QUERY = '{"query":"{__schema{types{name}}}"}'
    for path in GRAPHQL_PATHS:
        url = base_url.rstrip("/") + path
        try:
            status, headers, body = _http(
                url, method="POST", body=INTROSPECTION_QUERY.encode(),
                headers={"Content-Type": "application/json"}, timeout=timeout,
            )
            body_s = body.decode(errors="replace")
            if '"__schema"' in body_s or '"types"' in body_s:
                _log(f"GraphQL introspection exposta: {url}", "CRITICO")
                schema_preview = body_s[:200].replace("\n", " ")
                achados.append({
                    "tipo": "graphql_introspection", "severidade": "ALTO",
                    "url": url, "detalhe": "GraphQL introspection habilitada - schema vazado",
                    "evidencia": schema_preview,
                })
                break
            if '"data"' in body_s or '"errors"' in body_s:
                _log(f"Endpoint GraphQL encontrado: {url}", "ALERTA")
                achados.append({
                    "tipo": "graphql_found", "severidade": "INFO",
                    "url": url, "detalhe": "Endpoint GraphQL detectado (introspection desabilitada)",
                    "evidencia": body_s[:100],
                })
                break
            # Check GET-based introspection
            get_url = url + "?query={__schema{types{name}}}"
            st2, _, bd2 = _http(get_url, timeout=timeout)
            bd2_s = bd2.decode(errors="replace")
            if '"__schema"' in bd2_s:
                _log(f"GraphQL introspection via GET: {get_url}", "CRITICO")
                achados.append({
                    "tipo": "graphql_introspection", "severidade": "ALTO",
                    "url": get_url, "detalhe": "GraphQL introspection via GET",
                    "evidencia": bd2_s[:200],
                })
                break
        except Exception:
            pass
    return achados


def vuln_scan_cms(base_url, timeout=8, verbose=False):
    """Detecta CMS (WordPress, Joomla, Drupal, Magento) e versions expostas."""
    achados = []
    CMS_FINGERPRINTS = [
        ("WordPress", [
            ("/wp-login.php", "user_login", None),
            ("/wp-json/wp/v2/users", '"slug"', None),
            ("/readme.html", "WordPress", None),
            ("/wp-content/", None, None),
        ]),
        ("Joomla", [
            ("/administrator/", "Joomla", None),
            ("/components/", None, None),
            ("/templates/", None, None),
            ("/media/jui/", None, None),
        ]),
        ("Drupal", [
            ("/user/login", "Drupal", None),
            ("/core/CHANGELOG.txt", "Drupal", None),
            ("/sites/default/", None, None),
        ]),
        ("Magento", [
            ("/skin/frontend/", None, None),
            ("/downloader/", "Magento", None),
            ("/app/etc/", None, None),
        ]),
        ("Laravel", [
            ("/laravel-websockets", None, None),
            ("", "laravel_session", "set-cookie"),
        ]),
        ("Struts", [
            ("/.action", None, None),
            ("/.do", None, None),
        ]),
    ]
    for cms_name, probes in CMS_FINGERPRINTS:
        for path, keyword, header_name in probes:
            try:
                url = base_url.rstrip("/") + path
                status, headers, body = _http(url, timeout=timeout)
                body_s = body.decode(errors="replace").lower()
                if status in (200, 301, 302, 403):
                    matched = False
                    if keyword and keyword.lower() in body_s:
                        matched = True
                    elif header_name and keyword and keyword.lower() in headers.get(header_name, "").lower():
                        matched = True
                    elif not keyword and status in (200, 403):
                        matched = True
                    if matched:
                        _log(f"CMS detectado: {cms_name} em {base_url} [{url}]", "ALERTA")
                        # Try version detection for WordPress
                        version = ""
                        if cms_name == "WordPress":
                            import re as _re
                            m = _re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', body.decode(errors="replace"))
                            if m:
                                version = m.group(1)
                        achados.append({
                            "tipo": "cms_detected", "severidade": "MEDIO",
                            "url": url, "cms": cms_name,
                            "detalhe": f"CMS: {cms_name}" + (f" v{version}" if version else ""),
                            "evidencia": url,
                        })
                        break
            except Exception:
                pass
        if any(a.get("cms") == cms_name for a in achados):
            break  # Found this CMS, no need for more probes
    return achados


def vuln_scan_http(host, portas_abertas, timeout=8, verbose=False):
    """Orquestra todos os checks de vuln web em um host."""
    _secao("WEB VULNERABILITY SCAN")
    todos_achados = []
    base_urls = _base_urls(host, portas_abertas)

    if not base_urls:
        _log("Nenhuma porta web detectada para vuln scan", "INFO")
        return todos_achados

    for base_url in base_urls[:3]:
        _log(f"Testando: {base_url}", "INFO")

        # Descobrir parametros
        params = _encontrar_params(base_url, timeout=timeout)
        if verbose and params:
            _log(f"Parametros encontrados: {params}", "INFO")

        todos_achados += vuln_scan_waf(base_url, timeout=timeout, verbose=verbose)
        todos_achados += vuln_scan_cors(base_url, timeout=timeout, verbose=verbose)
        todos_achados += vuln_scan_cms(base_url, timeout=timeout, verbose=verbose)
        todos_achados += vuln_scan_graphql(base_url, timeout=timeout, verbose=verbose)
        todos_achados += vuln_scan_exposed_files(base_url, timeout=timeout, verbose=verbose)
        todos_achados += vuln_scan_sqli(base_url, params, timeout=timeout, verbose=verbose)
        todos_achados += vuln_scan_lfi(base_url, params, timeout=timeout, verbose=verbose)
        todos_achados += vuln_scan_xss(base_url, params, timeout=timeout, verbose=verbose)
        todos_achados += vuln_scan_ssrf(base_url, params, timeout=timeout, verbose=verbose)
        todos_achados += vuln_scan_auth_bypass(base_url, timeout=timeout, verbose=verbose)

    criticos = sum(1 for a in todos_achados if a.get("severidade") == "CRITICO")
    altos = sum(1 for a in todos_achados if a.get("severidade") == "ALTO")
    _log(f"Vuln scan concluido: {len(todos_achados)} finding(s) | {criticos} CRITICO | {altos} ALTO", "OK")
    return todos_achados


# ──────────────────────────────────────────────────────────────────
# CLI / main
# ──────────────────────────────────────────────────────────────────

_SCAN_HELP = """\033[92mOpcoes de Scan:\033[0m
  \033[1m-t / --target\033[0m      Alvo: hostname, IP ou CIDR (ex: 192.168.1.0/24)
  \033[1m--targets-file\033[0m     Arquivo com alvos (um por linha)
  \033[1m-p / --ports\033[0m       Portas (ex: 22,80,443 ou 1-1024 ou top100)
  \033[1m--rate\033[0m N            Pacotes por segundo (padrao: 1000)
  \033[1m--timeout\033[0m N         Timeout por porta em segundos (padrao: 1.0)
  \033[1m--threads\033[0m N         Threads paralelas (padrao: 10)
  \033[1m--fast\033[0m             Modo rapido - top 100 portas, timeout reduzido

\033[92mDeteccao:\033[0m
  \033[1m--banner\033[0m           Captura banner dos servicos abertos
  \033[1m--udp\033[0m              Scan UDP (requer root)
  \033[1m--os-detect\033[0m        Deteccao de OS via TTL e fingerprint
  \033[1m--http-fp\033[0m          Fingerprint HTTP em portas web detectadas
  \033[1m--ssl\033[0m              Analise de certificado SSL/TLS
  \033[1m--passive\033[0m          Modo passivo - sem SYN raw, apenas connect()
  \033[1m--exclude-cdn\033[0m      Pular IPs de CDN (Cloudflare, Akamai, Fastly)
  \033[1m-T N\033[0m               Timing: 0=paranoid 1=sneaky 2=polite 3=normal 4=agg 5=insane
  \033[1m--vuln\033[0m             Web vuln scan: WAF, CORS, CMS, GraphQL, SQLi, LFI, XSS, SSRF, auth bypass

\033[92mRede e Output:\033[0m
  \033[1m--ipv6\033[0m             Scan IPv6
  \033[1m--proxy\033[0m            Proxy HTTP/HTTPS (ex: http://127.0.0.1:8080)
  \033[1m--output\033[0m           Salvar resultados em JSON
  \033[1m--nmap-xml\033[0m         Importar/exportar formato XML do nmap
  \033[1m--html-output\033[0m      Salvar relatorio em HTML
  \033[1m--jsonl\033[0m            Salvar em formato JSONL (uma linha por host)
  \033[1m--verbose\033[0m          Saida detalhada
  \033[1m--no-banner\033[0m        Suprimir banner

\033[92mExemplos:\033[0m
  python ghost-scan.py -t 192.168.1.1 --banner --http-fp
  python ghost-scan.py -t 192.168.1.0/24 -p 22,80,443,3389 --threads 50
  python ghost-scan.py -t exemplo.com -p 1-65535 --fast --output resultado.json
  python ghost-scan.py --targets-file alvos.txt -p top100 --ssl --os-detect
  python ghost-scan.py -t 10.0.0.0/8 --rate 5000 -T 4 --jsonl saida.jsonl
  python ghost-scan.py -t exemplo.com --vuln --http-fp --banner

\033[2mUse: python ghost-scan.py --help  para ver todos os flags disponiveis\033[0m
"""


def main():
    parser = argparse.ArgumentParser(
        prog="ghost-scan",
        description=f"Ghost-Scan v{VERSAO} - Async Port Scanner  |  By Gh0st-Bx1",
        epilog=_SCAN_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("-t", "--target", default=None,
                        help="Alvo: hostname, IP ou CIDR (ex: 192.168.1.0/24)")
    parser.add_argument("--targets-file", metavar="FILE",
                        help="Arquivo com alvos (um por linha)")
    parser.add_argument("-p", "--ports",
                        help="Portas: '80,443', '1-1024', 'top100', 'full' (padrao: top100)")
    parser.add_argument("--rate", type=int, default=1000,
                        help="Max conexoes simultaneas (padrao: 1000)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Timeout por porta em segundos (padrao: 1.0)")
    parser.add_argument("--banner", action="store_true",
                        help="Capturar banners de servicos")
    parser.add_argument("--udp", action="store_true",
                        help="Escanear portas UDP comuns (DNS/SNMP/NTP/TFTP)")
    parser.add_argument("--os-detect", action="store_true",
                        help="Estimativa de SO via TTL/ping")
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="Salvar resultados em JSON")
    parser.add_argument("--nmap-xml", metavar="FILE",
                        help="Exportar em formato Nmap XML")
    parser.add_argument("--verbose", action="store_true",
                        help="Saida detalhada")
    parser.add_argument("--http-fp", action="store_true", dest="http_fp",
                        help="HTTP fingerprint: titulo, Server, tecnologias nas portas web")
    parser.add_argument("--ssl", action="store_true",
                        help="Analise SSL/TLS: cipher, protocolo, cert, fraquezas (portas 443/8443)")
    parser.add_argument("--ipv6", action="store_true",
                        help="Resolver registro AAAA (IPv6) do alvo alem do IPv4")
    parser.add_argument("--fast", action="store_true",
                        help="Modo rapido: timeout 0.3s, rate 2000, top100 portas, sem banner")
    parser.add_argument("--threads", type=int, default=10,
                        help="Threads para scan de multiplos hosts (padrao: 10)")
    parser.add_argument("--proxy", metavar="URL",
                        help="Proxy HTTP/HTTPS para requisicoes web (ex: http://127.0.0.1:8080)")
    parser.add_argument("--html-output", metavar="FILE",
                        help="Salvar relatorio HTML")
    parser.add_argument("--no-banner", action="store_true",
                        help="Sem banner inicial")
    parser.add_argument("-T", metavar="N", type=int, choices=range(6), default=None,
                        dest="timing",
                        help="Template de timing: 0=paranoid 1=sneaky 2=polite 3=normal 4=agressivo 5=insano")
    parser.add_argument("--passive", action="store_true",
                        help="Enriquecimento passivo via Shodan InternetDB (sem varredura ativa)")
    parser.add_argument("--exclude-cdn", action="store_true", dest="exclude_cdn",
                        help="Excluir IPs de CDN conhecidos (Cloudflare, Akamai, Fastly, etc.)")
    parser.add_argument("--jsonl", metavar="FILE",
                        help="Saida JSON Lines (streaming, um resultado por linha)")
    parser.add_argument("--vuln", action="store_true",
                        help="Web vuln scan: SQLi, LFI, XSS, SSRF, auth bypass, arquivos expostos")

    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    if not args.target and not args.targets_file:
        _log("Use --target ou --targets-file", "ERRO")
        parser.print_help()
        sys.exit(1)

    global _PROXY
    if args.proxy:
        _PROXY = args.proxy
        _log(f"Proxy: {_PROXY}", "INFO")

    # Timing templates T0-T5
    _TIMING = {
        0: (5.0, 50,  "paranoid:  timeout=5.0s rate=50"),
        1: (3.0, 150, "sneaky:    timeout=3.0s rate=150"),
        2: (2.0, 300, "polite:    timeout=2.0s rate=300"),
        3: (1.0, 1000,"normal:    timeout=1.0s rate=1000"),
        4: (0.5, 2000,"agressivo: timeout=0.5s rate=2000"),
        5: (0.2, 5000,"insano:    timeout=0.2s rate=5000"),
    }
    if args.timing is not None:
        t, r, lbl = _TIMING[args.timing]
        args.timeout = t; args.rate = r
        _log(f"Timing T{args.timing} ({lbl})", "INFO")

    # Fast mode overrides
    if args.fast:
        args.timeout = 0.3
        args.rate = 2000
        args.banner = False
        _log("Modo rapido: timeout=0.3s rate=2000 banner=off", "INFO")

    # Parsear portas
    portas = PORTAS_TOP_100
    if args.ports:
        p = args.ports.lower()
        if p == "top100":
            portas = PORTAS_TOP_100
        elif p == "full":
            portas = PORTAS_FULL
            _log("Modo full: 65535 portas. Pode ser lento.", "ALERTA")
        elif "-" in p and "," not in p:
            try:
                inicio, fim = p.split("-")
                portas = list(range(int(inicio), int(fim) + 1))
            except ValueError:
                _log("Formato de range invalido. Use: 1-1024", "ERRO")
                sys.exit(1)
        else:
            try:
                portas = [int(x.strip()) for x in p.split(",") if x.strip()]
            except ValueError:
                _log("Formato de portas invalido. Use: 80,443,8080", "ERRO")
                sys.exit(1)

    # CDN IP ranges (CIDRs of major CDN ASNs - static known ranges)
    _CDN_CIDRS = [
        # Cloudflare
        "103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","104.16.0.0/13",
        "104.24.0.0/14","108.162.192.0/18","131.0.72.0/22","141.101.64.0/18",
        "162.158.0.0/15","172.64.0.0/13","173.245.48.0/20","188.114.96.0/20",
        "190.93.240.0/20","197.234.240.0/22","198.41.128.0/17",
        # Fastly
        "23.235.32.0/20","23.253.0.0/18","199.27.72.0/21","199.232.0.0/16",
        "151.101.0.0/16",
        # Akamai (sample ranges)
        "23.32.0.0/11","23.64.0.0/14","104.64.0.0/10",
    ]

    def _is_cdn_ip(ip):
        try:
            addr = ipaddress.ip_address(ip)
            for cidr in _CDN_CIDRS:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
        except Exception:
            pass
        return False

    # Coletar alvos
    alvos_raw = []
    if args.target:
        if args.target == "-":
            for line in sys.stdin:
                line = line.strip()
                if line and not line.startswith("#"):
                    alvos_raw.append(line)
        else:
            alvos_raw.append(args.target)
    if args.targets_file:
        try:
            with open(args.targets_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        alvos_raw.append(line)
        except Exception as e:
            _log(f"Erro ao ler targets-file: {e}", "ERRO")
            sys.exit(1)

    # Expandir CIDR
    hosts = []
    for alvo in alvos_raw:
        hosts.extend(expandir_cidr(alvo))

    hosts = list(dict.fromkeys(hosts))  # deduplica mantendo ordem

    # CDN exclusion
    if getattr(args, "exclude_cdn", False):
        antes = len(hosts)
        hosts = [h for h in hosts if not _is_cdn_ip(h)]
        excl = antes - len(hosts)
        if excl:
            _log(f"CDN exclusion: {excl} IP(s) removido(s)", "INFO")

    if not hosts:
        _log("Nenhum host para escanear", "ERRO")
        sys.exit(1)

    _log(f"Alvos: {len(hosts)} host(s) | Portas: {len(portas)} | Rate: {args.rate}", "INFO")
    if args.banner:
        _log("Banner grabbing habilitado", "INFO")
    if args.udp:
        _log("UDP scan habilitado", "INFO")

    # Passive mode: Shodan InternetDB only, no active scan
    if getattr(args, "passive", False):
        _log("Modo passivo: Shodan InternetDB (sem varredura ativa)", "INFO")
        todos_resultados = []
        for host in hosts:
            try:
                ip = socket.gethostbyname(host)
            except Exception:
                ip = host
            req = urllib.request.Request(
                f"https://internetdb.shodan.io/{ip}",
                headers={"User-Agent": "GhostScan/2.0"}
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
                ports = [{"porta": p, "servico": SERVICOS.get(p, "unknown")} for p in data.get("ports", [])]
                cves = list(data.get("vulns", []))
                r = {"ip": ip, "hostname": host, "portas_tcp": ports, "cves": cves,
                     "hostnames": data.get("hostnames", []), "tags": data.get("tags", []),
                     "cpes": data.get("cpes", []), "fonte": "shodan-internetdb"}
                todos_resultados.append(r)
                _log(f"{ip}: {len(ports)} ports, {len(cves)} CVEs", "OK" if ports else "INFO")
                if cves:
                    _log(f"CVEs: {', '.join(cves[:5])}", "ALERTA")
            except Exception as e:
                _log(f"{host}: {e}", "ERRO")
    else:
        todos_resultados = []
        if len(hosts) == 1:
            r = scan_host(hosts[0], portas, args)
            if r:
                todos_resultados.append(r)
        else:
            _log(f"Scan em massa: {len(hosts)} hosts, {args.threads} threads", "INFO")
            with ThreadPoolExecutor(max_workers=args.threads) as pool:
                futures = {pool.submit(scan_host, h, portas, args): h for h in hosts}
                from concurrent.futures import as_completed
                for fut in as_completed(futures):
                    r = fut.result()
                    if r:
                        todos_resultados.append(r)

    # Resumo
    _secao("RESUMO FINAL")
    total_abertos = sum(len(r.get("portas_tcp", [])) for r in todos_resultados)
    total_udp = sum(len(r.get("portas_udp", [])) for r in todos_resultados)
    total_cves = sum(len(r.get("cves", [])) for r in todos_resultados)
    _log(f"Hosts escaneados: {len(todos_resultados)}", "INFO")
    _log(f"Portas TCP abertas: {total_abertos}", "OK" if total_abertos else "INFO")
    _log(f"Servicos UDP responderam: {total_udp}", "OK" if total_udp else "INFO")
    if total_cves:
        _log(f"CVEs correlacionadas: {total_cves}", "ALERTA")

    # JSON output
    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump({"ferramenta": "ghost-scan", "versao": VERSAO,
                           "resultados": todos_resultados}, f, indent=2, default=str)
            _log(f"Resultados salvos: {args.output}", "OK")
        except Exception as e:
            _log(f"Erro ao salvar JSON: {e}", "ERRO")

    # Nmap XML
    if args.nmap_xml and todos_resultados:
        try:
            r0 = todos_resultados[0]
            exportar_nmap_xml(r0["ip"], r0.get("portas_tcp", []),
                              r0.get("portas_udp", []), r0.get("os", {}),
                              args.nmap_xml)
        except Exception as e:
            _log(f"Erro ao exportar Nmap XML: {e}", "ERRO")

    # JSONL streaming output
    if getattr(args, "jsonl", None) and todos_resultados:
        try:
            with open(args.jsonl, "w") as f:
                for r in todos_resultados:
                    f.write(json.dumps(r, default=str) + "\n")
            _log(f"JSONL salvo: {args.jsonl}", "OK")
        except Exception as e:
            _log(f"Erro ao salvar JSONL: {e}", "ERRO")

    if getattr(args, "html_output", None) and todos_resultados:
        try:
            gerar_html(todos_resultados, args.html_output)
        except Exception as e:
            _log(f"Erro ao gerar HTML: {e}", "ERRO")

    print(f"\n  {C['G']}{C['N']}[+] Ghost-Scan finalizado.{C['X']}\n")


if __name__ == "__main__":
    main()
