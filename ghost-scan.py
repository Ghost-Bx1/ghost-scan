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

VERSAO = "1.0.0"

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
        f"{D}--target --ports --rate --banner --udp{X}",
        f"{D}--os-detect --cidr --nmap-xml --json{X}",
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

    elapsed = time.time() - t_inicio
    _log(f"Scan concluido em {elapsed:.1f}s", "INFO")

    return {
        "host": host, "ip": ip,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "portas_tcp": portas_abertas,
        "portas_udp": udp_resultados,
        "os": os_info,
        "cves": cves,
        "duracao_s": round(elapsed, 2),
    }


# ──────────────────────────────────────────────────────────────────
# CLI / main
# ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="ghost-scan",
        description=f"Ghost-Scan v{VERSAO} - Async Port Scanner | By Gh0st-Bx1",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument("-t", "--target", required=True,
                        help="Alvo: hostname, IP ou CIDR (ex: 192.168.1.0/24)")
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

    args = parser.parse_args()

    print(BANNER)

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

    # Expandir CIDR
    hosts = expandir_cidr(args.target)
    if not hosts:
        _log("Nenhum host para escanear", "ERRO")
        sys.exit(1)

    _log(f"Alvos: {len(hosts)} host(s) | Portas: {len(portas)} | Rate: {args.rate}", "INFO")
    if args.banner:
        _log("Banner grabbing habilitado", "INFO")
    if args.udp:
        _log("UDP scan habilitado", "INFO")

    todos_resultados = []
    for host in hosts:
        r = scan_host(host, portas, args)
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

    print(f"\n  {C['G']}{C['N']}[+] Ghost-Scan finalizado.{C['X']}\n")


if __name__ == "__main__":
    main()
