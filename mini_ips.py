#!/usr/bin/env python3
# mini_ips.py
# Lightweight IDS/IPS: detects SYN port scans and ICMP flood, blocks IPs temporarily with iptables.

from scapy.all import sniff, IP, TCP, ICMP, Ether
from collections import defaultdict
import threading, time, subprocess, os, signal, sys, json

# ---------- CONFIG ----------
PORT_SCAN_THRESHOLD = 5    # nb de ports différents
PORT_SCAN_WINDOW = 5     # secondes
ICMP_THRESHOLD = 20         # nb paquets ICMP
ICMP_WINDOW = 10
BLOCK_DURATION = 300        # secondes (5 minutes) -> durée du blocage auto
WHITELIST = set([ "127.0.0.1"])  # <-- METS ICI l'IP de ton smartphone et localhost
LOG_ALERTS = "alerts.log"
LOG_BLOCKED = "blocked.log"
# ---------------------------

port_scan_tracker = defaultdict(list)
icmp_tracker = defaultdict(list)
blocked_ips = {}  # ip -> unblock_time

def run_cmd(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True)
    except Exception as e:
        print("Erreur run_cmd:", e)
        return None

def block_ip(ip):
    if ip in WHITELIST:
        return
    if ip in blocked_ips:
        return
    # Add iptables rule
    cmd = f"iptables -I INPUT -s {ip} -j DROP"
    run_cmd(cmd)
    unblock_at = time.time() + BLOCK_DURATION
    blocked_ips[ip] = unblock_at
    now = time.ctime()
    entry = {"time": now, "action": "block", "ip": ip, "duration_s": BLOCK_DURATION}
    with open(LOG_BLOCKED, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[ACTION] IP {ip} blocked until {time.ctime(unblock_at)}")
    # schedule unblock
    t = threading.Timer(BLOCK_DURATION, unblock_ip, args=(ip,))
    t.daemon = True
    t.start()

def unblock_ip(ip):
    # remove iptables rule (attempt)
    cmd = f"iptables -D INPUT -s {ip} -j DROP"
    run_cmd(cmd)
    if ip in blocked_ips:
        del blocked_ips[ip]
    now = time.ctime()
    entry = {"time": now, "action": "unblock", "ip": ip}
    with open(LOG_BLOCKED, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[ACTION] IP {ip} unblocked at {now}")

def alert(msg, details=None):
    ts = time.ctime()
    line = {"time": ts, "msg": msg}
    if details:
        line["details"] = details
    with open(LOG_ALERTS, "a") as f:
        f.write(json.dumps(line) + "\n")
    print(f"[ALERTE] {msg}")

def detect_packet(packet):
    try:
        if not packet.haslayer(IP):
            return
        src_ip = packet[IP].src
        # optional: get mac if available
        src_mac = packet[Ether].src if packet.haslayer(Ether) else None

        if src_ip in WHITELIST or src_ip in blocked_ips:
            return

        # TCP SYN scanning detection
        if packet.haslayer(TCP):
            flags = int(packet[TCP].flags)
            if flags & 0x02:  # SYN
                dport = int(packet[TCP].dport)
                now = time.time()
                port_scan_tracker[src_ip].append((dport, now))
                # keep only events in window
                port_scan_tracker[src_ip] = [(p,t) for (p,t) in port_scan_tracker[src_ip] if now - t < PORT_SCAN_WINDOW]
                ports_seen = {p for (p,_) in port_scan_tracker[src_ip]}
                if len(ports_seen) >= PORT_SCAN_THRESHOLD:
                    details = {"src_ip": src_ip, "ports_count": len(ports_seen), "ports": list(ports_seen)}
                    alert(f"Port scan detected from {src_ip}", details)
                    block_ip(src_ip)

        # ICMP flood detection
        if packet.haslayer(ICMP):
            now = time.time()
            icmp_tracker[src_ip].append(now)
            icmp_tracker[src_ip] = [t for t in icmp_tracker[src_ip] if now - t < ICMP_WINDOW]
            if len(icmp_tracker[src_ip]) >= ICMP_THRESHOLD:
                details = {"src_ip": src_ip, "count": len(icmp_tracker[src_ip])}
                alert(f"ICMP flood detected from {src_ip}", details)
                block_ip(src_ip)
    except Exception as e:
        print("error in detect_packet:", e)

def cleanup_on_exit(signum, frame):
    print("Stopping... cleaning iptables for blocked IPs")
    for ip in list(blocked_ips.keys()):
        try:
            run_cmd(f"iptables -D INPUT -s {ip} -j DROP")
            print("Removed block for", ip)
        except Exception:
            pass
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup_on_exit)
    signal.signal(signal.SIGTERM, cleanup_on_exit)
    print("IDS/IPS started (listening). CTRL+C to stop.")
    # sniff on all interfaces (promiscuous)
    sniff(prn=detect_packet, store=0)
