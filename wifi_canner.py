import subprocess
from scapy.all import *
import threading

# Passive scan using Scapy (monitor mode required)
def passive_scan():
    print("\n[🔍] Passive scan (Scapy) started...\n")
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
            bssid = pkt[Dot11].addr2
            print(f"[Scapy] SSID: {ssid}, BSSID: {bssid}")

    sniff(iface="wlan0mon", prn=packet_handler, timeout=30, store=False)

# Active scan using iwlist
def active_scan():
    print("[📡] Active scan (iwlist) started...\n")
    try:
        result = subprocess.check_output(
            ["sudo", "iwlist", "wlan0", "scan"], stderr=subprocess.STDOUT
        ).decode()
        lines = result.split("\n")
        for line in lines:
            if "ESSID" in line or "Quality" in line or "Encryption" in line:
                print(f"[iwlist] {line.strip()}")
    except subprocess.CalledProcessError as e:
        print("[❌] Failed to scan using iwlist.")
        print(e.output.decode())

# Run both scanners (concurrently or sequentially)
if __name__ == "__main__":
    # Option 1: Run both at once (in parallel)
    t1 = threading.Thread(target=active_scan)
    t2 = threading.Thread(target=passive_scan)

    t1.start()
    t2.start()

    t1.join()
    t2.join()

    print("\n[✅] Wi-Fi scan complete.")
