import subprocess
import os

def start_monitor_mode(interface="wlan0"):
    subprocess.call(["airmon-ng", "start", interface])

def scan_networks(mon_interface="wlan0mon"):
    print("[*] Scanning for networks (Press Ctrl+C to stop)...")
    subprocess.call(["airodump-ng", mon_interface])

def capture_handshake(mon_interface="wlan0mon", bssid="", channel="", output="handshake"):
    subprocess.call(["airodump-ng", "-c", channel, "--bssid", bssid, "-w", output, mon_interface])

def stop_monitor_mode(interface="wlan0mon"):
    subprocess.call(["airmon-ng", "stop", interface])

# Example Usage
if __name__ == "__main__":
    start_monitor_mode("wlan0")
    # scan_networks()  # You manually copy BSSID and Channel
    # capture_handshake(mon_interface="wlan0mon", bssid="XX:XX:XX:XX:XX:XX", channel="6")
    # stop_monitor_mode("wlan0mon")
 