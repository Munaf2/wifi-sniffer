# -----------------------------
# Wi-Fi / Network Packet Sniffer
# -----------------------------
# Description:
#   This script uses Scapy to capture network packets from your machine.
#   It extracts useful information (source IP, destination IP, protocol)
#   and stores it in a CSV file for later analysis.
#
#   - Run this on your own computer / home network only!
#   - Packet sniffing usually requires root/administrator privileges.
#   - On Linux, you’ll likely need to run: sudo python3 sniffer.py
# -----------------------------

from scapy.all import sniff, IP, TCP, UDP
import csv

# Step 1 
# Open (or create) a CSV file where we’ll save packet data.
# We add column headers the first time we run the script.
with open("packets.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Source IP", "Destination IP", "Protocol"])


# Step 2 
def process_packet(packet):
    """
    This function runs every time we capture a packet.
    We check if the packet has an IP layer.
    If yes, we grab the source, destination, and protocol,
    then save it to our CSV file.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Protocol number (6=TCP, 17=UDP, etc.)
        proto = packet[IP].proto
        if proto == 6:
            proto_name = "TCP"
        elif proto == 17:
            proto_name = "UDP"
        else:
            proto_name = str(proto)

        print(f"{src_ip} → {dst_ip} | {proto_name}")

        # Save the info to our CSV
        with open("packets.csv", "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([src_ip, dst_ip, proto_name])


# Step 3 
print("Starting packet capture... (press Ctrl+C to stop)")

# "iface" = network interface to listen on.
#   - On Linux: usually wlan0 (Wi-Fi) or eth0 (Ethernet).
#   - Check your interface with: ifconfig  OR  ip link
#
# "prn" = the function to call for each packet
# "store=0" = don’t keep packets in memory (saves RAM)
sniff(iface="wlan0", prn=process_packet, store=0)
