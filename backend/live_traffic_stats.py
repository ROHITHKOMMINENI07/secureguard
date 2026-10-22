from collections import Counter
from statistics import mean, pstdev
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP

INTERFACE = "Wi-Fi"
WINDOW_SECONDS = 10

def analyze_window(packets):
    sizes = [len(packet) for packet in packets]
    protocols = Counter()
    flags = Counter()

    for packet in packets:
        if ARP in packet:
            protocols["ARP"] += 1
        elif TCP in packet:
            protocols["TCP"] += 1
            for flag in ["S", "A", "F", "R", "P"]:
                if flag in str(packet[TCP].flags):
                    flags[flag] += 1
        elif UDP in packet:
            protocols["UDP"] += 1
        elif ICMP in packet:
            protocols["ICMP"] += 1
        elif IP in packet:
            protocols["Other IP"] += 1

    print("\n========== LIVE TRAFFIC STATISTICS ==========")
    print("Packets:", len(packets))
    print("Protocols:", dict(protocols))
    print("TCP flags:", dict(flags))

    if sizes:
        print("Total bytes:", sum(sizes))
        print("Minimum size:", min(sizes))
        print("Maximum size:", max(sizes))
        print("Average size:", round(mean(sizes), 2))
        print("Standard deviation:", round(pstdev(sizes), 2))
        print("Packet rate:", round(len(sizes) / WINDOW_SECONDS, 2), "packets/sec")

    print("=============================================\n")

def main():
    print("SECUREGUARD LIVE TRAFFIC MONITOR")
    print("Interface:", INTERFACE)
    print("Window:", WINDOW_SECONDS, "seconds")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            packets = sniff(
                iface=INTERFACE,
                timeout=WINDOW_SECONDS,
                store=True
            )
            analyze_window(packets)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

if __name__ == "__main__":
    main()
