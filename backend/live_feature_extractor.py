from collections import Counter
from statistics import mean, pstdev
from datetime import datetime
from scapy.all import sniff, TCP, UDP, ARP, ICMP, IP

INTERFACE = "Wi-Fi"
WINDOW_SECONDS = 10


def extract_live_statistics(packets):
    sizes = [len(packet) for packet in packets]
    timestamps = [float(packet.time) for packet in packets]

    protocols = Counter()
    tcp_flags = Counter()

    for packet in packets:
        if ARP in packet:
            protocols["ARP"] += 1
        elif TCP in packet:
            protocols["TCP"] += 1

            flags = int(packet[TCP].flags)

            for name, mask in {
                "SYN": 0x02,
                "ACK": 0x10,
                "FIN": 0x01,
                "RST": 0x04,
                "PSH": 0x08,
            }.items():
                if flags & mask:
                    tcp_flags[name] += 1

        elif UDP in packet:
            protocols["UDP"] += 1
        elif ICMP in packet:
            protocols["ICMP"] += 1
        elif IP in packet:
            protocols["OTHER_IP"] += 1

    intervals = [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
    ]

    return {
        "timestamp": datetime.now().isoformat(),
        "packet_count": len(packets),
        "packet_rate": len(packets) / WINDOW_SECONDS,
        "total_bytes": sum(sizes),
        "min_packet_size": min(sizes) if sizes else 0,
        "max_packet_size": max(sizes) if sizes else 0,
        "avg_packet_size": mean(sizes) if sizes else 0,
        "std_packet_size": pstdev(sizes) if sizes else 0,
        "avg_interarrival_seconds": mean(intervals) if intervals else 0,
        "protocols": dict(protocols),
        "tcp_flags": dict(tcp_flags),
    }


def main():
    print("\nSECUREGUARD LIVE FEATURE COLLECTOR")
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

            stats = extract_live_statistics(packets)

            print("\n========== LIVE FEATURES ==========")

            for key, value in stats.items():
                print(f"{key}: {value}")

            print("===================================\n")

    except KeyboardInterrupt:
        print("\nLive collection stopped.")


if __name__ == "__main__":
    main()
