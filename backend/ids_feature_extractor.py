from collections import Counter
from statistics import mean, pstdev

from scapy.all import (
    IP, IPv6, TCP, UDP, ARP, ICMP,
    DNS, DHCP, Ether
)


def extract_packet_features(packets):
    """
    Extract observable packet-level and statistical features.

    These are intermediate measurements, not yet a validated
    CICIoMT2024-compatible 45-feature vector.
    """

    protocol_counts = Counter()
    tcp_flags = Counter()
    header_lengths = []
    packet_sizes = []
    timestamps = []

    flag_masks = {
        "fin_flag_number": 0x01,
        "syn_flag_number": 0x02,
        "rst_flag_number": 0x04,
        "psh_flag_number": 0x08,
        "ack_flag_number": 0x10,
        "ece_flag_number": 0x40,
        "cwr_flag_number": 0x80,
    }

    for packet in packets:
        packet_sizes.append(len(bytes(packet)))
        timestamps.append(float(packet.time))

        if IP in packet:
            header_lengths.append(
                IP(bytes(packet[IP])).ihl * 4
            )
        elif IPv6 in packet:
            header_lengths.append(40)

        if TCP in packet:
            protocol_counts["TCP"] += 1
            flags = int(packet[TCP].flags)

            for name, mask in flag_masks.items():
                if flags & mask:
                    tcp_flags[name] += 1

        if UDP in packet:
            protocol_counts["UDP"] += 1

        if ARP in packet:
            protocol_counts["ARP"] += 1

        if ICMP in packet:
            protocol_counts["ICMP"] += 1

        if DNS in packet:
            protocol_counts["DNS"] += 1

        if DHCP in packet:
            protocol_counts["DHCP"] += 1

        if IP in packet or IPv6 in packet:
            protocol_counts["IPv"] += 1

        if Ether in packet:
            protocol_counts["Ethernet"] += 1

    ordered_times = sorted(timestamps)

    duration = (
        ordered_times[-1] - ordered_times[0]
        if len(ordered_times) >= 2
        else 0.0
    )

    interarrival_times = [
        ordered_times[i] - ordered_times[i - 1]
        for i in range(1, len(ordered_times))
    ]

    statistics = {
        "Duration": duration,
        "Rate": len(packets) / duration if duration > 0 else 0.0,
        "Min": min(packet_sizes) if packet_sizes else 0,
        "Max": max(packet_sizes) if packet_sizes else 0,
        "AVG": mean(packet_sizes) if packet_sizes else 0.0,
        "Std": pstdev(packet_sizes) if packet_sizes else 0.0,
        "IAT": mean(interarrival_times) if interarrival_times else 0.0,
        "Tot sum": sum(packet_sizes),
        "Tot size": sum(packet_sizes),
    }

    return {
        "packet_count": len(packets),
        "packet_sizes": packet_sizes,
        "header_lengths": header_lengths,
        "protocol_counts": dict(protocol_counts),
        "tcp_flags": dict(tcp_flags),
        "statistics": statistics,
    }
