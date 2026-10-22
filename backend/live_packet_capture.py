from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ARP, ICMP, get_working_ifaces

def show_interfaces():
    print("\nAvailable network interfaces:\n")
    for index, iface in enumerate(get_working_ifaces(), start=1):
        print(f"{index}. {iface.name}")
        print(f"   Description: {iface.description}")
        print(f"   Network: {iface.network_name}")

def process_packet(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")

    if ARP in packet:
        protocol = "ARP"
        source = packet[ARP].psrc
        destination = packet[ARP].pdst

    elif IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "IP"

    elif IPv6 in packet:
        source = packet[IPv6].src
        destination = packet[IPv6].dst
        protocol = "IPv6"

    else:
        return

    print(
        f"[{timestamp}] "
        f"{protocol:<6} "
        f"{source} -> {destination} "
        f"Length={len(packet)}"
    )

def main():
    show_interfaces()

    print("\nStarting live packet capture...")
    print("Capturing 20 packets. Press Ctrl+C to stop.\n")

    try:
        sniff(
            prn=process_packet,
            count=20,
            store=False
        )
    except PermissionError:
        print("Permission denied. Try running VS Code as Administrator.")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as error:
        print(f"\nCapture error: {error}")

if __name__ == "__main__":
    main()
