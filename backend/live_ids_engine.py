from collections import Counter
from datetime import datetime, timezone

from scapy.all import ARP, IP, TCP


class LiveIDSEngine:
    def __init__(self, syn_threshold=100):
        self.syn_threshold = syn_threshold
        self.arp_table = {}

    def analyze(self, packets):
        alerts = []
        syn_sources = Counter()

        for packet in packets:

            if ARP in packet:
                arp = packet[ARP]

                if arp.op == 2:
                    ip_address = arp.psrc
                    mac_address = arp.hwsrc.lower()

                    previous_mac = self.arp_table.get(ip_address)

                    if previous_mac and previous_mac != mac_address:
                        alerts.append(
                            self._make_alert(
                                attack_type="ARP_SPOOFING_SUSPECTED",
                                severity="HIGH",
                                source_ip=ip_address,
                                evidence=(
                                    f"IP {ip_address} changed MAC "
                                    f"from {previous_mac} to {mac_address}"
                                ),
                            )
                        )

                    self.arp_table[ip_address] = mac_address

            if IP in packet and TCP in packet:
                flags = int(packet[TCP].flags)

                syn_set = bool(flags & 0x02)
                ack_set = bool(flags & 0x10)

                if syn_set and not ack_set:
                    syn_sources[packet[IP].src] += 1

        for source_ip, count in syn_sources.items():
            if count >= self.syn_threshold:
                alerts.append(
                    self._make_alert(
                        attack_type="SYN_FLOOD_SUSPECTED",
                        severity="HIGH",
                        source_ip=source_ip,
                        evidence=(
                            f"{count} SYN packets without ACK "
                            f"observed in one capture window"
                        ),
                    )
                )

        return alerts

    @staticmethod
    def _make_alert(attack_type, severity, source_ip, evidence):
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detection_method": "RULE_BASED",
            "attack_type": attack_type,
            "severity": severity,
            "source_ip": source_ip,
            "evidence": evidence,
        }
