from scapy.all import PcapReader, TCP, UDP, IP, IPv6, ICMP, ARP
import csv

# Input / output paths
pcap_file = r"C:\Users\dnsha\Downloads\7 (1).pcap"
csv_file = r"C:\Users\dnsha\Downloads\7_protocols_final_1.csv"

# Known TCP services
tcp_services = {
    20: "FTP-DATA", 21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP", 465: "SMTPS", 587: "SMTP Submission",
    110: "POP3", 995: "POP3S",
    143: "IMAP", 993: "IMAPS",
    80: "HTTP", 443: "HTTPS",
    139: "NBTSession", 445: "SMB"
}

# Known UDP services
udp_services = {
    53: "DNS",
    67: "DHCP Server", 68: "DHCP Client",
    123: "NTP",
    137: "NBNS", 138: "NBDS",
    161: "SNMP", 162: "SNMP Trap",
    546: "DHCPv6 Client", 547: "DHCPv6 Server",
    5353: "mDNS", 5355: "LLMNR"
}

# Open CSV file
with open(csv_file, mode="w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "Packet_ID", "Summary", "Protocol", "Src_IP", "Dst_IP", "Src_Port", "Dst_Port", "Size"
    ])

    # Efficiently read packets
    with PcapReader(pcap_file) as pcap:
        for i, pkt in enumerate(pcap, start=1):
            proto = "Other"
            src_ip = dst_ip = ""
            src_port = dst_port = ""

            # TCP
            if TCP in pkt:
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                proto = tcp_services.get(sport, tcp_services.get(dport, "TCP"))
                src_port, dst_port = sport, dport

            # UDP
            elif UDP in pkt:
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
                proto = udp_services.get(sport, udp_services.get(dport, "UDP"))
                src_port, dst_port = sport, dport

            # ICMP / ICMPv6
            elif ICMP in pkt or pkt.haslayer("ICMPv6"):
                proto = "ICMP"

            # ARP
            elif ARP in pkt:
                proto = "ARP"

            # Generic IP/IPv6
            elif IP in pkt or IPv6 in pkt:
                proto = "IP/IPv6"

            # IP addresses
            if IP in pkt:
                src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst

            # Packet size in bytes
            size = len(pkt)

            # Packet summary string
            summary = pkt.summary()

            # Write one row
            writer.writerow([i, summary, proto, src_ip, dst_ip, src_port, dst_port, size])

            if i % 100000 == 0:
                print(f"Processed {i} packets...")

print(f"[Done] CSV file created: {csv_file}")
