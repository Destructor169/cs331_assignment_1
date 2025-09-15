# ---------------------------
# client.py
# ---------------------------
import struct
import time
import socket
from scapy.all import PcapReader, DNS, Packet, hexdump

MAGIC = b"NP"
valid_ids = [ 
22638,
44981,
143275,
145830,
22637,
208280,
305371,
308169,
351846,
399085,
470497,
483841,
486344,
558711,
617350,
619123,
640341,
640342,
750469,
753561,
763225,
765395,
774396
]  # Example valid IDs

def build_packet(hh, mm, ss, pkt_id, inner_bytes):
    """Build custom packet with 6-byte header + 4-byte length + payload"""
    header = struct.pack("!BBB", hh, mm, ss) + pkt_id.to_bytes(3, byteorder='big')
    inner_len = struct.pack("!I", len(inner_bytes))
    return MAGIC + header + inner_len + inner_bytes


def parse_response(resp):
    """Extract inner_len and DNS bytes from server response"""
    if len(resp) < 6:
        raise ValueError("Response too short")
    inner_len = struct.unpack("!I", resp[2:6])[0]
    dns_bytes = resp[6:6+inner_len]
    return dns_bytes


def main():
    HOST = "127.0.0.1"
    PORT = 9000
    report = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        #print(f"[Client] Connecting to {HOST}:{PORT}...")
        s.connect((HOST, PORT))
        #print("[Client] Connected.")
        count = 0
        pcap_file = r"C:\Users\dnsha\Downloads\7 (1).pcap"
        with PcapReader(pcap_file) as pcap:
            for i, pkt in enumerate(pcap, start=1):
                if i not in valid_ids:
                    continue
                t = time.localtime()
                hours, minutes, seconds = t.tm_hour, t.tm_min, t.tm_sec
                raw_bytes = bytes(pkt)
                wrapped = build_packet(hours, minutes, seconds, count, raw_bytes)
                # Send packet
                
                try:
                    s.sendall(wrapped)
                    print(f"\n[Client] Sent Packet #{count} (PCAP index {i}) "
                          f"Time {hours:02}:{minutes:02}:{seconds:02}, Length {len(raw_bytes)} bytes")
                except Exception as e:
                    print(f"[Client][ERROR] Sending failed: {e}")
                    hexdump(raw_bytes)
                    break

                try:
                    s.settimeout(100)  # maximum 100 seconds to receive data
                    try:
                        resp = s.recv(65535)
                    except socket.timeout as e:
                        print("[Client][ERROR] Response timed out after 100s")
                        print(f"[Client][ERROR] Receive/parse error: {e}")
                        print("PCAP packet layers:")
                        print("[DEBUG] Summary:", pkt.summary())
                        pkt.show()                 # fields/values
                        print("[DEBUG] Raw Bytes:")
                        hexdump(pkt)               # actual bytes

                    dns_bytes = parse_response(resp)
                    dns_pkt = DNS(dns_bytes)

                except Exception as e:
                    print(f"[Client][ERROR] Receive/parse error: {e}")
                    print("PCAP packet layers:")
                    print("[DEBUG] Summary:", pkt.summary())
                    pkt.show()                 # fields/values
                    print("[DEBUG] Raw Bytes:")
                    hexdump(pkt)               # actual bytes
                    print("Raw packet bytes (hexdump):")
                    hexdump(raw_bytes)
                    break
                
                try:
                    qdcount = dns_pkt.qdcount
                    ancount = dns_pkt.ancount
                    print(f"[Client] DNS ID {dns_pkt.id}, Questions: {qdcount}, Answers: {ancount}")
                    if qdcount > 0:
                        for j in range(qdcount):
                            qname = dns_pkt.qd[j].qname.decode()
                            ans_ip = None
                            if ancount > 0 and j < ancount:  # match question with answer
                                ans_ip = dns_pkt.an[j].rdata
                            report.append((qname, ans_ip, count))
                            print(f"[Client][DNS] Q: {qname}, A: {ans_ip}, ID: {count}")
                except Exception as e:
                    print(f"[Client][ERROR] DNS parsing failed: {e}")
                
                count += 1
    print("\n[Client] Final report:")
    for r in report:
        print(r)


if __name__ == "__main__":
    main()
