import struct
import socket
from scapy.all import Ether, DNS, DNSRR, Packet, hexdump

MAGIC = b"NP"

IP_Pool = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10",
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

def parse_packet(packet: bytes):
    assert packet[:2] == MAGIC, "Invalid MAGIC"
    header = packet[2:8]  # 6 bytes header
    hh, mm, ss = struct.unpack("!BBB", header[:3])
    pkt_id = int.from_bytes(header[3:], byteorder='big')
    inner_len = struct.unpack("!I", packet[8:12])[0]
    inner_bytes = packet[12:12+inner_len]
    return hh, mm, ss, pkt_id, inner_bytes

def ip_to_use(hh, pkt_id):
    if 4 <= hh <= 11:
        return IP_Pool[pkt_id % 5]
    elif 12 <= hh <= 19:
        return IP_Pool[5 + (pkt_id % 5)]
    else:
        return IP_Pool[10 + (pkt_id % 5)]


def build_response(dns_req, ip_ans, id):
    """Build DNS response with same questions and authoritative answer"""
    answers = None
    for q in dns_req.qd:
        ans = DNSRR(rrname=q.qname, type="A", ttl=60, rdata=ip_ans)
        answers = ans if answers is None else answers / ans
    dns_resp = DNS(
        id=id,
        qr=1,  # response
        aa=1,  # authoritative
        qd=dns_req.qd,
        an=answers,
        ancount=len(dns_req.qd)
    )
    dns_bytes = dns_resp.build()
    inner_len = struct.pack("!I", len(dns_bytes))
    #print("[Server] DNS response built, length:", len(dns_bytes),dns_resp.summary(),dns_resp.show())
    packet = MAGIC + inner_len + dns_bytes
    return packet

def main():
    HOST = "127.0.0.1"
    PORT = 9000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        #print(f"[Server] Listening on {HOST}:{PORT} ...")
        conn, addr = s.accept()
        #print("[Server] Connected:", addr)

        with conn:
            while True:
                try:
                    data = conn.recv(65535)
                    if not data:
                        #print("[Server] Connection closed by client")
                        break

                    hh, mm, ss, pkt_id, inner_bytes = parse_packet(data)
                    #print(f"\n[Server] Received Packet ID {pkt_id} at {hh:02}:{mm:02}:{ss:02}, "
                          #f"length {len(inner_bytes)} bytes")

                    try:
                        pkt = Ether(inner_bytes)
                        #print("[DEBUG] Summary:", pkt.summary())
                        #pkt.show()                 # fields/values
                        #print("[DEBUG] Raw Bytes:")
                        #hexdump(pkt)               # actual bytes

                        dns_req = pkt[DNS]
                        #print(f"[Server] DNS ID {dns_req.id}, questions: {dns_req.qdcount}")

                        ip_ans = ip_to_use(hh, pkt_id)
                        #print(f"[Server] Answering Packet ID {pkt_id} with IP {ip_ans}")

                        response = build_response(dns_req, ip_ans,pkt_id)
                        
                        conn.sendall(response)
                    except Exception as e:
                        #print(f"[Server][ERROR] Failed to parse/build DNS: {e}")
                        #print(f"[Server][DEBUG] inner_bytes length: {len(inner_bytes)} bytes")

                        # Try to decode layers if possible
                        try:
                            pkt_debug = Ether(inner_bytes)
                            layers = []
                            #print("[DEBUG] Summary:", pkt.summary())
                            #pkt.show()                 # fields/values
                            #print("[DEBUG] Raw Bytes:")
                            #hexdump(pkt)               # actual bytes
                            #print("[Server][DEBUG] Layers detected:", " -> ".join(layers))
                            #print("[Server][DEBUG] Packet summary:", pkt_debug.summary())
                        except Exception as e2:
                            print(f"[Server][DEBUG] Could not decode layers: {e2}")
                            # Print raw bytes both hex and ASCII-safe
                            #print("[Server][DEBUG] Raw bytes (hex):")
                            #hexdump(inner_bytes)
                            #print("[Server][DEBUG] Raw bytes (repr):", repr(inner_bytes))
                                                
                except Exception as e:
                    print(f"[Server][ERROR] Connection/recv error: {e}")
                    break

if __name__ == "__main__":
    main()
