from scapy.all import sniff
from scapy.all import get_if_list

# List all available interfaces
print(get_if_list())

def packet_callback(pkt):
    print(pkt.summary())

# Capture for up to 100 seconds or indefinitely with Ctrl+C
sniff(iface="\\Device\\NPF_Loopback", prn=packet_callback, timeout=100, store=0, promisc=True)
