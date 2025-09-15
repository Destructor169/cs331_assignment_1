# Task 2 — Traceroute Protocol Behavior

## 📌 Problem Statement

The goal of this task is to analyze the packet-level behavior of the `traceroute` utility across different operating systems (Linux vs Windows). You are required to:

1. Run traceroute on Linux and Windows to compare their default probe protocols.  
   - Linux `traceroute` uses UDP probes (by default).  
   - Windows `tracert` uses ICMP Echo Requests.  

2. Capture the traffic while running traceroute using tools such as `tcpdump`, `tshark`, or `Wireshark`.

3. Answer the following questions based on your packet captures and traceroute outputs:
   - Which protocols are used by Windows `tracert` and Linux `traceroute` by default?  
   - Why might a router show `* * *` instead of a hop response?  
   - In Linux traceroute, which field changes between successive probes?  
   - How is the final hop response different from intermediate hops?  
   - If UDP is blocked but ICMP is allowed, how do results differ between Linux `traceroute` and Windows `tracert`?  

4. Perform traceroute to multiple websites (from the provided list, e.g., `www.google.com`, `www.youtube.com`, etc.) and include observations.

---

## 🛠️ Tools & Environment

- **OS:** Ubuntu Linux VM (VirtualBox)  
- **Commands Used:** `traceroute`, `tracert`, `tcpdump`, `tshark`  
- **Packet Capture Tools:** Wireshark, tcpdump  
- **Destination Sites:** Popular domains such as `google.com`, `youtube.com`, `wikipedia.org`, etc.
