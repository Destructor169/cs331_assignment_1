# CS331 - Assignment 1: Network Analysis

This repository contains the work for Assignment 1 in CS331: Computer Networks.

## Task 2: Traceroute Protocol Behavior 🌐

This task involved analyzing and comparing the `traceroute` (or `tracert`) utility across different operating systems to understand their underlying network protocols.

### Operating Systems Used

The analysis was performed on the following two operating systems:
* **Microsoft Windows** 🖥️
* **Apple macOS** 🍏

### Methodology & Commands

We used the built-in command-line utilities on each OS and captured the resulting network traffic to analyze the protocols.

#### Windows

The **`tracert`** command was used to trace the path to `www.google.com`. Network traffic was captured with **Wireshark**.

```cmd
tracert [www.google.com](https://www.google.com)
```

#### macOS

The **`traceroute`** command was used, and the network traffic was captured with **`tcpdump`**.

```bash
# To run the trace
traceroute [www.google.com](https://www.google.com)

# To capture the packets
sudo tcpdump -i en0 -n -vv 'host google.com or icmp'
```

The findings and detailed analysis, including screenshots and packet captures, are documented in the final PDF report.
