# Packet Sniffer

This project is a basic packet sniffer written in Python. It captures and displays Ethernet, IPv4, ICMP, TCP, and UDP packet information in a readable format.
**This project is built for Linux.** 

## Overview

A packet sniffer is a tool that captures and analyzes network packets. 
This packet sniffer captures raw packets at the data link layer, processes them, and then displays the details of each packet, including Ethernet frames, IPv4 packets, and ICMP, TCP, and UDP segments.

## Note

**This project is built for Linux.** 
It utilizes raw sockets which require administrative privileges and are typically supported on Unix-like operating systems such as Linux.

## Features

- Capture and parse Ethernet frames
- Decode and display IPv4 packets
- Handle and display ICMP packets
- Process and display TCP segments
- Unpack and show UDP segments
- Format and present packet data in a human-readable form

## Usage

### Imports

The script uses the following imports:
- `socket`: Provides access to the BSD socket interface.
- `struct`: Provides functions to work with C-style data structures.
- `textwrap`: Used to format multi-line data output.

### Functions

- `ethernetFrame(data)`: Unpacks Ethernet frames.
- `getMacAddr(rawMacAddr)`: Converts raw MAC addresses to a readable format.
- `ipv4_packet(data)`: Unpacks IPv4 packets.
- `ipv4(addr)`: Converts a binary IP address to a dotted-decimal format.
- `icmp_packet(data)`: Unpacks ICMP packets.
- `tcp_segment(data)`: Unpacks TCP segments.
- `udp_segment(data)`: Unpacks UDP segments.
- `format_multi_line(prefix, string, size=80)`: Formats multi-line data output.

### Main Function

The `main` function sets up a raw socket and enters an infinite loop to continuously capture and process network packets.

### How to Run

To run the packet sniffer, execute the script directly with admin privileges:

```bash
sudo python packet_sniffer.py
