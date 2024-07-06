import socket
import struct

# Unpack Ethernet Frame
def ethernetFrame(data):
    destinationMAC, sourceMAC, ethernetProtocol = struct.unpack('! 6s 6s H', data[:14])
    return getMacAddr(destinationMAC), getMacAddr(sourceMAC), socket.htons(ethernetProtocol), data[14:]

# Return Formatted MAC Address
def getMacAddr(rawMacAddr):
    mac_string = map('{:02x}'.format, rawMacAddr)
    return ':'.join(mac_string).upper()

# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, srcIP, destIP = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(srcIP), ipv4(destIP), data[header_length:]

# Return properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpack ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP Segment
def tcp_segment(data):
    srcPort, destPort, seqNum, ackNum, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return srcPort, destPort, seqNum, ackNum, offset_reserved_flags, data[offset:]
