import socket
import struct
import textwrap

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

# Unpack UDP Segment
def udp_segment(data):
    src_port, dest_port, udp_length = struct.unpack('! H H H', data[:6])
    return src_port, dest_port, udp_length, data[6:]

# Format multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def main():
    mySocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = mySocket.recvfrom(65536)
        destinationMAC, sourceMAC, ethernetProtocol, data = ethernetFrame(raw_data)
        print('\nEthernet Frame:')
        print(f'Destination: {destinationMAC}, Source: {sourceMAC}, Protocol: {ethernetProtocol}')
        
        #IPv4
        if ethernetProtocol == 8:
            (version, header_length, ttl, proto, srcIP, destIP, data) = ipv4_packet(data)
            print(f'\t- IPv4 Packet:')
            print(f'\t\t- Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'Protocol: {proto}, Source: {srcIP}, Destination: {destIP}')

            # ICMP
            if proto == 1:
                icmp_type, code, checksum = icmp_packet(data)
                print(f'\t- ICMP Packet:')
                print(f'\t\t- Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(f'\t\t- Data:')
                print(format_multi_line('\t\t\t', data))
            
            # TCP
            elif proto == 6:
                srcPort, destPort, seqNum, ackNum, offset_reserved_flags, data = tcp_segment(data)
                print(f'\t- TCP Segment:')
                print(f'\t\t- Source Port: {srcPort}, Destination Port: {destPort}')
                print(f'\t\t- Sequence: {seqNum}, Acknowledgment: {ackNum}')
                print(f'\t\t- Flags: {offset_reserved_flags}')
                print(f'\t\t- Data:')
                print(format_multi_line('\t\t\t', data))

            # UDP
            elif proto == 17:
                src_port, dest_port, udp_length, data = udp_segment(data)
                print(f'\t- UDP Segment:')
                print(f'\t\t- Source Port: {src_port}, Destination Port: {dest_port}, UDP Length: {udp_length}')
                print(f'\t\t- Data:')
                print(format_multi_line('\t\t\t', data))
        
        else:
            print(f'Other Ethernet Protocol: {ethernetProtocol}')

# Entry Point
if __name__ == "__main__":
    main()
