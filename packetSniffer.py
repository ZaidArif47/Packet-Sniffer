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
