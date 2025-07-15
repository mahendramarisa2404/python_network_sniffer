import socket
import struct
import time

# Formatting Helpers
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 4:
            size += 4 - (size % 4)
    return '\n'.join([prefix + string[i:i+size] for i in range(0, len(string), size)])

# Ethernet Frame
class Ethernet:
    def __init__(self, raw_data):
        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
        self.dest_mac = self.mac_format(dest)
        self.src_mac = self.mac_format(src)
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]

    def mac_format(self, bytes_addr):
        return ':'.join(map('{:02x}'.format, bytes_addr))

# IPv4 Packet
class IPv4:
    def __init__(self, raw_data):
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src = self.ipv4(src)
        self.target = self.ipv4(target)
        self.data = raw_data[self.header_length:]

    def ipv4(self, addr):
        return '.'.join(map(str, addr))

# ICMP Packet
class ICMP:
    def __init__(self, raw_data):
        self.type, self.code, self.checksum = struct.unpack('! B B H', raw_data[:4])
        self.data = raw_data[4:]

# TCP Segment
class TCP:
    def __init__(self, raw_data):
        (self.src_port, self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_fin = offset_reserved_flags & 1
        self.data = raw_data[offset:]

# UDP Segment
class UDP:
    def __init__(self, raw_data):
        self.src_port, self.dest_port, self.size = struct.unpack('! H H 2x H', raw_data[:8])
        self.data = raw_data[8:]

# HTTP Data
class HTTP:
    def __init__(self, raw_data):
        try:
            self.data = raw_data.decode('utf-8')
        except:
            self.data = raw_data

# PCAP Writer
class Pcap:
    def __init__(self, filename):
        self.pcap = open(filename, 'wb')
        self.write_global_header()

    def write_global_header(self):
        self.pcap.write(struct.pack('@ I H H i I I I',
                                    0xa1b2c3d4, 2, 4, 0,
                                    0, 65535, 1))

    def write(self, raw_bytes):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(raw_bytes)
        self.pcap.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap.write(raw_bytes)

    def close(self):
        self.pcap.close()

# Tabs for formatting output
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '

# Main Packet Sniffer
def main():
    pcap = Pcap('capture.pcap')

    # For Linux: AF_PACKET
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except Exception as e:
        print("Error: Raw socket requires sudo/admin rights.")
        return

    while True:
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        eth = Ethernet(raw_data)

        print('\nEthernet Frame:')
        print(TAB_1 + f'Destination: {eth.dest_mac}, Source: {eth.src_mac}, Protocol: {eth.proto}')

        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + f'Version: {ipv4.version}, Header Length: {ipv4.header_length}, TTL: {ipv4.ttl}')
            print(TAB_2 + f'Protocol: {ipv4.proto}, Source: {ipv4.src}, Target: {ipv4.target}')

            # ICMP
            if ipv4.proto == 1:
                icmp = ICMP(ipv4.data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + f'Type: {icmp.type}, Code: {icmp.code}, Checksum: {icmp.checksum}')
                print(TAB_2 + 'ICMP Data:')
                print(format_multi_line(DATA_TAB_3, icmp.data))

            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + f'Source Port: {tcp.src_port}, Destination Port: {tcp.dest_port}')
                print(TAB_2 + f'Sequence: {tcp.sequence}, Acknowledgment: {tcp.acknowledgment}')
                print(TAB_2 + 'Flags:')
                print(TAB_3 + f'URG: {tcp.flag_urg}, ACK: {tcp.flag_ack}, PSH: {tcp.flag_psh}')
                print(TAB_3 + f'RST: {tcp.flag_rst}, SYN: {tcp.flag_syn}, FIN: {tcp.flag_fin}')

                if len(tcp.data) > 0:
                    # HTTP Data
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp.data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(format_multi_line(DATA_TAB_3, tcp.data))

            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + f'Source Port: {udp.src_port}, Destination Port: {udp.dest_port}, Length: {udp.size}')

            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(format_multi_line(DATA_TAB_2, ipv4.data))

        else:
            print('Non-IPv4 Ethernet Data:')
            print(format_multi_line(DATA_TAB_1, eth.data))

    pcap.close()

if __name__ == "__main__":
    main()
