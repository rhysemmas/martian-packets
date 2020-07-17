import array
import socket
import struct

def chksum(packet: bytes) -> int:
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff


class TCPPacket:
    def __init__(self,
                 src_host:  str,
                 src_port:  int,
                 dst_host:  str,
                 dst_port:  int,
                 flags:     int = 0):
        self.src_host = src_host
        self.src_port = src_port
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.flags = flags

    def build_tcp(self) -> bytes:
        packet = struct.pack(
            '!HHIIBBHHH',
            self.src_port,  # Source Port
            self.dst_port,  # Destination Port
            0,              # Sequence Number
            0,              # Acknoledgement Number
            5 << 4,         # Data Offset
            self.flags,     # Flags
            8192,           # Window
            0,              # Checksum (initial value)
            0               # Urgent pointer
        )

        pseudo_hdr = struct.pack(
            '!4s4sHH',
            socket.inet_aton(self.src_host),    # Source Address
            socket.inet_aton(self.dst_host),    # Destination Address
            socket.IPPROTO_TCP,                 # PTCL
            len(packet)                         # TCP Length
        )

        checksum = chksum(pseudo_hdr + packet)

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
    real_dst = '192.168.0.1'
    dst = '127.0.0.1'
    src = '127.0.0.1'

    #tcp flags
    fin = 0
    syn = 1
    rst = 0
    psh = 0
    ack = 0
    urg = 0
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)

    pak = TCPPacket(
        src,
        25565,
        dst,
        10249,
        tcp_flags
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    packet = pak.build_ip() + pak.build_tcp()

    s.sendto(packet, (real_dst, 0))
