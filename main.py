import socket
import struct
import time


print('Author : omid tri')


# IN TCP IP AST. AMALKARD: BEHTARIN
class tcp_ip:

    def __init__(self, mac_sender, mac_hadaf, ip_sender, ip_hadaf, source_Port, destions_port, mssage):
        self.mac_sender = mac_sender
        self.mac_hadaf = mac_hadaf

        self.ip_sender = ip_sender
        self.ip_hadaf = ip_hadaf
        self.ip_sender_b = socket.inet_aton(self.ip_sender)
        self.ip_hadaf_b = socket.inet_aton(self.ip_hadaf)
        # self.total_len_ipv4 = int(len(self.IPV4())) + int(len(self.TCP_PSEUDO())) + int(len(self.mssage))

        self.source_port = source_Port
        self.destions_port = destions_port
        self.mssage = mssage
        self.mssage_b = bytes(mssage.encode())

    def checksum_packet(self, packet):
        size = len(packet)
        sum = 0
        pointer = 0

        while size > 1:
            sum += int((str("%02x" % (packet[pointer],)) + str("%02x" % (packet[pointer + 1],))), 16)
            size -= 2
            pointer += 2
        if size:
            sum += packet[pointer]

        # sum = (sum >> 16) + (sum & 0xffff)
        # sum += (sum >> 16)
        #
        # return (~sum) & 0xffff
        return sum

    def checksum_msg(self):
        sum = 0
        poin = 0
        while len(self.mssage) > poin:
            try:
                sum += (int(ord(self.mssage[poin]) * 256 + int(ord(self.mssage[poin + 1]))))
                poin += 2
            except:
                sum += (int(ord(self.mssage[poin]) * 256))
                break
        # sum = (sum >> 16) + (sum & 0xffff)
        # sum += (sum >> 16)
        #
        # return (~sum) & 0xffff
        return sum

    def IPV4(self):
        version = 4
        ihl = 5
        dscp = 48
        total_len = 20 + int(len(self.TCP_PSEUDO())) + int(len(self.mssage))
        idenfity = 10
        flags = 64
        fargoffset = 0
        ttl = 255
        protocol = 6
        ip_checksum = 0
        ip_sender_b = self.ip_sender_b
        ip_hadaf_b = self.ip_hadaf_b
        ver_ihl = (version << 4) | ihl

        ip_hed = struct.pack('!BBHHBBBBH4s4s', ver_ihl, dscp, total_len, idenfity, flags, fargoffset, ttl, protocol,
                             ip_checksum, ip_sender_b, ip_hadaf_b)
        ip_checksum = self.checksum_packet(ip_hed)
        ip_checksum = (ip_checksum >> 16) + (ip_checksum & 0xffff)
        ip_checksum += (ip_checksum >> 16)

        ip_checksum = (~ip_checksum) & 0xffff

        ip_hed = struct.pack('!BBHHBBBBH4s4s', ver_ihl, dscp, total_len, idenfity, flags, fargoffset, ttl, protocol,
                             ip_checksum, ip_sender_b, ip_hadaf_b)
        return ip_hed

    def TCP_PSEUDO(self):
        source_port = 80
        destination_port = 80
        seq_number = 1
        ack_number = 1
        hlen_tcp = 5
        res = 0
        fin_tcp = 0
        syn_tcp = 1
        rst_tcp = 0
        psh_tcp = 0
        ack_tcp = 0
        urg_tcp = 0
        window = socket.htons(556)
        tcp_checksum = 0
        tcp_urgent = 0
        tcp_offset = (hlen_tcp << 4) | res
        tcp_flags = fin_tcp | (syn_tcp << 1) | (rst_tcp << 2) | (psh_tcp << 3) | (ack_tcp << 4) | (urg_tcp << 5)

        tcp_hed = struct.pack("!HHLLBBHHH", source_port, destination_port, seq_number, ack_number, tcp_offset,
                              tcp_flags, window,
                              tcp_checksum, tcp_urgent)
        # ---PSEUDO
        pse_ip_send = self.ip_sender_b
        pse_ip_hadaf = self.ip_hadaf_b
        pse_zero = 0
        pse_protocol = 6
        pse_total_len = int(len(tcp_hed)) + int(len(self.mssage))
        # pse_zero_protocol = (pse_zero << 8) | pse_protocol
        pseudo_hed = struct.pack('!4s4sBBB', pse_ip_send, pse_ip_hadaf, pse_zero, pse_protocol, pse_total_len)

        tcp_checksum1 = self.checksum_packet(tcp_hed)
        tcp_checksum2 = self.checksum_packet(pseudo_hed)
        tcp_checksum3 = self.checksum_msg()

        tcp_checksum = tcp_checksum2 + tcp_checksum1 + tcp_checksum3
        tcp_checksum = (tcp_checksum >> 16) + (tcp_checksum & 0xffff)
        tcp_checksum += (tcp_checksum >> 16)

        tcp_checksum = (~tcp_checksum) & 0xffff
        tcp_checksum = tcp_checksum

        # ---NEW TCP HED
        tcp_hed = struct.pack("!HHLLBBHHH", source_port, destination_port, seq_number, ack_number, tcp_offset,
                              tcp_flags, window,
                              tcp_checksum, tcp_urgent)
        return tcp_hed

    def ETHER(self):
        ether = bytes.fromhex(self.mac_hadaf)
        ether += bytes.fromhex(self.mac_sender)
        ether += bytes.fromhex('0800')

        return ether

    def send(self):
        packet = self.ETHER() + self.IPV4() + self.TCP_PSEUDO() + self.mssage_b

        sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
        sock.bind(('eth0', socket.SOCK_RAW))

        while True:
            sock.send(packet)
            time.sleep(2)


mac_sender = '080027007248'
mac_hadaf = 'ac2b6ec943ac'
# mac_hadaf = '180f76d16670'
ip_sender = '192.168.1.12'
ip_hadaf = '192.168.1.4'
port_sender = 80
port_hadaf = 80
mssage = '  OMID  BEST**  OMID*_OMID'

tcp = tcp_ip(mac_sender, mac_hadaf, ip_sender, ip_hadaf, port_sender, port_hadaf, mssage)
tcp.send()
