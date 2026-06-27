import socket
import struct
import binascii

def checksum(msg):
    # Convert input to a list of byte integers in a Python 2/3 compatible way
    data = [ord(c) if isinstance(c, (str, bytes)) else c for c in msg]
    if len(data) % 2 == 1:
        data.append(0)
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i+1]
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s

def build_ethernet_header(src_mac, dst_mac, ethertype):
    src_bytes = binascii.unhexlify(src_mac.replace(':', ''))
    dst_bytes = binascii.unhexlify(dst_mac.replace(':', ''))
    return struct.pack('!6s6sH', dst_bytes, src_bytes, ethertype)

def build_ipv4_tcp(src_ip, dst_ip, src_port, dst_port, flags, seq, ack=0, payload=b""):
    version = 4
    ihl = 5
    tos = 0
    tot_len = 20 + 20 + len(payload)
    id = 54321
    frag_off = 0
    ttl = 64
    protocol = socket.IPPROTO_TCP
    check = 0
    saddr = socket.inet_aton(src_ip)
    daddr = socket.inet_aton(dst_ip)
    
    ihl_version = (version << 4) + ihl
    ip_header = struct.pack('!BBHHHBBH4s4s', ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
    ip_check = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', ihl_version, tos, tot_len, id, frag_off, ttl, protocol, ip_check, saddr, daddr)
    
    window = 5840
    tcp_check = 0
    urg_ptr = 0
    
    flag_val = 0
    if 'F' in flags: flag_val |= 1
    if 'S' in flags: flag_val |= 2
    if 'R' in flags: flag_val |= 4
    if 'P' in flags: flag_val |= 8
    if 'A' in flags: flag_val |= 16
    
    data_offset = 5
    offset_res = (data_offset << 4) + 0
    
    tcp_header = struct.pack('!HHLLBBHHH', src_port, dst_port, seq, ack, offset_res, flag_val, window, tcp_check, urg_ptr)
    
    placeholder = 0
    tcp_length = 20 + len(payload)
    psh = struct.pack('!4s4sBBH', saddr, daddr, placeholder, protocol, tcp_length)
    psh = psh + tcp_header + payload
    tcp_check = checksum(psh)
    
    tcp_header = struct.pack('!HHLLBBHHH', src_port, dst_port, seq, ack, offset_res, flag_val, window, tcp_check, urg_ptr)
    
    return ip_header + tcp_header + payload

def build_ipv6_tcp(src_ip, dst_ip, src_port, dst_port, flags, seq, ack=0, payload=b""):
    version = 6
    traffic_class = 0
    flow_label = 0
    payload_len = 20 + len(payload)
    next_header = 6 # TCP
    hop_limit = 64
    saddr = socket.inet_pton(socket.AF_INET6, src_ip)
    daddr = socket.inet_pton(socket.AF_INET6, dst_ip)
    
    vtcf = (version << 28) + (traffic_class << 20) + flow_label
    ipv6_header = struct.pack('!IHBB16s16s', vtcf, payload_len, next_header, hop_limit, saddr, daddr)
    
    window = 5840
    tcp_check = 0
    urg_ptr = 0
    
    flag_val = 0
    if 'F' in flags: flag_val |= 1
    if 'S' in flags: flag_val |= 2
    if 'R' in flags: flag_val |= 4
    if 'P' in flags: flag_val |= 8
    if 'A' in flags: flag_val |= 16
    
    data_offset = 5
    offset_res = (data_offset << 4) + 0
    
    tcp_header = struct.pack('!HHLLBBHHH', src_port, dst_port, seq, ack, offset_res, flag_val, window, tcp_check, urg_ptr)
    
    psh = struct.pack('!16s16sI3xB', saddr, daddr, payload_len, next_header)
    psh = psh + tcp_header + payload
    tcp_check = checksum(psh)
    
    tcp_header = struct.pack('!HHLLBBHHH', src_port, dst_port, seq, ack, offset_res, flag_val, window, tcp_check, urg_ptr)
    
    return ipv6_header + tcp_header + payload
