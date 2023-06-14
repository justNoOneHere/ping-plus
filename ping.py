import os
import platform
import socket
import struct
import sys
import time
import argparse

if platform.system().lower() == "windows":
    timer = time.perf_counter
else:
    timer = time.time

def calculate_checksum(packet):
    checksum = 0
    count = (len(packet) // 2) * 2

    for i in range(0, count, 2):
        checksum += (packet[i + 1] << 8) + packet[i]

    if count < len(packet):
        checksum += packet[len(packet) - 1]

    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16
    checksum = ~checksum & 0xFFFF

    return checksum

def send_ping_request(dest_addr, timeout=1, icmp_seq=1, payload_size=32, ttl=None):
    checksum = 0
    header = struct.pack('!BBHHH', 8, 0, checksum, icmp_seq, 1)
    data = payload_size * 'Q'
    packet = header + bytes(data.encode())

    checksum = calculate_checksum(packet)
    header = struct.pack('!BBHHH', 8, 0, socket.htons(checksum), icmp_seq, 1)
    packet = header + bytes(data.encode())

    icmp = socket.getprotobyname('icmp')
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    sock.settimeout(timeout)

    if ttl:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

    try:
        start_time = timer()
        sock.sendto(packet, (dest_addr, 1))

        recv_pkt, addr = sock.recvfrom(1024)
        end_time = timer()
        elapsed_time = (end_time - start_time) * 1000

        icmp_header = recv_pkt[20:28]
        type, code, checksum, packet_id, sequence = struct.unpack('!BBHHH', icmp_header)

        print(f'Reply from {dest_addr}: bytes={payload_size} time={int(elapsed_time)}ms TTL={recv_pkt[8]}')

        return True, elapsed_time

    except socket.timeout:
        print(f'Request timed out for {dest_addr}')
        return False, None

    finally:
        sock.close()

def ping(host, count=4, timeout=1, payload_size=32, ttl=None, interval=1, perform_whois_lookup=False, perform_nslookup=False, scan_ports=False, start_port=1, end_port=65535):
    print(f'\n[*] - Pinging {host} [{socket.gethostbyname(host)}] with {payload_size} bytes of data:')
    sent_count = 0
    recv_count = 0

    min_time = sys.maxsize
    max_time = 0
    total_time = 0

    for seq in range(1, count + 1):
        success, elapsed_time = send_ping_request(host, timeout, seq, payload_size, ttl)

        if success:
            sent_count += 1
            recv_count += 1
            total_time += elapsed_time

            if elapsed_time < min_time:
                min_time = elapsed_time
            if elapsed_time > max_time:
                max_time = elapsed_time
        else:
            sent_count += 1

        time.sleep(interval)

    packet_loss = (sent_count - recv_count) / sent_count * 100 if sent_count > 0 else 0
    avg_time = total_time / recv_count if recv_count > 0 else 0

    print(f'\n[*] - Packets: Sent = {sent_count}, Received = {recv_count}, Lost = {sent_count - recv_count} '
          f'({packet_loss:.1f}% loss)')
    print(f'Approximate round trip times in milli-seconds:')
    print(f'Minimum = {min_time:.0f}ms, Maximum = {max_time:.0f}ms, Average = {avg_time:.0f}ms')

    if perform_whois_lookup:
        perform_whois_lookup_func(host)

    if perform_nslookup:
        perform_nslookup_func(host)

    if scan_ports:
        perform_port_scan(host, start_port, end_port)

def perform_whois_lookup_func(host):
    whois_server = 'whois.iana.org'
    whois_port = 43

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((whois_server, whois_port))

        query = host + '\r\n'
        sock.send(query.encode())

        response = b''
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data

        print(f'\n[*] - WHOIS lookup for {host}:')
        print(response.decode())

    except socket.error as e:
        print(f'Error performing WHOIS lookup: {str(e)}')
    finally:
        sock.close()


def perform_nslookup_func(host):
    try:
        addresses = socket.getaddrinfo(host, None)
        ipv4_addresses = []
        ipv6_addresses = []

        for address in addresses:
            ip = address[4][0]
            if address[0] == socket.AF_INET6:
                ipv6_addresses.append(ip)
            else:
                ipv4_addresses.append(ip)

        print(f'\n[*] - IP Addresses for {host}:')
        if ipv4_addresses:
            print('IPv4 Addresses:')
            for ipv4 in ipv4_addresses:
                print(ipv4)
        
        if ipv6_addresses:
            print('IPv6 Addresses:')
            for ipv6 in ipv6_addresses:
                print(ipv6)
    except socket.gaierror:
        print(f'Could not resolve host: {host}')

def perform_port_scan(host, start_port, end_port):
    print(f'\n[*] - Starting port scan for {host} from port {start_port} to {end_port}:')
    open_ports = []

    for port in range(start_port, end_port + 1):
        print(f'Scanning port {port}...', end=' ')
        sys.stdout.flush()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            open_ports.append(port)
            print('Open')
        else:
            print('Closed')

    if open_ports:
        print('\n[*] - Open ports:')
        for port in open_ports:
            print(port)
    else:
        print('\n[*] - No open ports found.')

parser = argparse.ArgumentParser(description='Ping')
parser.add_argument('host', nargs='?', help='host to ping or perform WHOIS/NSLookup')
parser.add_argument('-c', '--count', type=int, default=4, help='number of packets to send (default: 4)')
parser.add_argument('-t', '--timeout', type=float, default=1, help='timeout in seconds (default: 1)')
parser.add_argument('-s', '--size', type=int, default=32, help='payload size in bytes (default: 32)')
parser.add_argument('-T', '--ttl', type=int, help='time to live (default: system default)')
parser.add_argument('-i', '--interval', type=float, default=1, help='interval between packets in seconds (default: 1)')
parser.add_argument('-w', '--whois', action='store_true', help='perform WHOIS lookup')
parser.add_argument('-n', '--nslookup', action='store_true', help='perform NSLookup')
parser.add_argument('--scan-port', action='store_true', help='perform port scan')
parser.add_argument('--start-port', type=int, default=1, help='start port for port scan (default: 1)')
parser.add_argument('--end-port', type=int, default=65535, help='end port for port scan (default: 65535)')

args = parser.parse_args()

if args.host:
    host = args.host
    count = args.count
    timeout = args.timeout
    payload_size = args.size
    ttl = args.ttl
    interval = args.interval
    perform_whois_lookup = args.whois
    perform_nslookup = args.nslookup
    scan_ports = args.scan_port
    start_port = args.start_port
    end_port = args.end_port

    ping(host, count, timeout, payload_size, ttl, interval, perform_whois_lookup, perform_nslookup, scan_ports, start_port, end_port)

else:
    parser.print_help()
