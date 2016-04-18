import socket
import argparse
from sockets import *
import re


regexp_iana = re.compile('whois:(.+)')
regexp_reg_country = re.compile('country:(.+)')


def recv_msg(sock):
    msg = buf = sock.recv(4096).decode()
    while buf:
        buf = sock.recv(4096).decode()
        msg += buf
    return msg


def traceroute(dest_name, max_hops=10, port=12345):
    dest_addr = socket.gethostbyname(dest_name)

    for ttl in range(1, max_hops + 1):
        with icmp_socket() as recv_socket, udp_socket() as send_socket:
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

            recv_socket.bind(("", port))
            send_socket.sendto(b"", (dest_name, port))

            curr_addr = None
            try:
                curr_addr = recv_socket.recvfrom(512)[1][0]
            except socket.error as e:
                pass

        yield curr_addr

        if curr_addr == dest_addr:
            break


def get_asn(ip_addr):
    ip_addr = ip_addr.strip() + '\n'

    with socket.create_connection(('v4.whois.cymru.com', 43)) as sock:
        sock.sendall(ip_addr.encode())
        res = recv_msg(sock).lower()
        data = res.split('\n')[1]
        asn = data.split(' ')[0]

    return asn


def get_whois_server(ip_addr):
    ip_addr = ip_addr.strip() + '\n'

    with socket.create_connection(("whois.iana.org", 43)) as sock:
        sock.sendall(ip_addr.encode())
        res = recv_msg(sock).lower()
        res = regexp_iana.search(res)

    try:
        return res.groups()[0].strip()
    except:
        return None


def get_country(server, ip_addr):
    ip_addr = ip_addr.strip() + '\n'

    with socket.create_connection((server, 43)) as sock:
        sock.sendall(ip_addr.encode())
        res = recv_msg(sock).lower()
        country = regexp_reg_country.search(res)

    try:
        return country.groups()[0].strip().upper()
    except:
        return None


def main(dest_name):
    for i, addr in enumerate(traceroute(dest_name)):
        asn = ""
        if addr:
            asn = get_asn(addr)
            server = get_whois_server(addr)
            country = ''
            if server:
                country = get_country(server, addr)
        print("%d) %s" % (i + 1, addr or "*"))
        print("....ASN: %s" % (asn,))
        print("....Country: %s" % (country,))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('host', help='Trace route to this host')
    parser.add_argument('-t', '--timeout', type=float,
                        default=2.0, help='Set timeout')
    args = parser.parse_args()
    socket.setdefaulttimeout(args.timeout)
    main(args.host)
