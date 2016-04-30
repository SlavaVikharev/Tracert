import socket
import argparse
from select import select
from sockets import *
import re


regexp_iana = re.compile('whois:(.+)')

fields_regexs = {
    'country': re.compile('country:(.+)')
}


def recv_msg(sock):
    msg = ''
    while select([sock], [], [], 5)[0]:
        res = sock.recv(4096).decode()
        if not res:
            break
        msg += res
    return msg


def traceroute(dest_name, max_hops=10, port=35353):
    dest_addr = socket.gethostbyname(dest_name)

    for ttl in range(1, max_hops + 1):
        cur_addr = ''

        try:
            with icmp_socket() as recv_socket, udp_socket() as send_socket:
                send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

                recv_socket.bind(('', port))
                send_socket.sendto(b'', (dest_name, port))

                try:
                    cur_addr = recv_socket.recvfrom(1024)[1][0]
                except socket.error:
                    pass
        except socket.error:
            pass

        yield cur_addr

        if cur_addr == dest_addr:
            break


def get_asn(ip_addr):
    ip_addr = ip_addr.strip() + '\n'
    asn = ''

    try:
        with socket.create_connection(('v4.whois.cymru.com', 43)) as sock:
            sock.sendall(ip_addr.encode())
            res = recv_msg(sock).lower()
            if res:
                data = res.split('\n')[1]
                asn = data.split(' ')[0]
    except socket.error:
        pass

    return asn


def get_whois_server(ip_addr):
    ip_addr = ip_addr.strip() + '\n'
    serv = ''

    try:
        with socket.create_connection(('whois.iana.org', 43)) as sock:
            sock.sendall(ip_addr.encode())
            res = recv_msg(sock).lower()
            res = regexp_iana.search(res)
            try:
                serv = res.groups()[0].strip()
            except:
                pass
    except socket.error:
        pass

    return serv


def get_info(server, ip_addr):
    ip_addr = ip_addr.strip() + '\n'

    info = {}

    try:
        with socket.create_connection((server, 43)) as sock:
            sock.sendall(ip_addr.encode())
            res = recv_msg(sock).lower()
            for field, regex in fields_regexs.items():
                value = regex.search(res)
                try:
                    value = value.groups()[0].strip()
                except:
                    value = ''
                info[field] = value
    except socket.error:
        pass

    return info


def main(dest_name):
    # t = Tracer(dest_name)
    # t.run()
    for i, addr in enumerate(traceroute(dest_name)):
        info = {}
        if addr:
            info['asn'] = get_asn(addr)
            server = get_whois_server(addr)
            if server:
                info.update(get_info(server, addr))
        print("%d) %s" % (i + 1, addr or "*"))
        print("....ASN: %s" % info.get('asn', ''))
        print("....Country: %s" % info.get('country', ''))


if __name__ == '__main__':
    socket.setdefaulttimeout(5)
    parser = argparse.ArgumentParser()
    parser.add_argument('host', help='Trace route to this host')
    parser.add_argument('-t', '--timeout', type=float,
                        default=2.0, help='Set timeout')
    args = parser.parse_args()
    socket.setdefaulttimeout(args.timeout)
    main(args.host)
