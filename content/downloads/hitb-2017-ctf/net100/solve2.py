import os
import re
import socket
import subprocess

import enum
import dpkt
import yenc


class State(enum.Enum):
    idle = 0
    waiting_for_response = 1
    multiline_response = 2


class Direction(enum.Enum):
    from_client = 0
    from_server = 1


def parse_yline(line):
    return {
        p[0]: p[1]
        for p in (
            piece.split('=')
            for piece in line.split()[1:]
        )
    }


class Session(object):
    def __init__(self):
        self.buffer = {
            Direction.from_client: '',
            Direction.from_server: '',
        }
        self.state = State.waiting_for_response  # Server starts with intro
        self.f = self.d = None

    def __call__(self, direction, data):
        buffer = self.buffer[direction] + data
        while True:
            i = buffer.find('\r\n')
            if i == -1:
                break
            line, buffer = buffer[:i], buffer[i + 2:]
            self.feed(direction, line)
        self.buffer[direction] = buffer

    def feed(self, direction, line):
        if direction == Direction.from_client:
            if self.state != State.idle:
                raise RuntimeError('Unexpected state {} when client is sending data'.format(self.state))
            self.state = State.waiting_for_response
        else:
            if self.state == State.idle:
                raise RuntimeError('Unexpected state {} when server is sending data'.format(self.state))
            elif self.state == State.waiting_for_response:
                code, message = line.split(' ', 1)
                if code in ('220', '221', '222', '231', '230', '215'):
                    self.state = State.multiline_response
                else:
                    self.state = State.idle
            elif self.state == State.multiline_response:
                if line != '.':
                    if line.startswith('=ybegin '):
                        hdr = parse_yline(line)
                        path = os.path.join('output', hdr['name'])
                        if not os.path.exists(path):
                            self.f = open(path, 'w+b')
                            self.f.write('\0' * int(hdr['size']))
                        else:
                            self.f = open(path, 'r+b')
                        self.f.seek(0, os.SEEK_SET)
                        self.d = yenc.Decoder()
                    elif line.startswith('=ypart '):
                        hdr = parse_yline(line)
                        self.f.seek(int(hdr['begin']), os.SEEK_SET)
                    elif line.startswith('=yend '):
                        hdr = parse_yline(line)
                        self.f.write(self.d.getDecoded())
                        self.f.close()
                        self.f = self.d = None
                    elif self.d is not None:
                        self.d.feed(line + '\r\n')
                else:
                    self.state = State.idle

def scrape(path):
    server = None
    sessions = {}

    pcap = dpkt.pcap.Reader(open(path, 'rb'))

    for ts, data in pcap:
        eth = dpkt.ethernet.Ethernet(data)
        ip = eth.data
        tcp = ip.tcp

        if tcp.flags & (dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK) == dpkt.tcp.TH_SYN:
            if server is None:
                server = ip.dst
            sessions[tcp.sport] = Session()

            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            print 'Created session {}:{} -> {}:{}'.format(src, tcp.sport, dst, tcp.dport)

        if tcp.data:
            if ip.dst == server:
                session = sessions[tcp.sport]
                session(Direction.from_client, tcp.data)
            else:
                session = sessions[tcp.dport]
                session(Direction.from_server, tcp.data)


def flagfinder(path):
    flag_re = re.compile(r'(HITB\{[0-9a-f]{32}\})')
    p = subprocess.Popen(['tar', '-jxOf', path], stdout=subprocess.PIPE)
    while p.returncode is None:
        line = p.stdout.readline()
        m = flag_re.search(line)
        if m is not None:
            p.terminate()
            return m.group(1)


if __name__ == '__main__':
    if not os.path.isdir('output'):
        os.mkdir('output')

    print
    print 'Scraping file from pcap...'
    scrape('net100.pcap')

    print
    print 'Reparing tarball...'
    subprocess.check_call(['par2', 'r', 'output/data.tar.bz2.par2'])

    print
    print 'Finding flag in tarball...'
    flag = flagfinder('output/data.tar.bz2')

    print
    print 'Flag:', flag