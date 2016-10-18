# -*- coding: utf-8 -*-
""" socks5_server

Supports both python 2 and 3.
"""

__author__ = "Caleb Madrigal"
__date__ = '2016-10-17'

import sys
import argparse
import logging
import socket
import select
import threading

PY3 = sys.version_info[0] == 3
if PY3:
    chr_to_int = lambda x: x
    encode_str = lambda x: x.encode()
else:
    chr_to_int = ord
    encode_str = lambda x: x

SOCK_TIMEOUT = 5  # seconds
RESEND_TIMEOUT = 60  # seconds
MAX_RECEIVE_SIZE = 65536

VER = b'\x05'
METHOD = b'\x00'
SUCCESS = b'\x00'
SOCK_FAIL = b'\x01'
NETWORK_FAIL = b'\x02'
HOST_FAIL = b'\x04'
REFUSED = b'\x05'
TTL_EXPIRED = b'\x06'
UNSUPPORTED_CMD = b'\x07'
ADDR_TYPE_UNSUPPORT = b'\x08'
UNASSIGNED = b'\x09'

ADDR_TYPE_IPV4 = b'\x01'
ADDR_TYPE_DOMAIN = b'\x03'
ADDR_TYPE_IPV6 = b'\x04'

CMD_TYPE_CONNECT = b'\x01'
CMD_TYPE_TCP_BIND = b'\x02'
CMD_TYPE_UDP = b'\x03'


def make_logger(log_path=None, log_level_str='INFO'):
    formatter = logging.Formatter('%(asctime)s: %(name)s (%(levelname)s): %(message)s')
    if log_path:
        log_handler = logging.FileHandler(log_path)
    else:
        log_handler = logging.StreamHandler(sys.stdout)
    log_handler.setFormatter(formatter)
    logger = logging.getLogger('socks5_server')
    logger.addHandler(log_handler)
    log_level = logging.getLevelName(log_level_str.upper())
    logger.setLevel(log_level)
    return logger


class Socks5Server:
    def __init__(self, host, port, logger, backlog=128):
        self.host = host
        self.port = port
        self.logger = logger
        self.backlog = backlog
        self.client_dest_map_lock = threading.Lock()
        # This holds client_sock -> dest_sock and dest_sock -> client_sock mappings
        self.client_dest_map = {}
        # Maps from sock -> buffer to send to sock
        self.sock_send_buffers = {}

    def buffer_receive(self, sock):
        """ Reads into the buffer for the corresponding relay socket. """
        target_sock = self.client_dest_map[sock]
        buf = sock.recv(MAX_RECEIVE_SIZE)
        if len(buf) == 0:
            self.flush_and_close_sock_pair(sock)
        elif target_sock not in self.sock_send_buffers:
            self.sock_send_buffers[target_sock] = buf
        else:
            self.sock_send_buffers[target_sock] = self.sock_send_buffers[target_sock] + buf

    def buffer_send(self, sock):
        if sock in self.sock_send_buffers:
            bytes_sent = sock.send(self.sock_send_buffers[sock])
            self.sock_send_buffers[sock] = self.sock_send_buffers[sock][bytes_sent:]

    def flush_and_close_sock_pair(self, sock, error_msg=None):
        """ Flush any remaining send buffers to the correct socket, close the sockets, and remove
        the pair of sockets from both the client_dest_map and the sock_send_buffers dicts. """
        if error_msg:
            self.logger.error('flushing and closing pair due to error: %s' % error_msg)
        else:
            self.logger.info('Flushing and closing finished connection pair')
        with self.client_dest_map_lock:
            partner_sock = self.client_dest_map.pop(sock)
            self.client_dest_map.pop(partner_sock)
        try:
            partner_sock.send(self.sock_send_buffers.pop(partner_sock, b''))
            partner_sock.close()
            sock.send(self.sock_send_buffers.pop(sock, b''))
            sock.close()
        except Exception:
            pass

    def establish_socks5(self, sock):
        """ Speak the SOCKS5 protocol to get and return dest_host, dest_port. """
        dest_host, dest_port = None, None
        try:
            ver, nmethods, methods = sock.recv(1), sock.recv(1), sock.recv(1)
            sock.sendall(VER + METHOD)
            ver, cmd, rsv, address_type = sock.recv(1), sock.recv(1), sock.recv(1), sock.recv(1)
            dst_addr = None
            dst_port = None
            if address_type == ADDR_TYPE_IPV4:
                dst_addr, dst_port = sock.recv(4), sock.recv(2)
                dst_addr = '.'.join([str(chr_to_int(i)) for i in dst_addr])
            elif address_type == ADDR_TYPE_DOMAIN:
                addr_len = ord(sock.recv(1))
                dst_addr, dst_port = sock.recv(addr_len), sock.recv(2)
                dst_addr = ''.join([chr(chr_to_int(i)) for i in dst_addr])
            elif address_type == ADDR_TYPE_IPV6:
                dst_addr, dst_port = sock.recv(16), sock.recv(2)
                tmp_addr = []
                for i in range(len(dst_addr) // 2):
                    tmp_addr.append(chr(dst_addr[2 * i] * 256 + dst_addr[2 * i + 1]))
                dst_addr = ':'.join(tmp_addr)
            dst_port = chr_to_int(dst_port[0]) * 256 + chr_to_int(dst_port[1])
            server_sock = sock
            server_ip = ''.join([chr(int(i)) for i in socket.gethostbyname(self.host).split('.')])
            if cmd == CMD_TYPE_TCP_BIND:
                self.logger.error('TCP Bind requested, but is not supported by socks5_server')
                sock.close()
            elif cmd == CMD_TYPE_UDP:
                self.logger.error('UDP requested, but is not supported by socks5_server')
                sock.close()
            elif cmd == CMD_TYPE_CONNECT:
                sock.sendall(VER + SUCCESS + b'\x00' + b'\x01' + encode_str(server_ip +
                                        chr(self.port // 256) + chr(self.port % 256)))
                dest_host, dest_port = dst_addr, dst_port
            else:
                # Unsupport/unknown Command
                self.logger.error('Unsupported/unknown SOCKS5 command requested')
                sock.sendall(VER + UNSUPPORTED_CMD + encode_str(server_ip + chr(self.port // 256) +
                                        chr(self.port % 256)))
                sock.close()
        except KeyboardInterrupt as e:
            self.logger.error('Error in SOCKS5 establishment: %s' % e)

        return dest_host, dest_port

    def handle_connect_thread(self, client_sock, addr):
        """ Handles the establishment of the connection from the client, the socks5 protocol,
        and to the destination. Once finished, it puts the client and dest sockets into the
        self.client_dest_map, from where they are serviced by the main loop/thread. """
        self.logger.info('Connection from: %s:%d' % addr)
        client_sock.settimeout(SOCK_TIMEOUT)

        dest_host, dest_port = self.establish_socks5(client_sock)
        if None in (dest_host, dest_port):
            client_sock.close()
            return None

        self.logger.debug('Trying to connect to destination: %s:%d' % (dest_host, dest_port))
        dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest_sock.settimeout(RESEND_TIMEOUT)
        try:
            dest_sock.connect((dest_host, dest_port))
        except Exception as e:
            self.logger.error('Failed to connect to requested destination (%s:%d) due to error: %s'
                              % (dest_host, dest_port, e))
            client_sock.close()
            return None

        self.logger.debug('Connection to %s:%d established' % (dest_host, dest_port))

        # From this point on, we'll be doing nonblocking io on the sockets
        client_sock.settimeout(RESEND_TIMEOUT)
        client_sock.setblocking(0)
        dest_sock.setblocking(0)

        with self.client_dest_map_lock:
            self.client_dest_map[client_sock] = dest_sock
            self.client_dest_map[dest_sock] = client_sock
        self.logger.info('SOCKS5 proxy from %s:%d to %s:%d established' %
                         (addr[0], addr[1], dest_host, dest_port))

    def accept_connection(self):
        (client, addr) = self.server_sock.accept()
        t = threading.Thread(target=self.handle_connect_thread, args=(client, addr))
        t.daemon = True
        t.start()

    def serve_forever(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(self.backlog)
        self.logger.info('Serving on %s:%d' % (self.host, self.port))

        while True:
            connected_sockets = list(self.client_dest_map.keys())
            in_socks = [self.server_sock] + connected_sockets
            out_socks = connected_sockets
            in_ready, out_ready, err_ready = select.select(in_socks, out_socks, [], 0.1)

            for sock in in_ready:
                if sock == self.server_sock:
                    self.accept_connection()
                else:
                    try:
                        self.buffer_receive(sock)
                    except Exception as e:
                        self.flush_and_close_sock_pair(sock, str(e))

            for sock in out_ready:
                try:
                    self.buffer_send(sock)
                except Exception:
                    self.flush_and_close_sock_pair(sock, str(e))

            for sock in err_ready:
                if sock == self.server_sock:
                    self.logger.critical('Error in server socket; closing down')
                    for c in connected_socks:
                        c.close()
                    self.server_sock.close()
                    sys.exit(1)
                else:
                    self.flush_and_close_sock_pair(sock, 'Unknown socket error')


def main(args):
    logger = make_logger(log_path=args.log_path, log_level_str=args.log_level)
    socks5_server = Socks5Server(args.host, args.port, logger)
    socks5_server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--host', action='store', default='',
                        help='IP/Hostname to serve on', type=str)
    parser.add_argument('-p', '--port', action='store', default=1080,
                        help='Port to serve on', type=int)
    parser.add_argument('--log-path', action='store', default=None,
                        help='DEBUG, INFO, WARNING, ERROR, or CRITICAL', type=str)
    parser.add_argument('--log-level', action='store', default='INFO',
                        help='Log file path', type=str)
    args = parser.parse_args()

    main(args)

