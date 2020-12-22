#!/usr/bin/env python
"""
Copyright (C) 2019  Matt Borgerson

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

Simple UDP Repeater
===================
This script can be used to relay UDP packets to multiple peers through a
central server. When a packet is sent by a peer to the repeater, the repeater
sends that packet to all other peers.

Peers are registered once they start sending some data to the central server.
This could be modified to have a pre-registered list, or some token-based
verification, or something.

Optionally, after a period of inactivity (not sending any data), a peer is
considered to be "disconnected," and the repeater will no longer forward any
packets to it.
"""
import socket
import argparse
import time
import struct
import logging

logging.basicConfig(format='%(message)s', level=logging.INFO)

l = logging.getLogger(__name__)

broadcast_mac = (0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
fmt_mac = lambda o: ':'.join([('%02x' % o) for o in o])

def main():
	# Parse command line arguments
	ap = argparse.ArgumentParser(description='Simple UDP relay server for one-to-many packet transmission')
	ap.add_argument('--host', default='0.0.0.0', help='interface to bind to')
	ap.add_argument('--port', '-p', type=int, default=1337, help='port to listen on')
	ap.add_argument('--timeout', '-t', type=int, default=0, help='peer inactivity timeout (0 for no timeout)')
	ap.add_argument('--switch', '-s', default=False, action='store_true', help='behave like network switch (fwd only to dest mac)')
	ap.add_argument('--verbose', '-v', default=False, action='store_true', help='enable verbose log output')
	args = ap.parse_args()

	if args.verbose:
		l.setLevel(logging.DEBUG)

	# Create datagram socket
	sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
	assert(sock != None)
	sock.bind((args.host, args.port))
	l.info('Waiting for UDP packets on %s:%d' % sock.getsockname())

	peers = {}
	macs = {}

	while True:
		# Receive packet on the interface
		data, addr = sock.recvfrom(1500)
		l.debug('Received %d bytes from %s:' % (len(data), addr))
		if len(data) < 12: continue
		now = time.time()

		dest_mac = struct.unpack('6B', data[0:6])
		src_mac = struct.unpack('6B', data[6:12])
		l.debug('%s -> %s', fmt_mac(src_mac), fmt_mac(dest_mac))

		# If you wanted to, you could verify that this packet came from an
		# authorized peer. Instead, we will permit registration of peer upon
		# first packet they send.
		if addr not in peers:
			l.info('New peer %s:%d (total %d)', addr[0], addr[1], len(peers)+1)
		peers[addr] = now

		# Update MAC:HOST table
		if (src_mac in macs) and (macs[src_mac] != addr):
			l.info('Updated MAC table %s: %s:%d -> %s:%d', fmt_mac(src_mac),
				macs[src_mac][0], macs[src_mac][1],
				addr[0], addr[1])
		macs[src_mac] = addr

		# Check for timeouts
		if args.timeout > 0:
			for p in [p for p in peers if (now-peers[p] > args.timeout)]:
				l.info('Peer %s:%d has timed out', *p)
				del peers[p]

		i = 0
		if args.switch and (dest_mac != broadcast_mac):
			if dest_mac not in macs:
				l.debug('Unknown destination')
				continue
			peer = macs[dest_mac]
			if peer not in peers:
				l.debug('Peer has timed out')
				del macs[dest_mac]
				continue
			if peer == addr: continue # Don't repeat to sender
			sock.sendto(data, peer)
			i += 1
		else:
			# Repeat to all peers
			for peer in peers:
				if peer == addr: continue # Don't repeat to sender
				sock.sendto(data, peer)
				i += 1
		l.debug('Forwarded to %d peers' % i)

if __name__ == '__main__':
	main()
