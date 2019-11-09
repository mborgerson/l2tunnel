Layer 2 Tunnel
==============

[![Build Status](https://travis-ci.org/mborgerson/l2tunnel.svg?branch=master)](https://travis-ci.org/mborgerson/l2tunnel)

This is a simple utility to tunnel link-layer traffic from a device accessible
through a local network interface to a remote host via UDP to enable a basic
VLAN.

The intended use case for this utility is to enable game consoles which support
LAN network play (e.g. Xbox) to play on the Internet by creating a virtual LAN.
To the console, it will appear as if other consoles are connected on the LAN.

Pre-built Binaries
------------------
Download the latest pre-built release [here](https://github.com/mborgerson/l2tunnel/releases).

How to Build
------------

### Windows

```sh
# Install mingw toolchain and download npcap SDK
wget https://nmap.org/npcap/dist/npcap-sdk-1.04.zip
unzip -dnpcap npcap-sdk-1.04.zip

# Compile
x86_64-w64-mingw32-gcc-7.3-win32 -o l2tunnel.exe -I npcap/Include/ \
    -L npcap/Lib/x64 l2tunnel.c -l wpcap -lws2_32
```

### macOS

```sh
# Compile
gcc -o l2tunnel l2tunnel.c -lpcap
```

Additionally, once you have built the program, you will need to run it as root
in order to permit it raw network access. You can apply "setuid" on the binary
so it is always run as root, regardless of the user.

```sh
# Setuid to permit raw net access
sudo chown root l2tunnel
sudo chmod u+s l2tunnel
```

### Ubuntu/Debian

```sh
# Install libpcap
sudo apt install libpcap-dev

# Compile
gcc -o l2tunnel l2tunnel.c -lpcap
```

Additionally, once you have built the program, you will need to either run it as
root (not recommended) or set a capability on the executable to permit it raw
network access. This can be done via:

```sh
# Set capabilities on the executable to permit raw net access
sudo setcap cap_net_raw,cap_net_admin=eip l2tunnel
```

Prerequisites
-------------
This utility depends on libpcap to send and receive raw network traffic through
a network interface.

### Windows

Download and install the latest "Npcap installer" [available
here](https://nmap.org/npcap/).

### macOS

libpcap should be pre-installed.

### Linux

Install libpcap-dev via:

```sh
sudo apt install libpcap-dev
```

How to Use
----------
The ideal setup is having the device you want to forward traffic to connected
via Ethernet directly to a network port on your machine, or through a switch.

First, list the available network interfaces on the system:

```sh
$ ./l2tunnel list
device 0: vboxnet0
- flags: PCAP_IF_UP PCAP_IF_RUNNING
device 1: wlp0s20f3
- flags: PCAP_IF_UP PCAP_IF_RUNNING
[trimmed]
device 2: enp0s31f6
- flags: PCAP_IF_UP PCAP_IF_RUNNING
[ additional interfaces trimmed ]
```

There are 3 interfaces shown here. The device I want to forward traffic for in
this example is connected directly to interface number 2, `enp0s31f6`.

Next, we need to know the MAC address of the device in order to isolate its
traffic from any other traffic on the network.

The MAC address can usually be found on the device itself or within a system
configuration menu. Alternatively, if you do not know the MAC address of the
device, we can monitor all traffic on the interface to determine the MAC
address.

```sh
$ ./l2tunnel discover enp0s31f6
00:0d:3a:38:ac:2e to ff:ff:ff:ff:ff:ff
```

We see that a broadcast packet was sent by the device, and the source MAC
address is `00:0d:3a:38:ac:2e`.

Finally, we are ready to begin tunneling. We will tunnel traffic on local
interface `enp0s31f6` to/from our device with MAC address `00:0d:3a:38:ac:2e` to
a remote host 1.2.3.4 via UDP port 1337 and receive traffic that will be
forwarded back to the via via local UDP port 1337:

```sh
#                   (iface)   (mac addr)        (local addr) (remote addr)
$ ./l2tunnel tunnel enp0s31f6 00:0d:3a:38:ac:2e 0.0.0.0 1337 1.2.3.4 1337
```

Virtual LAN
-----------
To create a simple VLAN (emulating a simple network hub), the `hub.py`
script can be used. This script will listen on a specified UDP port for packets.
Upon arrival of a packet from a given host, it will be forwarded to any other
host which has also sent a packet.

To connect multiple consoles over the Internet, a hub should first be created.
Then each user can start a tunnel which forwards traffic to the hub.

Connecting other Applications
-----------------------------

### XQEMU

Full disclosure: as a maintainer of [XQEMU](https://xqemu.com), an original Xbox
emulator, my main motivation for this project was to allow both original Xboxes
and instances of XQEMU to communicate harmoniously across the Internet.

XQEMU can connect directly with a tunnel or through VLAN created via hub.py
easily by adding the following command line option:

```
-net nic -net socket,udp=1.2.3.4:1337,localaddr=0.0.0.0:1337
```

Like the above `l2tunnel` example, here 1.2.3.4:1337 is the IP/Port of the vlan
hub and the localaddr option specifies that XQEMU should listen on port 1337 for
traffic from the VLAN.