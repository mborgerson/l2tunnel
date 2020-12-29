/*
 * Copyright (C) 2019  Matt Borgerson
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#define DEBUG 1

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef WIN32
    #include <pcap/pcap.h>
    #include <winsock.h>
#else
    #include <netinet/if_ether.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <sys/time.h>
    #include <sys/types.h>
    #include <pcap/pcap.h>
    #include <unistd.h>
#endif

pcap_t *p;
char err[PCAP_ERRBUF_SIZE];
const u_char *pcap_packet_buf;
size_t pcap_packet_len;

#define LOG_ERROR(...) fprintf(stderr, "error: " __VA_ARGS__)
#ifdef DEBUG
#define LOG_DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define LOG_DEBUG(...)
#endif

/*
 * Get all available network interfaces
 */
static void list_available_interfaces(void)
{
    int status;
    pcap_if_t *alldevs, *iter;
    int i;

    alldevs = NULL;
    status = pcap_findalldevs(&alldevs, err);
    if (status != 0) {
        LOG_ERROR("unable to list devs (%s)\n", err);
    }

    for (i=0, iter=alldevs; iter != NULL; i++, iter=iter->next) {
        printf("device %d: %s\n", i, iter->name);

        if (iter->description) {
            printf("- description: %s\n", iter->description);
        }

        printf("- flags:");
        if (iter->flags & PCAP_IF_LOOPBACK) printf(" PCAP_IF_LOOPBACK");
        if (iter->flags & PCAP_IF_UP) printf(" PCAP_IF_UP");
        if (iter->flags & PCAP_IF_RUNNING) printf(" PCAP_IF_RUNNING");
        printf("\n");

        /* FIXME: Print addresses */
    }

    pcap_freealldevs(alldevs);
}

/*
 * Pretty-print a MAC address into a buffer as 00:00:00:00:00:00
 */
static int fmt_mac_addr(char *buf, size_t len, const uint8_t mac[6])
{
    return snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*
 * Parse a 00:00:00:00:00:00 address into a binary representation.
 */
static int parse_mac_addr(uint8_t mac[6], const char *in)
{
    int status;
    unsigned int tmp[6];

    /* %02hhx is not universally supported, so sscanf to ints first */
    status = sscanf(in, "%02x:%02x:%02x:%02x:%02x:%02x",
        &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
    if (status != 6) return -1;

    mac[0] = (uint8_t)tmp[0];
    mac[1] = (uint8_t)tmp[1];
    mac[2] = (uint8_t)tmp[2];
    mac[3] = (uint8_t)tmp[3];
    mac[4] = (uint8_t)tmp[4];
    mac[5] = (uint8_t)tmp[5];

    return 0;
}

/*
 * Begin listening on an interface
 */
static pcap_t *setup_pcap(const char *if_name)
{
    const int promisc = 1;
    int status;

    /* Open the device */
    p = pcap_open_live(if_name, 65536, promisc, 1, err);
    if (p == NULL) {
        LOG_ERROR("failed to open '%s' for capture (%s)\n", if_name, err);
        exit(1);
    }

    /* Set data link */
    status = pcap_set_datalink(p, DLT_EN10MB);
    if (status != 0) {
        LOG_ERROR("failed to set data link format to DLT_EN10MB\n");
        exit(1);
    }

#ifdef WIN32
    pcap_setmintocopy(p, 40);
#endif

    return p;
}

/*
 * Filter traffic for a specific MAC address
 */
static int filter_by_mac(const uint8_t mac[6], bool flt_by_src)
{
    struct bpf_program fp;
    int status;

    char filter_str[32];
    char mac_str[18];

    return 0;


    fmt_mac_addr(mac_str, sizeof(mac_str), mac);

    if (flt_by_src) {
        snprintf(filter_str, sizeof(filter_str), "ether src %s", mac_str);
    } else {
        snprintf(filter_str, sizeof(filter_str),
            "ether dst %s or ether dst ff:ff:ff:ff:ff:ff", mac_str);
    }

    status = pcap_compile(p, &fp, filter_str, 1, PCAP_NETMASK_UNKNOWN);
    if (status != 0) {
        LOG_ERROR("failed to compile filter\n");
        exit(1);
    }

    status = pcap_setfilter(p, &fp);
    if (status != 0) {
        LOG_ERROR("failed to set filter\n");
        exit(1);
    }

    return 0;
}

/*
 * Discover devices on the network
 *
 * Listen for traffic on the network and print out when a unique
 * MAC address is discovered
 */
static void discover_devices(void)
{
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    int status;

    while (1) {
        status = pcap_next_ex(p, &pkt_header, &pkt_data);
        if (status == 1) {
            /* Success */
        } else if (status == 0) {
            /* Timeout */
            continue;
        } else if (status == -1) {
            LOG_ERROR("pcap_next_ex error: %s\n", pcap_geterr(p));
            exit(1);
            return;
        } else {
            LOG_ERROR("unknown error %d\n", status);
            exit(1);
            return;
        }

        /* Assume we at least get an ethernet header */
        assert(pkt_header->len >= 14);

        /* Verify that we captured the entire packet */
        assert(pkt_header->caplen == pkt_header->len);

        char to[24], from[24];
        fmt_mac_addr(to, sizeof(to), &pkt_data[0]);
        fmt_mac_addr(from, sizeof(from), &pkt_data[6]);

        printf("%s to %s\n", from, to);
        fflush(stdout);
    }
}

/*
 * Monitor traffic from a specific MAC address
 */
static void capture_traffic_from(const uint8_t filter_mac[6], bool flt_by_src)
{
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    const uint8_t *pkt_src;
    const uint8_t *pkt_dest;
    const char *bcast = "\xff\xff\xff\xff\xff\xff";
    int status;

    pcap_packet_len = 0;
    pcap_packet_buf = NULL;

    status = pcap_next_ex(p, &pkt_header, &pkt_data);
    if (status == 1) {
        /* Success */
    } else if (status == 0) {
        /* Timeout */
        return;
    } else if (status == -1) {
        LOG_ERROR("pcap_next_ex error: %s\n", pcap_geterr(p));
        exit(1);
        return;
    } else {
        LOG_ERROR("unknown error %d\n", status);
        exit(1);
        return;
    }

    /* Assume we at least get an ethernet header */
    assert(pkt_header->len >= 14);

    /* Verify that we captured the entire packet */
    assert(pkt_header->caplen == pkt_header->len);

    if (flt_by_src) {
        pkt_src = &pkt_data[6];
        if (memcmp(pkt_src, filter_mac, 6) != 0) {
            /* Not our packet */
            return;
        }
    } else {
        pkt_dest = &pkt_data[0];
        if (memcmp(pkt_dest, filter_mac, 6) != 0 &&
            memcmp(pkt_dest, bcast, 6) != 0) {
            /* Not our packet */
            return;
        }
    }

    char to[24], from[24];
    fmt_mac_addr(to, sizeof(to), &pkt_data[0]);
    fmt_mac_addr(from, sizeof(from), &pkt_data[6]);
    LOG_DEBUG("%s to %s\n", from, to);

    pcap_packet_buf = pkt_data;
    pcap_packet_len = pkt_header->len;
}

/*
 * Create a local UDP socket for sending/recieving frames
 */
static int setup_local_socket(const struct sockaddr_in *local_addr)
{
    int sockfd;
    int status;

    /* Create socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        LOG_ERROR("failed to create socket\n");
        exit(1);
    }

    status = bind(sockfd,
        (const struct sockaddr *)local_addr, sizeof(struct sockaddr_in));
    if (status < 0) {
        LOG_ERROR("failed to bind\n");
        exit(1);
    }

    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);

    status = getsockname(sockfd, (struct sockaddr *)&sin, &len);
    if (status == -1) {
        LOG_ERROR("getsockname failed\n");
        exit(1);
    }

    printf("Listening on %s:%d\n",
        inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
    fflush(stdout);

    return sockfd;
}

/*
 * Program entry
 */
int main(int argc, char *argv[])
{
    char *if_name;
    bool flt_by_src;
    char *flt_str;
    uint8_t mac[6];
    char *mac_str;
    char *laddr_str;
    char *lport_str;
    unsigned short lport;
    char *raddr_str;
    char *rport_str;
    unsigned short rport;
    struct sockaddr_in local_addr, remote_addr, recv_addr;
#ifdef WIN32
    HANDLE pcapfd;
    HANDLE sockevent;
    int sockfd;
#else
    fd_set fds;
    int pcapfd, sockfd;
    int max_fd;
    struct timeval tv;
#endif
    uint8_t *packet_buf;
    int retval;
    socklen_t addr_length;
    ssize_t n;

    if (argc < 2) {
        goto usage;
    } else if (!strcmp(argv[1], "list")) {
        list_available_interfaces();
        exit(0);
    } else if (!strcmp(argv[1], "discover")) {
        if (argc < 3) goto usage;
        if_name = argv[2];
        setup_pcap(if_name);
        discover_devices();
        exit(0);
    } else if (!strcmp(argv[1], "tunnel")) {
        if (argc < 9) goto usage;
        if_name = argv[2];
        flt_str = argv[3];
        mac_str = argv[4];
        laddr_str = argv[5];
        lport_str = argv[6];
        raddr_str = argv[7];
        rport_str = argv[8];
    } else {
        goto usage;
    }

#ifdef WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        LOG_ERROR("WSAStartup failed!\n");
        exit(1);
    }
#endif

    /* Set up local address */
    retval = sscanf(lport_str, "%hu", &lport);
    if (retval != 1) {
        LOG_ERROR("invalid local port\n");
        exit(1);
    }
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(lport);
#ifdef WIN32
    local_addr.sin_addr.s_addr = inet_addr(laddr_str);
    // FIXME: Add error checking
#else
    if (inet_aton(laddr_str, &local_addr.sin_addr) == 0) {
        LOG_ERROR("invalid local IP address\n");
        exit(1);
    }
#endif

    /* Set up remote address */
    retval = sscanf(rport_str, "%hu", &rport);
    if (retval != 1) {
        LOG_ERROR("invalid remote port\n");
        exit(1);
    }
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(rport);
#ifdef WIN32
    remote_addr.sin_addr.s_addr = inet_addr(raddr_str);
    // FIXME: Add error cehcking
#else
    if (inet_aton(raddr_str, &remote_addr.sin_addr) == 0) {
        LOG_ERROR("invalid remote IP address\n");
        exit(1);
    }
#endif

    if (strcmp(flt_str, "-s") == 0) {
        flt_by_src = true;
    } else if (strcmp(flt_str, "-d") == 0) {
        flt_by_src = false;
    } else {
        LOG_ERROR("specify -s or -d for MAC filtering\n");
        exit(1);
    }

    if (parse_mac_addr(mac, mac_str)) {
        LOG_ERROR("invalid MAC address\n");
        exit(1);
    }

    setup_pcap(if_name);
    filter_by_mac(mac, flt_by_src);
    sockfd = setup_local_socket(&local_addr);

#ifdef WIN32
    pcapfd = pcap_getevent(p);
    sockevent = WSACreateEvent();
    WSAEventSelect(sockfd, sockevent, FD_READ);
#else
    pcapfd = pcap_get_selectable_fd(p);
    assert(pcapfd >= 0);
    max_fd = pcapfd > sockfd ? pcapfd : sockfd;
#endif

    /* Allocate a buffer to recieve packets from the socket */
    packet_buf = malloc(65536);
    assert(packet_buf != NULL);

    while (1) {
#ifndef WIN32
        FD_ZERO(&fds);
        FD_SET(pcapfd, &fds);
        FD_SET(sockfd, &fds);

        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = 10;
        tv.tv_usec = 0;

        retval = select(max_fd+1, &fds, NULL, NULL, &tv);
        if (retval == -1) {
            LOG_ERROR("select failed\n");
            exit(1);
        } else if (retval == 0) {
            /* Timeout */
            continue;
        }
#else
        HANDLE handles[2] = {sockevent, pcapfd};
        DWORD result = WaitForMultipleObjects(2, handles, FALSE, 5000);
#endif

        /*
         * Handle data from pcap
         */
#ifdef WIN32
        if (result == WAIT_OBJECT_0+1) {
#else
        if (FD_ISSET(pcapfd, &fds)) {
#endif
            LOG_DEBUG("packet waiting from pcap\n");
            capture_traffic_from(mac, flt_by_src);

            /* Send this packet to the remote */
            if (pcap_packet_len > 0) {
                LOG_DEBUG("forwarding to %s:%s\n", raddr_str, rport_str);
                sendto(sockfd,
                    (void *)pcap_packet_buf, pcap_packet_len,
                    0,
                    (const struct sockaddr *)&remote_addr, sizeof(remote_addr));
            }
        }

        /*
         * Handle packet from socket
         */
#ifdef WIN32
        else if (result == (WAIT_OBJECT_0)) {
            WSANETWORKEVENTS NetworkEvents;
            WSAEnumNetworkEvents(sockfd, sockevent, &NetworkEvents);
            if (NetworkEvents.lNetworkEvents == FD_READ) {
#else
        if (FD_ISSET(sockfd, &fds)) {
#endif
            LOG_DEBUG("packet waiting from socket\n");

            /* Recieve packet from the socket */
            addr_length = sizeof(recv_addr);
            n = recvfrom(sockfd, (void*)packet_buf, 65536,
#ifdef WIN32
                0,
#else
                MSG_WAITALL,
#endif
                (struct sockaddr *)&recv_addr, &addr_length);
            if (n < 0) {
                LOG_DEBUG("recvfrom returned < 0\n");
#ifdef WIN32
                LOG_DEBUG("WSA Error = %d\n", WSAGetLastError());
#endif
                continue;
            }

            assert(recv_addr.sin_family == AF_INET);
            LOG_DEBUG("received %d bytes from %s:%d\n", (int)n,
                inet_ntoa(recv_addr.sin_addr),
                ntohs(recv_addr.sin_port));

            /* FIXME: Verify the packet came from the expected remote and not
             * some random place
             */

            /* FIXME: Verify this is a DLT_EN10MB link-layer header type and
             * that the destination address is either multicast or our intended
             * MAC address
             */

            /* Inject this packet into the tapped interface */
            LOG_DEBUG("injecting to link!\n");
            retval = pcap_sendpacket(p, packet_buf, n);
            if (retval != 0) {
                LOG_ERROR("pcap_sendpacket failed!\n");
            }
#ifdef WIN32
        }
#endif
        }

    }

    return 0;
usage:
    fprintf(stderr, "l2tunnel version " BUILD_VERSION " (" BUILD_DATE ")\n");
    fprintf(stderr, "Copyright (c) 2019-2020 Matt Borgerson\n");
    fprintf(stderr, "usage: %s <cmd...>\n", argv[0]);
    fprintf(stderr, "\n");
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  list                    List available interfaces\n");
    fprintf(stderr, "  discover <if>           Discover MAC addresses on interface <if>\n");
    fprintf(stderr, "  tunnel   <if> -d|-s <mac> <laddr> <lport>  <raddr> <rport>\n");
    fprintf(stderr, "                          Forward datagrams sent to udp:<laddr:lport> to\n");
    fprintf(stderr, "                          <if> and packets sniffed on <if> to udp:<raddr:rport>.\n");
    fprintf(stderr, "                             -s filters traffic from <if> by source <mac>\n");
    fprintf(stderr, "                             -d filters traffic from <if> by destination <mac>\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "This free software is distributed in the hope that it will be useful,\n");
    fprintf(stderr, "but WITHOUT ANY WARRANTY. See the GNU General Public License for more details.\n");
    return 1;
}
