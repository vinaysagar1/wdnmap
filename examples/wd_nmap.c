/*
    Copyright (C) 2015  vinay sagar. 
    This is a test program for netmap 
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
*/


#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include <ctype.h>	// isprint()
#include <unistd.h>	// sysconf()
#include <poll.h>
#include <arpa/inet.h>	/* ntohs */
#include <sys/sysctl.h>	/* sysctl */
#include <ifaddrs.h>	/* getifaddrs */
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>      /* ether_aton */
#include <linux/if_packet.h>    /* sockaddr_ll */
#include <signal.h>
#include <string.h>


int do_abort = 0;

struct pkt {
    struct ether_header eh;
    struct ip ip;
    struct udphdr udp;
    uint8_t body[2048]; // XXX hardwired
} __attribute__((__packed__));

static void
sigint_h(int sig)
{
    (void)sig;  /* UNUSED */
    do_abort = 1;
    signal(SIGINT, SIG_DFL);
}

static inline char* ether_sprintf(char ether_addr[])
{
    static char ether_mac[30];
    snprintf(ether_mac,30,"%0x:%0x:%0x:%0x:%0x:%0x",ether_addr[0],ether_addr[1],ether_addr[2],ether_addr[3],ether_addr[4],ether_addr[5]);
    return ether_mac;
}

struct slot_info {
    uint16_t offset;
    void    *skb;
}__attribute__((packed));

int main()
{
    char regif[20] = "netmap:sample_nmap";
    struct nm_desc *nm;
    struct pollfd pollfd;
    int cnt = 0;

    nm = nm_open(regif, NULL, 0, NULL);

    if (!nm)
    {
        printf ("Error opening netmap on %s:%s\n",__func__,regif);
        return -1;
    }
    
    /* main loop */
    signal(SIGINT, sigint_h);
    memset(&pollfd, 0 , sizeof(struct pollfd));
    pollfd.fd = nm->fd;
    pollfd.events |= POLLIN;

    while (!do_abort)
    {
        struct netmap_ring *rxring, *bufring;
        int ret = 1;
        //u_int m = 0;, si = nm->first_rx_ring+1;
        int tot_slot,j;

        ret = poll(&pollfd, 1, 25000);
        if (ret <= 0)
        {
	    printf ("error in poll %d\n",ret);
            continue;
        }
        ioctl(pollfd.fd, NIOCRXSYNC, NULL);

        rxring = NETMAP_RXRING(nm->nifp, nm->last_rx_ring);
        bufring = NETMAP_RXRING(nm->nifp, nm->first_rx_ring);
        if (nm_ring_empty(rxring)) 
        {
	    printf ("ring is empty\n");
            continue;
        }
        tot_slot = nm_ring_space(rxring);
        j = rxring->cur;
        while (tot_slot--)
        {
            struct netmap_slot *rs = &rxring->slot[j];
            char *rxbuf = NETMAP_BUF(bufring, rs->buf_idx);
            struct slot_info sinfo;
            struct pkt *pkt;
	    char   *val;

            memcpy (&sinfo, &rs->ptr, sizeof (struct slot_info));
            pkt = (struct pkt*)(rxbuf + sinfo.offset);
	    val = (char *)pkt;
 	    printf ("first pkt byte %x\n",*val);
            j = nm_ring_next(rxring, j);
        }
        rxring->head = rxring->cur = j;

        cnt ++;
	printf ("%d pkts received\n",cnt);
    }
    return 0;
}
