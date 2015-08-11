/*
    Copyright (C) 2015  vinay sagar. 
    This implements an example device driver using netmap with 
    zero copy on a wireless device driver

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


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <net/sock.h>
#include <net/checksum.h>
#include <linux/if_ether.h>     /* For the statistics structure. */
#include <linux/if_arp.h>       /* For ARPHRD_ETHER */
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/percpu.h>
#include <net/net_namespace.h>
#include <linux/u64_stats_sync.h>
#include "../LINUX/bsd_glue.h"

int sample_open(struct net_device *dev);
int sample_stop(struct net_device *dev);
#define LOG_MSG printk
#include "wd_netmap.h"
#include "sample_netdrv.h"

#define DRIVER_NAM "sample_nmap"

static struct net_device *sample_dev = NULL;

int sample_open(struct net_device *dev) 
{ 
        struct sample_priv *tp = netdev_priv(dev);
	wd_netmap_rxinit(&tp->wd_nmap);
   	wd_netmap_txinit(&tp->wd_nmap);
   	netmap_enable_all_rings(dev);

	LOG_MSG("sample_open is called\n"); 
	return 0; 
}

int sample_stop(struct net_device *dev) 
{
   	netmap_disable_all_rings(dev);
        LOG_MSG("sample_stop is called\n");
        return 0;
}

static netdev_tx_t sample_start_xmit(struct sk_buff *skb, struct net_device *dev) 
{
        struct sample_priv *tp = netdev_priv(dev);
	struct wd_nmap_info *wd = &tp->wd_nmap;
        int count = 0;

        LOG_MSG("sample_start_xmit is called\n");

    	/* keep a copy of this in netmap list for the netmap to reap later */
    	if (wd->wd_nmap_enable)
    	{
        	struct sk_buff *nmap_skb;
        	if (skb->wd_netmap == 1)
            		nmap_skb = skb_clone(skb, GFP_ATOMIC);
        	else
        	{
        		LOG_MSG("sample_start_xmit skbcopy!\n");
                	if ((nmap_skb = skb_copy((struct sk_buff*)skb, GFP_ATOMIC)) == NULL)
                	goto out;
        	}
        	skb_queue_tail(&wd->wd_nmap_rxq,nmap_skb);
        	netmap_rx_irq(dev, 0, &count);
        	LOG_MSG("sample_start_xmit netmap rx! count %d\n",count);
    	}
        LOG_MSG("sample_start_xmit netmap rx! count %d\n",count);
out:
	dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
}

static struct net_device_stats* sample_get_stats(struct net_device *dev) 
{
	
        struct sample_priv *tp = netdev_priv(dev);
	dev->stats.rx_packets = tp->stats.packets;
	dev->stats.tx_packets = tp->stats.packets;
        return &dev->stats;
}

static const struct net_device_ops sample_ops = {
        .ndo_start_xmit= sample_start_xmit,
        .ndo_get_stats = sample_get_stats,
	.ndo_open = sample_open,
	.ndo_stop = sample_stop,
};

void sample_netdev_setup(struct net_device *dev)
{
        dev->mtu                = 64 * 1024;
        dev->hard_header_len    = ETH_HLEN;     /* 14   */
        dev->addr_len           = ETH_ALEN;     /* 6    */
        dev->tx_queue_len       = 0;
        dev->type               = ARPHRD_ETHER;      /* 0x0001*/
        //dev->flags              = IFF_LOOPBACK;
        netif_keep_dst(dev);
        dev->hw_features        = NETIF_F_ALL_TSO | NETIF_F_UFO;
        dev->features           = NETIF_F_SG | NETIF_F_FRAGLIST
                | NETIF_F_ALL_TSO
                | NETIF_F_UFO
                | NETIF_F_HW_CSUM
                | NETIF_F_RXCSUM
                | NETIF_F_SCTP_CSUM
                | NETIF_F_HIGHDMA
                | NETIF_F_LLTX
                | NETIF_F_NETNS_LOCAL
                | NETIF_F_VLAN_CHALLENGED;
                //| NETIF_F_LOOPBACK;
        dev->netdev_ops = &sample_ops;
        dev->hard_header_len = 14;
}

int init_module(void)
{
        struct net_device *dev;
        struct sample_priv *tp;

        /* 
         * alloc_etherdev allocates memory for dev and dev->priv.
         * dev->priv shall have sizeof(struct sample_priv) memory
         * allocated.
         */
        dev = alloc_netdev(sizeof(struct sample_priv),DRIVER_NAM,NET_NAME_UNKNOWN,sample_netdev_setup);
        if(!dev) {
               LOG_MSG("Could not allocate etherdev\n");
               return -1;
        }
	
        tp = netdev_priv(dev);
	tp->wd_nmap.dev = dev;
	wd_netmap_attach(&tp->wd_nmap);
        tp->val = 1;


        /* register the device */
        if(register_netdev(dev)) {
               LOG_MSG("Could not register netdevice\n");
               goto cleanup0;
        }
	sample_dev = dev;
	wd_netmap_attach(&tp->wd_nmap);
        return 0;
cleanup0:
	free_netdev(dev);
 	return -1;
}


void cleanup_module(void) 
{
        struct sample_priv *tp;

	if (sample_dev == NULL)
		return;

	netmap_detach(sample_dev);
        tp = netdev_priv(sample_dev);
	tp->val = 0;
        unregister_netdev(sample_dev);
	free_netdev(sample_dev);
        return;
}
