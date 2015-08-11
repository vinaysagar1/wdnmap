/*
    Copyright (C) 2015  vinay sagar. 
    This implements netmap with zero copy on a wireless device driver

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

/* This has support for netmap packet handling. 
 * This will forward the packets to user space with zerocopy 
 */

#include <net/netmap.h>
#include <netmap/netmap_kern.h>

#define NUM_SKB_POOL 1024
#define NUM_SKB_POOL1 1000
#define NUM_TX_DESC 51
#define NUM_RX_DESC 256

#define NMAP_BUF_SIZE 2048

#define NBBY 8
#define FALSE 0
#define TRUE 1

struct wd_nmap_info {
	bool wd_nmap_enable;
	struct net_device *dev;
	int	wd_cur_rx;
	struct sk_buff_head wd_nmap_rxq;
};

extern bool    wd_nmap_support;
extern u8*     (*wd_nmap_alloc)(int, void **) ;
extern void    (*wd_nmap_free)(void *) ;

int alloc_count = 0, free_count = 0;

struct wd_nmap_ctx {
    int idx;
    struct netmap_slot *slot;
};

struct slot_info {
    uint16_t offset;
    void    *skb;
}__attribute__((packed));

uint8_t  nmap_bitmap[NUM_SKB_POOL/NBBY];
int      nxtfree_idx = 0;

#define BITMAP_GET_INTPOS(idx) (idx/(NBBY))
#define BITMAP_GET_BITPOS(idx) (idx%(NBBY))

static inline int get_free_idx(void)
{
    int cnt = 0;
    for (cnt = 0; cnt < NUM_SKB_POOL; cnt ++)
    {
        int byte = BITMAP_GET_INTPOS(nxtfree_idx);
        int bit  = BITMAP_GET_BITPOS(nxtfree_idx);

        if ((nmap_bitmap[byte] & (1<<bit)) == 0)
        {
            nmap_bitmap[byte] |= (1<<bit);
            return nxtfree_idx;
        }
        nxtfree_idx++;
        if (nxtfree_idx == NUM_SKB_POOL)
            printk ("%s: nmap buffers roll over\n",__func__);
        nxtfree_idx %= NUM_SKB_POOL;
    }
    return -1;
}

struct netmap_adapter *na_pool = NULL;
uint8_t* netmap_alloc(int size, void **priv)
{
    int idx;

    if (size > NMAP_BUF_SIZE)
        return NULL;

    if (na_pool == NULL)
        return NULL;

    if ((idx = get_free_idx()) != -1)
    {
        struct netmap_ring *ring = na_pool->rx_rings[1].ring;
        struct wd_nmap_ctx *ctx = (struct wd_nmap_ctx*) kmalloc(sizeof(struct wd_nmap_ctx),GFP_DMA);
        if (!ctx)
        {
            /* free up the slot */
            int byte = BITMAP_GET_INTPOS(idx);
            int bit  = BITMAP_GET_BITPOS(idx);
            printk ("%s: error allocating skb\n",__func__);
            nmap_bitmap[byte] &= ~(1<<bit);
            return NULL;
        }
        ctx->slot = &ring->slot[idx];
        ctx->idx = idx;
        *priv = (void *)ctx;
        alloc_count ++;
        return NMB(na_pool, &ring->slot[idx]);
    }
    printk ("%s: error allocating skb -- 2\n",__func__);
    return NULL;
}

void netmap_free(void *ctx)
{
    struct wd_nmap_ctx *nmap_ctx = (struct wd_nmap_ctx*)ctx;
    int byte,bit;

    byte = BITMAP_GET_INTPOS(nmap_ctx->idx);
    bit  = BITMAP_GET_BITPOS(nmap_ctx->idx);
    nmap_bitmap[byte] &= ~(1<<bit);
    free_count ++;
    kfree(ctx);
}

static int wd_netmap_open(struct wd_nmap_info *wd_info)
{
    skb_queue_head_init(&wd_info->wd_nmap_rxq);
    wd_info->wd_nmap_enable = TRUE;
    wd_nmap_alloc = &netmap_alloc;
    wd_nmap_free = &netmap_free;
    memset (nmap_bitmap,0,NUM_SKB_POOL/NBBY);
    wd_info->wd_cur_rx = 0;
    //wd_nmap_support = TRUE;
    return 1;
}

static int wd_netmap_close(struct wd_nmap_info *wd)
{
    skb_queue_purge(&wd->wd_nmap_rxq);
    wd->wd_nmap_enable = FALSE;
    wd_nmap_support = FALSE;
    return 1;
}

#define WD_INFO(ifp) (struct wd_nmap_info*)netdev_priv(ifp)
/* Reg function to register / enable netmap on the netdevice */
static int wd_netmap_reg(struct netmap_adapter *na, int onoff)
{
    struct net_device *ifp = na->ifp;
    struct wd_nmap_info *wd = WD_INFO(ifp);
    int error = 0;

    rtnl_lock();
    /* close the rx skb queue destined for stack */
    wd_netmap_close(wd);

    if (netif_running(ifp))
                sample_stop(ifp);

 
    if (onoff)
    {
        if (wd_netmap_open(wd) < 0) {
            goto fail;
        }
        if (na_pool == NULL)
            na_pool = na;
	nm_set_native_flags(na);
    }
    else 
    {
fail:
        nm_clear_native_flags(na);
        error = wd_netmap_close(wd) ? EINVAL : 0;
    }
    if (netif_running(ifp))
                sample_open(ifp);

    rtnl_unlock();
    return (error);
}

/* tx init ring buffer */
static int wd_netmap_txinit(struct wd_nmap_info *wd)
{
    struct netmap_adapter *na = NA(wd->dev);
    netmap_reset(na, NR_TX, 0, 0);
    return 1;
}

/* rx init ring buffer */
static  int wd_netmap_rxinit(struct wd_nmap_info *wd)
{
    struct netmap_adapter *na = NA(wd->dev);
    struct netmap_slot *slot;

    if (!nm_native_on(na))
	return 0;

    slot = netmap_reset(na, NR_RX, 0, 0);
    if (!slot)
        return 0;  /* XXX cannot happen */

    return 1;
}


/* txsync --> tx is not needed dummy fn */
static int wd_netmap_txsync(struct netmap_kring *kring, int flags)
{
    return 0;
}

/* rxsync */
static int wd_netmap_rxsync(struct netmap_kring *kring, int flags)
{
    struct netmap_adapter *na = kring->na;
    struct net_device *ifp = na->ifp;
    struct wd_nmap_info *wd = WD_INFO(ifp);
    struct netmap_ring *ring = kring->ring;
    u_int nm_i; /* index into the netmap ring */
    u_int nic_i;    /* index into the NIC ring */
    u_int n;
    u_int const lim = kring->nkr_num_slots - 1;
    u_int const head = nm_rxsync_prologue(kring);
    int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

    if (!netif_carrier_ok(ifp))
        return 0;

    if (head > lim)
        return netmap_ring_reinit(kring);

    rmb();

     /*
      * First part: import newly received packets.
      */
    if (netmap_no_pendintr || force_update) 
    {
        uint16_t slot_flags = kring->nkr_slot_flags;
        uint32_t stop_i = nm_prev(kring->nr_hwcur, lim);
        int cnt = 0;
                
        nic_i = wd->wd_cur_rx; /* next pkt to check */
        nm_i = netmap_idx_n2k(kring, nic_i);

        while (nm_i != stop_i) 
        {
            int total_len;
            struct sk_buff *skb = skb_dequeue(&wd->wd_nmap_rxq);
            void *vaddr;
            struct netmap_slot *slot = &ring->slot[nm_i];

            if (skb == NULL)
	    {
                break;
	    }
            if (skb->wd_netmap)
            {
                /* zero copy pkt transfer to the user space */
                struct netmap_slot *skb_slot;
                struct wd_nmap_ctx *skb_ctx = (struct wd_nmap_ctx*) skb->wd_nmap_ctx;
                struct slot_info old_info;
                
     		LOG_MSG("%s: zerocopy called\n",__func__);
                total_len = skb->len;
                skb_slot = skb_ctx->slot;

                old_info.offset  =  (unsigned char *)eth_hdr(skb) - skb->head;
                old_info.skb = (void *)skb; 

                slot->old_buf = slot->buf_idx;
                slot->buf_idx = skb_slot->buf_idx;
                memcpy(&slot->ptr,&old_info,sizeof(old_info));

                ring->slot[nm_i].len = total_len;
                ring->slot[nm_i].flags = slot_flags;

                nm_i = nm_next(nm_i, lim);
                nic_i = nm_next(nic_i, lim);
                cnt ++;
            }
            else
            {
                cnt ++;
                total_len = skb->len;
                ring->slot[nm_i].len = total_len;
                ring->slot[nm_i].flags = slot_flags;
                vaddr = NMB(na, slot);
                memcpy ((char *)vaddr, skb->data, total_len);
                nm_i = nm_next(nm_i, lim);
                nic_i = nm_next(nic_i, lim);
                kfree_skb(skb);
                slot->ptr = 0;
            }
        }
        if (cnt)
        {
            wd->wd_cur_rx = nic_i;
            kring->nr_hwtail = nm_i;
            kring->nr_kflags &= ~NKR_PENDINTR;
        }
    }

    /* free up all the buffers used up by the user space */
    nm_i = kring->nr_hwcur;
    if (nm_i != head) 
    {
        nic_i = netmap_idx_k2n(kring, nm_i);
        for (n = 0; nm_i != head; n++) 
        {
            struct netmap_slot *slot = &ring->slot[nm_i];
            void *addr = NMB(na, slot);

            if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
                goto ring_reset;

            if (slot->flags & NS_BUF_CHANGED) 
            {
                /* buffer has changed, reload map */
                printk ("%s: Err shd not happen!\n",__func__);
		slot->flags &= ~NS_BUF_CHANGED;
            }

            if (slot->ptr != 0) 
            {
                struct slot_info old_info;
                memcpy (&old_info, &slot->ptr, sizeof(old_info));
                slot->buf_idx = slot->old_buf;
                kfree_skb(old_info.skb);
                slot->ptr = 0;
                //printk (" reapedbuf sign %x:%x:%x\n",(unsigned int)buf[0],(unsigned int)buf[1],(unsigned int)buf[2]);
            }
            nm_i = nm_next(nm_i, lim);
            nic_i = nm_next(nic_i, lim);
        }

        kring->nr_hwcur = head;
        wmb(); // XXX needed ?
    }

    /* tell userspace that there might be new packets */
    nm_rxsync_finalize(kring);
    return 0;

ring_reset:
    return netmap_ring_reinit(kring);
}

/* Attach function  initializes the na stuct and calls the register */
static void wd_netmap_attach(struct wd_nmap_info *wd_info)
{
    struct netmap_adapter na;

    bzero(&na, sizeof(na));

    na.ifp = wd_info->dev;
    na.num_tx_desc = 0;
    na.num_rx_desc = NUM_SKB_POOL;
    na.nm_txsync   = wd_netmap_txsync;
    na.nm_rxsync   = wd_netmap_rxsync;
    na.nm_register = wd_netmap_reg;
    na.num_tx_rings = 1;
    na.num_rx_rings = 2;
    netmap_attach(&na);
}
