#ifndef AI_TEST_IIP_LWIPOPTS_H
#define AI_TEST_IIP_LWIPOPTS_H

/* A deterministic, single-threaded lwIP peer for the in-memory tests. */
#define NO_SYS                          1
#define SYS_LIGHTWEIGHT_PROT            0
#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0
#define LWIP_IPV4                       1
#define LWIP_IPV6                       0
#define LWIP_ARP                        1
#define LWIP_ETHERNET                   1
#define LWIP_ICMP                       1
#define LWIP_RAW                        1
#define LWIP_UDP                        1
#define LWIP_TCP                        1
#define LWIP_DHCP                       0
#define LWIP_AUTOIP                     0
#define LWIP_IGMP                       0
#define LWIP_DNS                        0
#define LWIP_STATS                      0
#define MEM_SIZE                        (64 * 1024)
#define MEMP_NUM_PBUF                   64
#define PBUF_POOL_SIZE                  64
#define MEMP_NUM_TCP_PCB                16
#define MEMP_NUM_TCP_PCB_LISTEN         8
#define MEMP_NUM_TCP_SEG                64
#define TCP_SND_BUF                     (8 * TCP_MSS)
#define TCP_SND_QUEUELEN                64
#define TCP_WND                         (8 * TCP_MSS)
#define LWIP_SINGLE_NETIF               1
#define LWIP_NETIF_HOSTNAME             0
#define LWIP_NETIF_STATUS_CALLBACK      0
#define LWIP_NETIF_LINK_CALLBACK        0
#define LWIP_PROVIDE_ERRNO               1
#define LWIP_NOASSERT                    0

#endif
