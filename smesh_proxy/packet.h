/*
 * SMesh
 * Copyright (c) 2005 - 2008 Johns Hopkins University
 * All rights reserved.
 *
 * The contents of this file are subject to the SMesh Open-Source
 * License, Version 1.1 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.smesh.org/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * SMesh is developed at the Distributed Systems and Networks Lab,
 * The Johns Hopkins University.
 *
 * Software distributed under the License is distributed on an AS IS basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Creators:
 *    Yair Amir                 yairamir@dsn.jhu.edu
 *    Claudiu Danilov           claudiu@dsn.jhu.edu
 *    Raluca Musaloiu-Elefteri  ralucam@dsn.jhu.edu
 *    Nilo Rivera               nrivera@dsn.jhu.edu
 *
 * Major Contributors:
 *    Michael Hilsdale          mhilsdale@dsn.jhu.edu
 *    Michael Kaplan            kaplan@dsn.jhu.edu
 *
 * WWW:     www.smesh.org      www.dsn.jhu.edu
 * Contact: smesh@smesh.org
 *
 * This product uses software developed by Spines and Spread Concepts LLC.
 * For more information about SMesh, see http://www.smesh.org
 * For more information about Spread, see http://www.spread.org
 *
 */


#ifndef PACKET_H
#define PACKET_H

/* Debug Flags */
#define DEBUG_SMESH     0x01000000
#define DEBUG_IPCAP     0x02000000
#define DEBUG_PACKET    0x04000000
#define DEBUG_HEX       0x08000000
#define DEBUG_DHCP      0x10000000
#define DEBUG_NAT       0x20000000
#define DEBUG_LQ        0x40000000
#define DEBUG_ARP       0x80000000

/* Define Boolean Type */
#define FALSE           0  
#define TRUE            1 

/* Macro for min max computation */
#define min(a,b)        ((a) < (b) ? (a) : (b))
#define max(a,b)        ((a) > (b) ? (a) : (b))

/* IP Management Macros (mostly from Spread util/alarm */
/* To print IP, use use printf with IPF and call IP(x) on the argument */
#define IPINT(a,b,c,d)  ((int32) ((a << 24) + (b << 16) + (c << 8) + (d)))
#define IP1( address )  ( ( 0xFF000000 & (address) ) >> 24 )
#define IP2( address )  ( ( 0x00FF0000 & (address) ) >> 16 )
#define IP3( address )  ( ( 0x0000FF00 & (address) ) >> 8 )
#define IP4( address )  ( ( 0x000000FF & (address) ) )
#define IPF "%d.%d.%d.%d"
#define IP( address )   IP1(address),IP2(address),IP3(address),IP4(address)
#define ARRAY2IP(ip)    (unsigned char) ip[0],\
                        (unsigned char) ip[1],\
                        (unsigned char) ip[2],\
                        (unsigned char) ip[3]
#define IPARRAY2IPINT(ip) IPINT((int)ip[0], (int)ip[1], (int)ip[2], (int)ip[3])

/* Print spaces so that IPs take the same number of spaces */
#define IP_PRINT_SPACES(x) { \
int a=DIGIT_CNT(IP1(x)) + DIGIT_CNT(IP2(x)) + DIGIT_CNT(IP3(x)) + DIGIT_CNT(IP4(x));\
 a = 12 - a;\
while(a-->0) printf(" ");\
}
#define DIGIT_CNT(x) (x!=0?floor(log10(x))+1:1)

#define PRINT_FUNCTION_HEADER "=====> %s -- %s [%d] =====>\n", __func__, __FILE__, __LINE__
#define PRINT_FUNCTION_FOOTER "<===== %s <=====\n", __func__, __FILE__, __LINE__


#define MAC_SIZE     6
#define MAC_BCAST_ADDR (unsigned char *) "\xff\xff\xff\xff\xff\xff"
#define MACPF        "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X"
#define MAC(m)       (unsigned char) m[0],\
                     (unsigned char) m[1],\
                     (unsigned char) m[2],\
                     (unsigned char) m[3],\
                     (unsigned char) m[4],\
                     (unsigned char) m[5] 

/*
 * Structure of an internet header, naked of options.
 */
struct my_ip {
        u_int8_t        ip_vhl;         /* header length, version */
        u_int8_t        ip_tos;         /* type of service */
        u_int16_t       ip_len;         /* total length */
        u_int16_t       ip_id;          /* identification */
        u_int16_t       ip_off;         /* fragment offset field */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
        u_int8_t        ip_ttl;         /* time to live */
        u_int8_t        ip_p;           /* protocol */
        u_int16_t       ip_sum;         /* checksum */
        struct in_addr  ip_src,ip_dst;  /* source and dest address */
};
#define _IP_SIZE sizeof(struct my_ip)
#define IP_V(iph)        (((iph)->ip_vhl & 0xf0) >> 4)
#define IP_HL(iph)       ((iph)->ip_vhl & 0x0f)
#define IP_V_SET(iph,x) ((iph)->ip_vhl = ((iph)->ip_vhl & 0x0F) | ((x) << 4))
#define IP_HL_SET(iph,x) ((iph)->ip_vhl = ((iph)->ip_vhl & 0xF0) | (((x) >> 2) & 0x0F))



/*
 * Structure of a ICMP header 
 */
struct my_icmp {
    u_int8_t type;        /* message type */
    u_int8_t code;        /* type sub-code */
    u_int16_t checksum;
    union
    {
        struct
        {
            u_int16_t id;
            u_int16_t sequence;
        } echo;             /* echo datagram */
        u_int32_t   gateway;    /* gateway address */
        struct
        {
            u_int16_t unused;
            u_int16_t mtu;
        } frag;         /* path mtu discovery */
    } un;
};

/*
 * Structure of a UDP header 
 */
struct my_udp {
    unsigned short source_port;
    unsigned short dest_port;
    unsigned short len;
    unsigned short sum;
};
#define _UDP_SIZE sizeof(struct my_udp)

/*
 * Structure of a TCP header 
 */
struct my_tcp {
    unsigned short       source_port;
    unsigned short       dest_port;
    unsigned int         tcp_seqno;
    unsigned int         tcp_ackno;
    unsigned int         tcp_res1:4,     /*little-endian*/
    tcp_hlen:4,
    tcp_fin:1,
    tcp_syn:1,
    tcp_rst:1,
    tcp_psh:1,
    tcp_ack:1,
    tcp_urg:1,
    tcp_res2:2;
    unsigned short      tcp_winsize;
    unsigned short      tcp_cksum;
    unsigned short      tcp_urgent;
};
#define _TCP_SIZE sizeof(struct my_tcp)

struct my_tcp_option {
    int temp;
};

/*
 * Structure of DNS Request/Response
 */
struct my_dns {
    unsigned short int id;
    unsigned char info1;

/*        unsigned char  rd:1;            recursion desired */
/*        unsigned char  tc:1;            truncated message */
/*        unsigned char  aa:1;            authoritive answer */
/*        unsigned char  opcode:4;        purpose of message */
/*        unsigned char  qr:1;            response flag */

    unsigned char info2;

/*        unsigned char  rcode:4;         response code */
/*        unsigned char  unused:2;        unused bits */
/*        unsigned char  pr:1;            primary server required */
/*        unsigned char  ra:1;            recursion available */

    unsigned short int que_num;
    unsigned short int rep_num;
    unsigned short int num_rr;
    unsigned short int num_rrsup;
};
#define _DNS_SIZE sizeof(struct my_dns)
#define DNS_PORT 53


/*
 * Structure of ARP Request/Response
 */

struct my_arp {
    unsigned short int ar_hrd;          /* Format of hardware address.  */
    unsigned short int ar_pro;          /* Format of protocol address.  */
    unsigned char ar_hln;               /* Length of hardware address.  */
    unsigned char ar_pln;               /* Length of protocol address.  */
    unsigned short int ar_op;           /* ARP opcode (command).  */
    unsigned char ar_sha[6];		/* Sender hardware address.  */
    unsigned char ar_sip[4];		/* Sender IP address.  */
    unsigned char ar_tha[6];		/* Target hardware address.  */
    unsigned char ar_tip[4];		/* Target IP address.  */
};

/* Function Prototypes */
void    pkt_checksum(char *pkt);
void    check_checksum(char *pkt);
int     send_raw_eth_pkt(char *pkt, int bytes, short protocol, 
                         int out_ifindex, char *dest_mac);
int     send_raw_ip_pkt(int raw_sk, char *pkt, int bytes);
int     max_rcv_buff(int sk);
int     max_snd_buff(int sk);

#endif

