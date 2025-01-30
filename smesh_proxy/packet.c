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


#include "util/alarm.h"

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <features.h>          /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>      /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>    /* The L2 protocols */
#endif

#include "packet.h"
extern int32 Debug_Flags;

// Send packet through raw socket using specified device to specified ethernet destination
int send_raw_eth_pkt(char *pkt, int bytes, short protocol, int out_ifindex, char *dest_mac)
{
    int ret;
    int sk;
    struct sockaddr_ll to;

    if (pkt == NULL || dest_mac == NULL || bytes <= 0) {
        return(-1);
    }

    sk = socket(PF_PACKET, SOCK_DGRAM, htons(protocol));
    if(sk < 0) {
        Alarm(PRINT, "ip_send_raw_pkt: Unable to open up raw socket for sending data...\n");
        exit(1);
    }

    memset(&to, 0, sizeof(to));
    to.sll_family = AF_PACKET;
    to.sll_protocol = htons(protocol);
    to.sll_ifindex = out_ifindex;
    to.sll_halen = MAC_SIZE;
    memcpy(to.sll_addr, dest_mac, MAC_SIZE);

    if(bind(sk, (struct sockaddr*) &to, sizeof(to)) < 0) {
        Alarm(PRINT, "ip_send_raw_pkt: Bind Error [%s]\n", strerror(errno));
        close(sk);
        exit(1);
    }
    ret = sendto(sk, pkt, bytes, 0, (struct sockaddr *) &to, sizeof(to));
    if (ret <= 0) {
        Alarm(PRINT, "Error sending raw packet \n");
        perror("sendto error: ");
    }
    close(sk);
    return ret;
}

// Send packet through raw socket to specified ip destination
int send_raw_ip_pkt(int raw_sk, char *pkt, int bytes)
{
    int ret;
    struct sockaddr_in sin;
    struct my_ip   *ip;

    ip = (struct my_ip*)pkt;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    // setsockopt(raw_sk, IPPROTO_IP, IP_HDRINCL, &temp, sizeof(temp));
    // sin.sin_len = sizeof(sin);
    sin.sin_addr.s_addr = ip->ip_dst.s_addr;

    ret = sendto(raw_sk, pkt, bytes, 0, (struct sockaddr *)&sin, sizeof(sin));
    if (ret <= 0) {
        Alarm(PRINT, "Error sending raw packet \n");
    } 
    return ret;
}


// 16-bit one's complement sum (pads the buffer if necesary)
uint16_t sum16(char *addr, int count, uint16_t initial_sum)
{
    /* Compute Internet Checksum for "count" bytes beginning at location "addr". */
    uint16_t byte0, byte1, _byte0, _byte1, tmp;
    uint16_t sum = initial_sum;
/*
    Alarm(PRINT, "packet.c: sum16: %d bytes\n", count);
*/
    byte0 = initial_sum & 0xff;
    byte1 = (initial_sum & 0xff00) >> 8;

    while (count > 1)  {
/*          
        Alarm(PRINT, "\t\tstep %d: byte0 = %X byte1 =%X\n", count, byte0, byte1);
*/      
        /*  This is the inner loop */
        tmp = addr[0] & 0xff;
        byte0 += tmp;
        tmp = addr[1] & 0xff;
        byte1 += tmp;
        while ((byte0 & 0xff00) || (byte1 & 0xff00)) {
            _byte0 = (byte0 & 0xff) + (byte1 >> 8);
            _byte1 = (byte1 & 0xff) + (byte0 >> 8);
            byte0 = _byte0;
            byte1 = _byte1;
        }
        addr += 2;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if (count > 0) {
        byte0 += addr[0] & 0xff;
        while ((byte0 & 0xff00) || (byte1 & 0xff00)) {
            _byte0 = (byte0 & 0xff) + (byte1 >> 8);
            _byte1 = (byte1 & 0xff) + (byte0 >> 8);
            byte0 = _byte0;
            byte1 = _byte1;
        }
    }
    sum = byte0 + (byte1 << 8);
    return sum;
}

// complement the sum to obtain the checksum
uint16_t ip_checksum(uint16_t sum16)
{
    sum16 = ~sum16 & 0xffff;
    if (htons(sum16) == sum16) {
        sum16 = ((sum16<<8) & 0xFF00) | ((sum16>>8) & 0x00FF);
    }
    return sum16;
}

// Compute IP and upper layers packet checksum.
void pkt_checksum(char *pkt)
{
    struct my_ip   *ip;
    struct my_icmp *icmp;
    struct my_udp  *udp;
    struct my_tcp  *tcp;

    uint16_t sum, len;
    char tmp[2];
    uint16_t tmp2;
    
    //printf("packet.c: pkt_checksum in\n");

    ip = (struct my_ip*) pkt;
    ip->ip_sum = 0;
    // IP checksum covers only the IP header which is ip->len * 4  bytes;
    ip->ip_sum = ip_checksum(sum16((char *)ip, IP_HL(ip) * 4, 0));
    //printf("DEBUG: pkt_checksum [IP] %X\n", ip->ip_sum);
    
    // IP - IP_header
    len = ntohs(ip->ip_len) - IP_HL(ip) * 4; 
    //printf("len = %d\n", len);

    if (ip->ip_p == IPPROTO_TCP) {
        tcp = (struct my_tcp*)((char *)ip + _IP_SIZE);
        tcp->tcp_cksum = 0;
        // pseudoheader 
        sum = sum16((char *)&(ip->ip_src), 4, 0);   // IP src       4 bytes
        sum = sum16((char *)&(ip->ip_dst), 4, sum); // IP dest      4 bytes
        tmp[0] = 0;
        tmp[1] = ip->ip_p;
        sum = sum16((char *)&tmp, 2, sum);          // TCP protocol 2 bytes 
        tmp2 = htons(len);
        sum = sum16((char *)&tmp2, 2, sum);         // TCP length   2 bytes
        sum = sum16((char *)tcp, len, sum);         // TCP packet
        tcp->tcp_cksum = ip_checksum(sum);
        //printf("DEBUG: pkt_checksum [TCP] %X\n", tcp->tcp_cksum);
        
    } else if (ip->ip_p == IPPROTO_UDP) {
        udp = (struct my_udp*)((char *)ip + _IP_SIZE);
        udp->sum= 0;
        // pseudoheader 
        sum = sum16((char *)&(ip->ip_src), 4, 0);   // IP src       4 bytes
        sum = sum16((char *)&(ip->ip_dst), 4, sum); // IP dest      4 bytes
        tmp[0] = 0;
        tmp[1] = ip->ip_p;
        sum = sum16((char *)&tmp, 2, sum);          // UDP protocol 2 bytes
        tmp2 = htons(len);
        sum = sum16((char *)&tmp2, 2, sum);         // UDP length   2 bytes
        sum = sum16((char *)udp, len, sum);         // UDP packet 
        udp->sum = ip_checksum(sum);
        //printf("DEBUG: pkt_checksum [UDP] %X\n", udp->sum);
        
    } else if (ip->ip_p == IPPROTO_ICMP) {
        icmp = (struct my_icmp*)((char *)ip + _IP_SIZE);
        icmp->checksum = 0;
        // ICMP checksum covers entire ICMP packet
        icmp->checksum = ip_checksum(sum16((char *)icmp, len, 0));
        //printf("DEBUG: pkt_checksum [ICMP] %X\n", icmp->checksum);
        
    }
    //printf("packet.c: pkt_checksum out\n");
}

// Check the IP chechsum and upper layers packet checksum.
void check_checksum(char *pkt)
{
    struct my_ip   *ip;
    struct my_icmp *icmp;
    struct my_udp  *udp;
    struct my_tcp  *tcp;

    uint16_t sum, len;
    uint16_t chk_sum;
    char tmp[2];
    uint16_t tmp2;

    //printf("packet.c: check_checksum in\n");
    ip = (struct my_ip*) pkt;
    // IP checksum covers only the IP header which is ip->len * 4  bytes;
    chk_sum = ip_checksum(sum16((char *)ip, IP_HL(ip) * 4, 0));
    //printf("DEBUG: check_checksum [IP] %X\n", chk_sum);
    
    // IP - IP_header
    len = ntohs(ip->ip_len) - IP_HL(ip) * 4; 
    //printf("len = %d\n", len);

    if (ip->ip_p == IPPROTO_TCP) {
        tcp = (struct my_tcp*)((char *)ip + _IP_SIZE);
        //printf("tcp checksum = %X\n", tcp->tcp_cksum);
        // pseudoheader 
        sum = sum16((char *)&(ip->ip_src), 4, 0);   // IP src       4 bytes
        sum = sum16((char *)&(ip->ip_dst), 4, sum); // IP dest      4 bytes
        tmp[0] = 0;
        tmp[1] = ip->ip_p;
        sum = sum16((char *)&tmp, 2, sum);          // TCP protocol 2 bytes 
        tmp2 = htons(len);
        sum = sum16((char *)&tmp2, 2, sum);         // TCP length
        sum = sum16((char *)tcp, len, sum);         // TCP packet
        chk_sum = ip_checksum(sum);
        //printf("DEBUG: check_checksum [TCP] %X\n", chk_sum);
        
    } else if (ip->ip_p == IPPROTO_UDP) {
        udp = (struct my_udp*)((char *)ip + _IP_SIZE);
        // pseudoheader 
        sum = sum16((char *)&(ip->ip_src), 4, 0);   // IP src       4 bytes
        sum = sum16((char *)&(ip->ip_dst), 4, sum); // IP dest      4 bytes
        tmp[0] = 0;
        tmp[1] = ip->ip_p;
        sum = sum16((char *)&tmp, 2, sum);          // UDP protocol 2 bytes
        tmp2 = htons(len);
        sum = sum16((char *)&tmp2, 2, sum);         // UDP length   2 bytes
        sum = sum16((char *)udp, len, sum);         // UDP packet
        chk_sum = ip_checksum(sum);
        //printf("DEBUG: check_checksum [UDP] %X\n", chk_sum);
        
    } else if (ip->ip_p == IPPROTO_ICMP) {
        icmp = (struct my_icmp*)((char *)ip + _IP_SIZE);
        // ICMP checksum covers entire ICMP packet
        chk_sum = ip_checksum(sum16((char *)icmp, len, 0));
        //printf("DEBUG: pkt_checksum [ICMP] %X\n", chk_sum);
        
    }
    //printf("packet.c: check_checksum out\n");
}


int max_rcv_buff(int sk)
{
    /* Increasing the buffer on the socket */
    int i, val, ret;
    unsigned int lenval;

    for(i=10; i <= 100; i+=5)
    {
        val = 1024*i;
        ret = setsockopt(sk, SOL_SOCKET, SO_RCVBUF, (void *)&val, sizeof(val));
        if (ret < 0)
            break;
        lenval = sizeof(val);
        ret= getsockopt(sk, SOL_SOCKET, SO_RCVBUF, (void *)&val, &lenval);
        if(val < i*1024 )
            break;
    }
    return(1024*(i-5));
}

int max_snd_buff(int sk)
{
    /* Increasing the buffer on the socket */
    int i, val, ret;
    unsigned int lenval;

    for(i=10; i <= 100; i+=5)
    {
        val = 1024*i;
        ret = setsockopt(sk, SOL_SOCKET, SO_SNDBUF, (void *)&val, sizeof(val));
        if (ret < 0)
            break;
        lenval = sizeof(val);
        ret = getsockopt(sk, SOL_SOCKET, SO_SNDBUF, (void *)&val,  &lenval);
        if(val < i*1024)
            break;
    }
    return(1024*(i-5));
}


