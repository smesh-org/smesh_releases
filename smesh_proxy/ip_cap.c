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


#include "util/arch.h"
#include "util/alarm.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <net/if.h>
/*#include <netinet/if_ether.h>*/
/*#include <netinet/ether.h>*/
#include <netinet/ip.h>

#include <features.h>          /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1 
#include <netpacket/packet.h>
#include <net/ethernet.h>      /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>    /* The L2 protocols */ 
#endif


#include "pcap.h"
#include "packet.h"
#include "ip_cap.h"

char errbuf[PCAP_ERRBUF_SIZE];
extern int32 Debug_Flags;

/***********************************************************/
/* int IPCAP_init(char *dev, int primisc,                  */
/*                      pcap_t** descr, char *my_filter)   */
/*                                                         */
/* Initialize libpcap handler                              */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* dev: device name i.e. "eth0"                            */
/* promisc: use primiscuous mode                           */
/* descr: place to store pointer to pcap descriptor        */
/* my_filter: bpf filter to use                            */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* Selectable Socket                                       */
/*                                                         */
/***********************************************************/
int init_pcap(char *dev, int promisc, pcap_t** descr, char *my_filter) 
{
    struct bpf_program fp; 
    int pcap_socket;
    bpf_u_int32 maskp; 
    bpf_u_int32 netp; 

    Alarm(DEBUG_IPCAP, PRINT_FUNCTION_HEADER);

    if (dev == NULL) {
        dev = pcap_lookupdev(errbuf);
        if(dev == NULL) { printf("%s\n",errbuf); exit(1); }
    }

    /* ask pcap for the network address and mask of the device */
    if(pcap_lookupnet(dev,&netp,&maskp,errbuf) == -1) 
    { printf("pcap_lookupnet(): %s\n", errbuf); exit(1); }

    /* open device for reading. Need only 2024 as Spines packets will be less */
    *descr = pcap_open_live(dev,2024,promisc,0,errbuf);
    if(*descr == NULL)
    { printf("pcap_open_live(): %s\n", errbuf); exit(1); }

    /* put device in non-blocking mode */
    if(pcap_setnonblock(*descr, 1, errbuf) == -1)
    { printf("pcap_setnonblock(): %s\n", errbuf); exit(1); }

    /* compile/set filter */
    if (my_filter != NULL) {
        if(pcap_compile(*descr,&fp,my_filter,0,netp) == -1)
        { printf("Error calling pcap_compile\n%s\n", pcap_geterr(*descr)); exit(1); }

        if(pcap_setfilter(*descr,&fp) == -1)
        { printf("Error setting filter\n"); exit(1); }
    }

    pcap_socket = pcap_get_selectable_fd(*descr);
    if(pcap_socket < 0) 
    { printf("Error getting pcap select socket\n"); exit(1); }

    printf("\nRAW SOCKET CAPTURE : DEVICE=%s \n", dev);

    Alarm(DEBUG_IPCAP, PRINT_FUNCTION_FOOTER);

    return(pcap_socket); 
}


/***********************************************************/
/* int IPCAP_get_next_packet(char** ip_packet,             */
/*                           pcap_t* descr, int *type)     */
/*                                                         */
/* Initialize libpcap handler                              */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* ip_packet: pointer to packet pointer where incoming     */
/*            packet will be returned                      */
/* descr: pcap descriptor                                  */
/* type: place to return ethernet packet type              */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* Packet length                                           */
/*                                                         */
/***********************************************************/
int get_next_ip_packet(char** ip_packet, pcap_t* descr, int *type)
{ 
    int ret, len;
    struct pcap_pkthdr *pkthdr;
    const struct my_ip* ip;
    u_int16_t eth_type;
    u_int8_t  ip_prot;
    const u_char *packet;
    
    ret = pcap_next_ex(descr, &pkthdr, &packet);
    if (ret < 0) { 
        printf("pcap_next_ex: error\n");
        exit(1);
    }
    else if(ret == 0) {
        /* Timeout Elapsed */
        ip_packet = NULL;
        return(0);
    }
    else {
        if (pkthdr->caplen < ETHER_HDRLEN) {
            Alarm(PRINT, "Packet length[%d] less than ethernet header length\n", pkthdr->caplen);
            return 0;
        }
        eth_type = ntohs(((struct ether_header *)packet)->ether_type);

        if (eth_type == ETHERTYPE_ARP) {
            /* handle ARP packet */
            *ip_packet = (char *)(packet + sizeof(struct ether_header));
            *type = ETHER_ARP;
        } 
        else if(eth_type == ETHERTYPE_IP) {
            /* handle IP packet */
            *type = ETHER_IP;
            ip_prot = handle_IP(pkthdr, packet);
            if (ip_prot == IPPROTO_TCP || ip_prot == IPPROTO_UDP ||
                ip_prot == IPPROTO_ICMP ) {
                /* return IP packet and number of bytes */
                *ip_packet = (char *)(packet + sizeof(struct ether_header));
                ip = (struct my_ip*) *ip_packet;
                len = pkthdr->len - sizeof(struct ether_header); 
                /* check for ethernet trailer */
                if ((ret=len-ntohs(ip->ip_len)) > 0) {
                    len = ntohs(ip->ip_len);
                    Alarm(DEBUG_IPCAP , "Warning: Trailer Found : Bytes=[%d]. Resetting Legth\n", ret);
                }
                return(len);
            }
        }
    }
    return(0);
}



int handle_IP (struct pcap_pkthdr* pkthdr,
               const u_char* packet)
{
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    int len;

    /* jump pass the ethernet header */
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header); 

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct my_ip)) {
        Alarm(DEBUG_IPCAP, "truncated ip %d", length);
        return(0);
    }

    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip); /* header length */
    version = IP_V(ip);/* ip version */

    /* check version */
    if(version != 4) {
        Alarm(DEBUG_IPCAP, "Unknown IP version %d\n", version);
        return(0);
    }

    /* check header length */
    if(hlen < 5 ) {
        Alarm(DEBUG_IPCAP, "bad-hlen %d \n", hlen);
    }

    /* see if we have as much packet as we should */
    if(length < len)
        Alarm(DEBUG_IPCAP, "\ntruncated IP - %d bytes missing\n",len - length);

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 ) {
        /* aka no 1's in first 13 bits */
        /* print SOURCE DESTINATION hlen version len offset */
        Alarm(DEBUG_IPCAP, "IPCAP: IP Bytes[%d]: ", length);
        Alarm(DEBUG_IPCAP, "Protocol[%2d]: ", ip->ip_p);
        Alarm(DEBUG_IPCAP, "%s ", inet_ntoa(ip->ip_src));
        Alarm(DEBUG_IPCAP, "-> %s\n", inet_ntoa(ip->ip_dst));
    }
    return(ip->ip_p);
}


void print_packet(char* packet, int bytes) 
{
    struct my_ip* ip;
    const struct my_icmp* icmp;
    const struct my_udp*  udp;
    const struct my_tcp*  tcp;
    unsigned char *ptr;
    int i;

    if (!(Debug_Flags & DEBUG_PACKET))  {
        return;
    }

    if (packet != NULL && bytes > sizeof(struct my_ip)) {
        ip = (struct my_ip *)packet;
        printf("\tBytes = [%d] : Protocol = [%d] : ", bytes, ip->ip_p);
        printf("%s ", inet_ntoa(ip->ip_src));
        printf("-> %s\n",  inet_ntoa(ip->ip_dst));

        if (ip->ip_p == IPPROTO_ICMP) {
            icmp = (struct my_icmp*)((char *)ip + _IP_SIZE);
            printf("\tICMP: Type = [%d]\n", ntohs(icmp->type));
        }
        else if (ip->ip_p == IPPROTO_TCP) {
            tcp = (struct my_tcp*)((char *)ip + _IP_SIZE);
            printf("\tTCP: Source Port = [%d] : Dest Port = [%d] \n",
                    ntohs(tcp->source_port), ntohs(tcp->dest_port));
        }
        else if (ip->ip_p == IPPROTO_UDP) {
            udp = (struct my_udp*)((char *)ip + _IP_SIZE);
            printf("\tUDP: Source Port = [%d][0x%X] Dest Port = [%d][0x%X] \n",
                    ntohs(udp->source_port), (udp->source_port),
                    ntohs(udp->dest_port), (udp->dest_port));
            ptr = (unsigned char *)((char *)udp + _UDP_SIZE);
            printf("\tUDP: ASCII DATA = ");
            for (i=0;i<bytes-_IP_SIZE-_UDP_SIZE;i++,ptr++) {
                if (((int)*ptr >= 32 && (int)*ptr <= 126)) {
                 printf("%c", *ptr);
                }
            }
        }

        if (Debug_Flags & DEBUG_HEX) {
            ptr = (unsigned char*)ip;
            printf("\nHEX DATA OUTPUT:");
            for (i=0;i<bytes;i++,ptr++) {
                if (i%8 == 0) { printf(" "); }
                if (i%16 == 0) { printf("\n\t"); }
                printf(" %X", *ptr);
            }
        }

        printf("\n\n");
        fflush(NULL);
    }
}

void close_pcap(pcap_t* descr) 
{
    pcap_close(descr);
}

void get_device_info(char *dev, int *io_ip, int *io_ifindex, char* io_mac)
{
    int sk;
    int32 addr;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(struct ifreq));
    if((sk = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0) {
        ifr.ifr_addr.sa_family = AF_INET;
        strcpy(ifr.ifr_name, dev);
                                                                                
        if (ioctl(sk, SIOCGIFADDR, &ifr) == 0) {
            addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;
            *io_ip = ntohl(addr);
        } else {
            Alarm(EXIT, "ip_cap get_device_ifindex SIOCGIFADDR problem\n");    
        }
                                                                                
        if (ioctl(sk, SIOCGIFINDEX, &ifr) == 0) {
            *io_ifindex = ifr.ifr_ifindex;
        } else {
            Alarm(EXIT, "ip_cap get_device_ifindex SIOCGIFINDEX problem\n");    
        }

        if (ioctl(sk, SIOCGIFHWADDR, &ifr) == 0) {
            memcpy(io_mac, ifr.ifr_hwaddr.sa_data, MAC_SIZE);
        } else {
            Alarm(EXIT, "ip_cap get_device_ifindex SIOCGIFHWADDR problem\n");
        }
    } else {
        Alarm(EXIT, "ip_cap socket error\n");
    }
    close(sk);
}


