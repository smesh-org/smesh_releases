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
#include "util/sp_events.h"
#include "util/data_link.h"
#include "stdutil/src/stdutil/stdhash.h"
#include "stdutil/src/stdutil/stddll.h"

#include <stdlib.h>
#include <tgmath.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <features.h>        /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>    /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>  /* The L2 protocols */
#endif
#include <net/if_arp.h>

//#include <netpacket/packet.h>
#include <net/ethernet.h>    /* the L2 protocols */

#include "pcap.h"
#include "packet.h"
#include "dhcp.h"
#include "ip_cap.h"
#include "smesh_proxy.h"
#include "arp.h"

/* Global variables */
extern int32    LAN_intf_ip;
extern int      LAN_intf_ifindex;
extern char     LAN_intf_mac[MAC_SIZE];
extern int32    Debug_Flags;
extern char     Local_Packet_Buff[PKT_BUFF_SIZE];
extern char     LAN_intf_name[20];
extern int32    LQ_max;
extern float    LQ_decay_factor;
extern int32    Hello_Bcast_Timeout;
extern int32    Hello_Ucast_Timeout;
extern stdhash  DHCP_Table;
extern int      Mcast_Control_sk;
extern char      Metric;
extern int      Aggressive_Mode;

/* Local Variables */
sp_time arp_check_response_timeout = {  0,  250000};   /* 250 ms */
sp_time barp_last_time_sent;
sp_time uarp_last_time_sent;

char client_arp_ucast_ip[4];
char client_arp_bcast_ip[4];


#define CLIENT_ARP_UC_IP(x) client_arp_ucast_ip[0] = IP1(x); client_arp_ucast_ip[1] = IP2(x); client_arp_ucast_ip[2] = IP3(x); client_arp_ucast_ip[3] = (IP4(x) & 0xF8) | 0x03

#define CLIENT_ARP_BC_IP(x) client_arp_bcast_ip[0] = IP1(x); client_arp_bcast_ip[1] = IP2(x); client_arp_bcast_ip[2] = IP3(x); client_arp_bcast_ip[3] = (IP4(x) & 0xF8) | 0x04


void ARP_Init() 
{
    int arp_sk, promisc;     
    char bpf[200];  
    pcap_t* pcap_handler;
    sp_time start_timeout = {  0,  0};

    memset(bpf, 0, sizeof(bpf));
    sprintf(bpf, "arp and (! ether src "MACPF") ", MAC(LAN_intf_mac));
    if (Metric & METRIC_BARP) {
        promisc = 0;
    } else {
        promisc = 1;
    }
    arp_sk = init_pcap(LAN_intf_name, promisc, &pcap_handler, bpf);
    max_rcv_buff(arp_sk);
    max_snd_buff(arp_sk);
    E_attach_fd(arp_sk, READ_FD, ARP_process_pkt, 0, 
            (void*)pcap_handler, HIGH_PRIORITY);

    if (Metric & METRIC_BARP) {
        start_timeout.sec = 0;
        start_timeout.usec = 0;
        E_queue(ARP_send_request, METRIC_BARP, NULL, start_timeout);
    }
    if (Metric & METRIC_UARP || Metric & METRIC_RSSI) {
        start_timeout.sec = (int)(Hello_Bcast_Timeout/2);
        if(Hello_Bcast_Timeout%2 != 0) {
            start_timeout.usec = 5000000;
        }
        E_queue(ARP_send_request, METRIC_UARP, NULL, start_timeout);
    }
}

void ARP_process_pkt(int sk, int dummy_i, void *pcap_handler)
{
    int bytes, pkt_type;
    struct my_arp *aptr;        /* net/if_arp.h */
    dhcp_entry *de;
    int old_metric;
    char *recv_packet = NULL;
    char bcast_mac[MAC_SIZE];

    Alarm(DEBUG_ARP, PRINT_FUNCTION_HEADER);

    /* ARP message from the client, update the metric */
    bytes = get_next_ip_packet(&recv_packet, (pcap_t*)pcap_handler, &pkt_type);
    aptr = (struct my_arp *)recv_packet;
    memset(bcast_mac, 0xFF, MAC_SIZE);

    /* If packet is a reply, check metric */
    /* Note that we will not see ARP sent to other nodes
       if promiscuous mode is not enabled */
    if ((ntohs(aptr->ar_op) == ARPOP_REPLY)) {
        if ((de = DHCP_Lookup_Entry((char*)aptr->ar_sha))) {
            /* client is still alive, update its DHCP entry */
            de->dhcp_last_time_heard = E_get_time();    
            CLIENT_ARP_BC_IP(de->ip_addr);
            if (!memcmp(aptr->ar_tip, client_arp_bcast_ip, 4) && (Metric & METRIC_BARP)) {
                /* We got a broadcast reply to our request */
                de->barp_last_time_heard = E_get_time();    
                old_metric = de->bcast_lq_metric;
                de->bcast_lq_metric = de->bcast_lq_metric * (1 - LQ_decay_factor) 
                                        + (int)(LQ_max) * LQ_decay_factor;
                if (old_metric == de->bcast_lq_metric && de->bcast_lq_metric < (int)(LQ_max)) {
                    de->bcast_lq_metric = de->bcast_lq_metric + 1;
                }
                /* Join now, since we have a bidirectional link */
                if (!(de->groups & GROUP_STAT_JOINED_CTRL)) {
                    de->join_time = E_get_time();
                    de->groups |= GROUP_STAT_JOINED_CTRL;
                    smesh_add_membership(Mcast_Control_sk, IP_TO_CTRL_MCAST(de->ip_addr));
                }
            } else if (!memcmp(aptr->ar_tha, LAN_intf_mac, MAC_SIZE) && (Metric & METRIC_UARP)) {
                /* We got a unicast reply to our request */
                de->uarp_last_time_heard = E_get_time();    

                old_metric = de->ucast_lq_metric;
                de->ucast_lq_metric = de->ucast_lq_metric * (1 - 2.0*LQ_decay_factor) 
                                        + (int)(LQ_max) * LQ_decay_factor * 2.0;
                if (old_metric == de->ucast_lq_metric && de->ucast_lq_metric < (int)(LQ_max)) {
                    de->ucast_lq_metric = de->ucast_lq_metric + 1;
                }

                /* Join Client Control group, since we have a bidirectional link */
                if (!(de->groups & GROUP_STAT_JOINED_CTRL)) {
                    de->join_time = E_get_time();
                    de->groups |= GROUP_STAT_JOINED_CTRL;
                    smesh_add_membership(Mcast_Control_sk, IP_TO_CTRL_MCAST(de->ip_addr));
                }
            } else if (!memcmp(aptr->ar_tha, bcast_mac, MAC_SIZE) && (Metric & METRIC_BARP)) {
                /* We got a broadcast reply for someone else, so at least half the link is up */
                /* Consider it only if metric is less than 50%, otherwise, let metric go down */
                if (de->bcast_lq_metric < (int)(0.5*LQ_max)) {
                    /* I can hear everyone's reply, so only consider one every so many seconds */
                    if (E_compare_time(barp_last_time_sent, de->barp_last_time_heard) > 0) {
                        de->barp_last_time_heard = E_get_time();    
                        de->bcast_lq_metric = de->bcast_lq_metric * (1 - LQ_decay_factor) 
                                              + (int)(LQ_max) * LQ_decay_factor;
                        /* Prevent oscillations */
                        if (de->bcast_lq_metric > (int)(0.5*LQ_max)) {
                            de->bcast_lq_metric = (int)(0.5*LQ_max);
                        }
                    }
                }
            } else if (Metric & METRIC_UARP) {
                /* We got a unicast reply for someone else */
                if (de->ucast_lq_metric < (int)(0.5*LQ_max)) {
                    /* I can hear everyone's reply, so only consider one every so many second */
                    if (E_compare_time(uarp_last_time_sent, de->uarp_last_time_heard) > 0) {
                        de->uarp_last_time_heard = E_get_time();    
                        de->ucast_lq_metric = de->ucast_lq_metric * (1 - LQ_decay_factor) 
                                              + (int)(LQ_max) * LQ_decay_factor;
                        /* Prevent oscillations */
                        if (de->ucast_lq_metric > (int)(0.5*LQ_max)) {
                            de->ucast_lq_metric = (int)(0.5*LQ_max);
                        }
                    }
                }
            }
            /* TODO: If using RSSI and I hear you and the rssi is ok, join Client Control group */
            if ((Metric & METRIC_RSSI) && !(de->groups & GROUP_STAT_JOINED_CTRL)) {
                de->join_time = E_get_time();
                de->groups |= GROUP_STAT_JOINED_CTRL;
                smesh_add_membership(Mcast_Control_sk, IP_TO_CTRL_MCAST(de->ip_addr));
            }
        } else {
            /* new client */
            if (MAC_TO_IP((char*)aptr->ar_sha) == IPARRAY2IPINT(aptr->ar_sip)) {
                Alarm(DEBUG_ARP, "ARP_process_pkt: ARP IP Address Ok: Creating Client\n");
                DHCP_Create_Entry((char*)aptr->ar_sha);
                if(!(de = DHCP_Lookup_Entry((char*)aptr->ar_sha))) {
                    Alarm(EXIT,"Unable to lookup newly created dhcp_entry\n");
                }
                //Alarm(DEBUG_DHCP, "Joining CTRL group ["IPF"]\n", IP(IP_TO_CTRL_MCAST(de->ip_addr)));
                //de->groups = GROUP_STAT_JOINED_CTRL;
                //smesh_add_membership(Mcast_Control_sk, IP_TO_CTRL_MCAST(de->ip_addr));
            }
        }
    } 
    Alarm(DEBUG_ARP, PRINT_FUNCTION_FOOTER);
}

/* Send an ARP packet to the client (either an gratuitous ARP or an ARP for the metric) */
void ARP_send_raw_pkt(int dest_ifindex, unsigned char *ether_src, unsigned char *ether_dst,
              unsigned short int arp_op, unsigned char *arp_sha, unsigned char *arp_sip,
              unsigned char *arp_tha, unsigned char *arp_tip)
{
    int ret, bytes;
    struct my_arp *aptr;

    Alarm(DEBUG_ARP, PRINT_FUNCTION_HEADER);

    bytes = sizeof(struct my_arp);
    memset(Local_Packet_Buff, 0, bytes);
    aptr = (struct my_arp *)Local_Packet_Buff;

    /* ARP header */
    aptr->ar_hrd = htons(ARPHRD_ETHER);
    aptr->ar_pro = htons(ETH_P_IP);
    aptr->ar_hln = 6;  
    aptr->ar_pln = 4;

    memcpy(aptr->ar_sha, arp_sha, MAC_SIZE);
    memcpy(aptr->ar_tha, arp_tha, MAC_SIZE);
    memcpy(aptr->ar_sip, arp_sip, sizeof(int32));
    memcpy(aptr->ar_tip, arp_tip, sizeof(int32));
    aptr->ar_op = htons(arp_op);

    if(Debug_Flags & DEBUG_ARP) {
        Alarm(DEBUG_ARP, "ARP_send_raw_pkt: Sending ARP packet:\n");
        ARP_print_packet(Local_Packet_Buff);
    }

    /* Send Packet */
    ret = send_raw_eth_pkt(Local_Packet_Buff, bytes, ETH_P_ARP, dest_ifindex, (char*) ether_dst);

    Alarm(DEBUG_ARP, PRINT_FUNCTION_FOOTER);
}

void ARP_send_gratuitous_arp(int dummy_int, void *mac, int ip)
{
    unsigned char fake_ip[4];
    unsigned char dest_mac[MAC_SIZE];

    Alarm(DEBUG_ARP, PRINT_FUNCTION_HEADER);

    fake_ip[0] = IP1(DHCP_FAKE_GATEWAY_X(ip)); 
    fake_ip[1] = IP2(DHCP_FAKE_GATEWAY_X(ip));
    fake_ip[2] = IP3(DHCP_FAKE_GATEWAY_X(ip));
    fake_ip[3] = IP4(DHCP_FAKE_GATEWAY_X(ip));

    memcpy(&dest_mac, (unsigned char*)mac, MAC_SIZE);
    Alarm(DEBUG_ARP, "\tSending Gratuitous ARP to "MACPF"\nfake_ip = "IPF"\n", 
          MAC(dest_mac), ARRAY2IP(fake_ip));
    ARP_send_raw_pkt(LAN_intf_ifindex, (u_char*)LAN_intf_mac, dest_mac, ARPOP_REPLY,
           (u_char*)LAN_intf_mac, fake_ip, (u_char*)LAN_intf_mac, fake_ip);

    Alarm(DEBUG_ARP, PRINT_FUNCTION_FOOTER);
}

/* Send an ARP request to each client; replies will be used for the metric */
void ARP_send_request(int arp_request_type, void *dummy)
{
    stdit dhcp_it;
    dhcp_entry *de;
    unsigned char bcast_mac[MAC_SIZE], zero_mac[MAC_SIZE];
    unsigned char target_ip[4];
    unsigned char *destination_mac, *reply_mac, *reply_ip;
    sp_time arp_request_timeout;

    Alarm(DEBUG_ARP, PRINT_FUNCTION_HEADER);
    memset(zero_mac, 0, MAC_SIZE);
    memset(bcast_mac, 0xFF, MAC_SIZE);

    /* Did arp response checker ever get called? */
    if (E_dequeue(ARP_lq_check, arp_request_type, NULL) == 0) {
        Alarm(PRINT, "ARP_send_request: TimeEvent Problem. Check Response was never called\n");
        ARP_lq_check(arp_request_type, NULL);
    }

    stdhash_begin(&DHCP_Table, &dhcp_it);
    while(!stdhash_is_end(&DHCP_Table, &dhcp_it)) {
        de = *((dhcp_entry **)stdhash_it_val(&dhcp_it));
        target_ip[0] = IP1(de->ip_addr); 
        target_ip[1] = IP2(de->ip_addr); 
        target_ip[2] = IP3(de->ip_addr); 
        target_ip[3] = IP4(de->ip_addr); 

        if (arp_request_type == METRIC_UARP) {
            /* 
               Should I use a broadcast destination mac? That way,
               if client is not in reach, I will not re-transmit requests
               for him:  destination_mac = (unsigned char*)&bcast_mac; 
            */
            destination_mac = de->mac_addr;
            reply_mac = (unsigned char*)&LAN_intf_mac;
            CLIENT_ARP_UC_IP(de->ip_addr);
            reply_ip = (unsigned char*)&client_arp_ucast_ip;
        } else if (arp_request_type == METRIC_BARP) {
            destination_mac = (unsigned char*)&bcast_mac;
            reply_mac = (unsigned char*)&bcast_mac;
            CLIENT_ARP_BC_IP(de->ip_addr);
            reply_ip = (unsigned char*)&client_arp_bcast_ip;
        } else {
            Alarm(EXIT, "BAD APR REQUEST TYPE\n");
            return;
        }
        ARP_send_raw_pkt(LAN_intf_ifindex, (u_char*)LAN_intf_mac, destination_mac,
                         ARPOP_REQUEST, reply_mac, reply_ip, 
                         zero_mac, target_ip);
        stdhash_it_next(&dhcp_it);
    }

    /* Reschedule ARP request packets based on hello timeout */
    arp_request_timeout.sec = 4;
    arp_request_timeout.usec = 0;

    if (arp_request_type == METRIC_UARP) {
        arp_request_timeout.sec = Hello_Ucast_Timeout;
        uarp_last_time_sent = E_get_time();
    } else if (arp_request_type == METRIC_BARP) {
        arp_request_timeout.sec = Hello_Bcast_Timeout;
        barp_last_time_sent = E_get_time();
    }
    
    if (Metric & METRIC_BARP || Metric & METRIC_UARP) {
        E_queue(ARP_lq_check, arp_request_type, NULL, arp_check_response_timeout);
    }
    E_queue(ARP_send_request, arp_request_type, NULL, arp_request_timeout);
    Alarm(DEBUG_ARP, PRINT_FUNCTION_FOOTER);
}

/* An ARP response was NOT received, decrease metric */
void ARP_lq_check(int arp_request_type, void *dummy)
{
    stdit dhcp_it;
    dhcp_entry *de;

    stdhash_begin(&DHCP_Table, &dhcp_it);
    while(!stdhash_is_end(&DHCP_Table, &dhcp_it)) {
        de = *((dhcp_entry **)stdhash_it_val(&dhcp_it));
        if (arp_request_type == METRIC_UARP) {
            /* If never received response, decrease metric */
            if (E_compare_time(uarp_last_time_sent, de->uarp_last_time_heard) > 0) {
                de->ucast_lq_metric = de->ucast_lq_metric * (1 - 2.0*LQ_decay_factor);

                if (de->groups & GROUP_STAT_JOINED_DATA)  {
                    LQ_Check_DataGroup(Aggressive_Mode, de);
                }
            }
        } else if (arp_request_type == METRIC_BARP) {
            /* If never received response, decrease metric */
            if (E_compare_time(barp_last_time_sent, de->barp_last_time_heard) > 0) {
                /* Losing control packets in a row means link is much worse */
                /* TODO: Do something about it using a flag ... last_bcast_lost */
                de->bcast_lq_metric = de->bcast_lq_metric * (1 - LQ_decay_factor);

                if (de->groups & GROUP_STAT_JOINED_DATA)  {
                    LQ_Check_DataGroup(Aggressive_Mode, de);
                }
            }
        }
        stdhash_it_next(&dhcp_it);
    }
}

void ARP_print_packet(const char *packet)
{
    struct ether_header *eptr;  /* net/ethernet.h */
    struct my_arp *aptr;        /* net/if_arp.h */
    unsigned char *ptr;

    u_short ether_type;
    int i;

    if (!(Debug_Flags & DEBUG_ARP)) {
        return;
    }

    Alarm(DEBUG_ARP, PRINT_FUNCTION_HEADER);

    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);
    aptr = (struct my_arp *) (packet + sizeof(struct ether_header));

    /* ethernet header */
    Alarm(PRINT, "ether_header: ether_dhost = "MACPF" ether_shost = "MACPF" ether_type = %x\n",
          MAC(eptr->ether_dhost), MAC(eptr->ether_shost), eptr->ether_type);

    /* arp header */
    Alarm(PRINT, "arphdr: type = %d sha = "MACPF" sip = "IPF" tha = "MACPF" tip = "IPF"\n",
      htons(aptr->ar_op), MAC(aptr->ar_sha), ARRAY2IP(aptr->ar_sip),
      MAC(aptr->ar_tha), ARRAY2IP(aptr->ar_tip));

    Alarm(PRINT, "ARP in hex - start\n");
    ptr = (unsigned char *) aptr;
    for (i = 0; i < sizeof(struct my_arp); ptr++, i++) {
        Alarm(PRINT, "%X ", *ptr);
    }
    Alarm(PRINT, "ARP in hex - end\n");

    Alarm(DEBUG_ARP, PRINT_FUNCTION_FOOTER);
}

