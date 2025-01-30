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

#include <sys/time.h>
#include <time.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <tgmath.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <features.h>    /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1 
#include <netpacket/packet.h>
#include <net/ethernet.h>    /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>    /* The L2 protocols */ 
#endif

#include <net/if_arp.h>

#include "pcap.h"
#include "packet.h"
#include "dhcp.h"
#include "ip_cap.h"
#include "smesh_proxy.h"
#include "arp.h"

#include "spines_lib.h"

#define METRIC(x)      (compute_metric(x))

/* Global variables */
extern int32 LAN_intf_ip;
extern int LAN_intf_ifindex;
extern char  LAN_intf_name[20];
extern char LAN_intf_mac[MAC_SIZE];
extern int32 DNS1;
extern int32 DNS2;
extern int32 DNS3;
extern int32 Main_Lease_Time;
extern int32 Debug_Flags;
extern int32 Hello_Bcast_Timeout;
extern int32 Hello_Ucast_Timeout;
extern int32 LQ_max;
extern float LQ_threshold;
extern float LQ_decay_factor;
extern int32 Num_Listeners;
extern int Mcast_Client_sk;
extern int Mcast_Control_sk;
extern char Packet_Buff[PKT_BUFF_SIZE];
extern char Metric;
extern int  Kernel_Routing;
extern int  Aggressive_Mode;
extern int LQ_check_time;

int32 LQ_last_leave_request_id;

const sp_time dhcp_print_timeout = {15,0};
const sp_time dhcp_gb_timeout = {10,0};
const sp_time link_quality_check_time = {0, 750000}; /* If changed, look at update_freq */

stdhash DHCP_Table;
inline unsigned int compute_metric(dhcp_entry *de);

struct rec {
    int ip;
    int metric;
};

static char _dhcp_msg_type[][20] = { "_", "DHCP_DISCOVER", "DHCP_OFFER",
                                     "DHCP_REQUEST", "DHCP_DECLINE", "DHCP_ACK",
                                     "DHCP_NAK", "DHCP_RELEASE", "DHCP_INFORM" };

static char _dhcp_state[][15] = { "S_IDLE", "S_HEARD", 
                                  "S_OFFE", "S_REQUE",
                                  "S_REGIST", "S_INVAL" };

/* ********************************************************************* *
 * Function:    DHCP_Init()                                              *
 * Description: Construct DHCP Table and clearip lease array             *
 * ********************************************************************* */
void DHCP_Init() 
{
    int dhcp_sk, promisc;
    char bpf[200];  
    pcap_t* pcap_handler;

    stdhash_construct(&DHCP_Table, MAC_SIZE, sizeof(dhcp_entry*),
                      NULL, NULL, 0);

    /* Open incomming channel */
    // dhcp_sk = DL_init_channel (RECV_CHANNEL, (int16) DHCP_PORT_S, 0, 0);
    memset(bpf, 0, sizeof(bpf));
    sprintf(bpf, "udp dst port %d and (! ether src "MACPF") ", 
            DHCP_PORT_S, MAC(LAN_intf_mac));
    if (Metric & METRIC_DHCP || Metric & METRIC_BARP) {
        promisc = 0;
    } else {
        promisc = 1;
    }
    dhcp_sk = init_pcap(LAN_intf_name, promisc, &pcap_handler, bpf);
    max_rcv_buff(dhcp_sk);
    max_snd_buff(dhcp_sk);
    E_attach_fd(dhcp_sk, READ_FD, DHCP_Receive, 0, (void*)pcap_handler, HIGH_PRIORITY);

    LQ_last_leave_request_id = 1;
    DHCP_LinkState_Check();
    DHCP_Print_Table();
    
    if (Metric & METRIC_DHCP) {
        DHCP_lq_check(0, NULL);
    } 

    LQ_Check_DataGroup(0, NULL);
    LQ_check_time = 0;
}

/* ********************************************************************* *
 * Function:    DHCP_Receive()                                           *
 * ********************************************************************* */
void DHCP_Receive(int sk, int dummy, void *pcap_handler) 
{
    unsigned char mac[MAC_SIZE];
    int received_bytes, old_metric, pkt_type;
    dhcp_header hdr;
    dhcp_opts_parsed opts;
    dhcp_entry *de;
    char *recv_packet = NULL;
    
    Alarm(DEBUG_DHCP, PRINT_FUNCTION_HEADER);

    /* Do a pcap socket.  Cannot use regular socket regular dhcp requests 
       since they are directed to fake ip in the ip header on barp metric mode */
    received_bytes = get_next_ip_packet(&recv_packet, (pcap_t*)pcap_handler, &pkt_type);
    recv_packet = (char*)recv_packet + _IP_SIZE + _UDP_SIZE;
    received_bytes = received_bytes - _IP_SIZE - _UDP_SIZE;

    if (received_bytes == 0) { 
        return; 
    }
    Alarm(DEBUG_DHCP, "DHCP_Recv() Received %d bytes\n", received_bytes);

    /* retrieve the DHCP header from the packet */
    memset(&hdr, 0, sizeof(hdr));
    DHCP_grab_header(&hdr, recv_packet, received_bytes);

    /* verify the magic cookie */
    if(hdr.magic_cookie != DHCP_MAGIC_COOKIE)
        Alarm(DEBUG_DHCP,"DHCP magic cookie invalid (0x%X)\n", hdr.magic_cookie);

    /* retrieve the DHCP options from the packet */
    memset(&opts, 0, sizeof(opts));
    DHCP_parse_options(&opts, &recv_packet[sizeof(hdr)], received_bytes - sizeof(hdr));
    memcpy(mac, hdr.chaddr, MAC_SIZE);

    /* if the message is not for me, do not respond...Why? */
    /*
    if (opts.server_ip != LAN_intf_ip && opts.server_ip != 0 && 
            opts.server_ip != DHCP_FAKE_GATEWAY(x)) 
        Alarm(DEBUG_DHCP,"DHCP Message meant for another server. Ignore\n");
        return;
    }
    */

    if((de = DHCP_Lookup_Entry((char*)mac))) {
        Alarm(DEBUG_DHCP,"DHCP entry found\n");
        memcpy(de->hostname, opts.hostname, opts.hostname_len);
    } 
    else {
        Alarm(DEBUG_DHCP,"DHCP entry not found\n");
        /* Security: Only create an entry if we have a DISCOVER or REQUEST */
        if (opts.msg_type != DHCP_DISCOVER && opts.msg_type != DHCP_REQUEST) {
            Alarm(DEBUG_DHCP, "DHCP_Recv(): Not a valid packet for no entry: Ignoring\n");
            return;
        }
        /* If node is already created, assign requested IP as it is valid. 
         * If node does not exist, then assign from my pool */
        DHCP_Create_Entry((char*)mac);
        if(!(de = DHCP_Lookup_Entry((char*)mac))) {
            Alarm(EXIT,"Unable to lookup newly created dhcp_entry\n");
        }
        memcpy(de->hostname, opts.hostname, opts.hostname_len);
        Alarm(DEBUG_DHCP, "Joining CTRL group ["IPF"]\n", IP(IP_TO_CTRL_MCAST(de->ip_addr)));
        de->groups = GROUP_STAT_JOINED_CTRL;
        smesh_add_membership(Mcast_Control_sk, IP_TO_CTRL_MCAST(de->ip_addr));
    }

    old_metric = de->bcast_lq_metric;
    de->dhcp_last_time_heard = E_get_time();
    de->bcast_lq_metric = de->bcast_lq_metric * (1 - LQ_decay_factor) +  (int)(LQ_max) * LQ_decay_factor;
         
    /* If metric did not change, just go up a little */
    if (old_metric == de->bcast_lq_metric && de->bcast_lq_metric < (int)(LQ_max)) {
        de->bcast_lq_metric = de->bcast_lq_metric + 1;
    }

    Alarm(DEBUG_DHCP, "DHCP_receive: metric = %5lf\n", de->bcast_lq_metric);
    
    DHCP_Respond(de, &hdr, &opts);
    Alarm(DEBUG_DHCP, PRINT_FUNCTION_FOOTER);
    return;
}

/* Grab headers from DHCP Packet */
void DHCP_grab_header(dhcp_header* hdr, char *buffer, const int size) 
{
    if(size < sizeof(hdr)) {
        Alarm(DEBUG_DHCP,"Error: received DHCP packet is too small (%d) < (%d)\n",
              size, sizeof(hdr));
        return;
    }

    memcpy(hdr, buffer, sizeof(*hdr));

    hdr->xid = ntohl(hdr->xid);
    hdr->secs = ntohs(hdr->secs);
    hdr->flags = ntohs(hdr->flags);
    hdr->ciaddr = ntohl(hdr->ciaddr);
    hdr->yiaddr = ntohl(hdr->ciaddr);
    hdr->siaddr = ntohl(hdr->ciaddr);
    hdr->giaddr = ntohl(hdr->ciaddr);
    hdr->magic_cookie = ntohl(hdr->magic_cookie);

    return;
}

/* Parse common headers available in the DHCP Packet */
void DHCP_parse_options(dhcp_opts_parsed *opts, char *buffer, const int size) 
{
    unsigned int idx = 0;
    unsigned int idx2, len;
    char mac_buffer[6];

    /* Grab and verify magic cookie */
    if(size < 4) {
        Alarm(DEBUG_DHCP,"DHCP Parser  : options too small; maigc cookie not found\n");
        return;
    }

    while(idx < size) {
        if((idx + 1 >= size) && ((unsigned char) buffer[idx] != DHCP_O_END)) {
            Alarm(DEBUG_DHCP,"DHCP Parser   : Premature end of packet\n");
            return;
        }

        switch((unsigned char) buffer[idx++]) 
        {
        case DHCP_O_PADDING:
            break;
    
        case DHCP_O_HOSTNAME:
            len = buffer[idx];
            VERIFY_SIZE(len);
            idx++;
            if (len >= DHCP_MAX_OPT_LEN) {
                opts->hostname_len = DHCP_MAX_OPT_LEN;
            } else {
                opts->hostname_len = len+1;
            }
            memcpy(opts->hostname, &buffer[idx], opts->hostname_len);
            opts->hostname[(opts->hostname_len-1)] = '\0';
            idx+=len;
            break;
    
        case DHCP_O_REQ_IP:
            VERIFY_SIZE(4);
            idx++;
            opts->req_ip = ntohl(*((unsigned int*) &buffer[idx]));
            idx+=4;
            break;
    
        case DHCP_O_MSG_TYPE:
            VERIFY_SIZE(1);
            opts->msg_type = buffer[++idx];
            idx+=1;
            break;
    
        case DHCP_O_SERVER:
            VERIFY_SIZE(4);
            idx++;
            opts->server_ip = ntohl(*((unsigned int*) &buffer[idx]));
            idx+=4;
            break;
    
        case DHCP_O_PARAM_REQ:
            VERIFY_SIZE(0);
            idx2 = buffer[idx++];
            while(idx2--) {
                idx++;
            }
            break;
    
        case DHCP_O_VENDOR:
            len = buffer[idx];
            VERIFY_SIZE(len);
            idx++;
            if (len >= DHCP_MAX_OPT_LEN) {
                opts->vendor_len = DHCP_MAX_OPT_LEN;
            } else {
                opts->vendor_len = len+1;
            }
            memcpy(opts->vendor, &buffer[idx], opts->vendor_len);
            opts->vendor[(opts->vendor_len-1)] = '\0';
            idx+=len;
            break;
    
        case DHCP_O_CLIENT_ID:
            VERIFY_SIZE(buffer[idx++]);
    
            /* verify that the size is of known length */
            /* MAC address (6 bytes) + 1 byte for the hardware type = 7 */
            /* NILO: BUG FOUND HERE! if(buffer[idx] != 7)  idx++; */

            /* make sure that Ethernet hardware type (0x01) is specified */
            if(buffer[idx++] != 0x01) {
                Alarm(DEBUG_DHCP,"DHCP Parser : Unknown hardware type in client identifier (%d)\n", (unsigned char) buffer[idx]);
                return;
            }
            memset(mac_buffer, 0, 6);
            memcpy(mac_buffer,&buffer[idx],6);
            idx += 6;
            break;
    
        case DHCP_O_AUTO_CONFIG:
            VERIFY_SIZE(buffer[idx]);
            idx+=2;
            break;
    
        case DHCP_O_END:
            return;
            break;
    
        default:
            Alarm(DEBUG_DHCP,"DHCP Parser   : Unknown option code encountered: %3d (0x%.2x)\n", (unsigned char) buffer[idx - 1], (unsigned char) buffer[idx - 1]);
            idx += buffer[idx] + 1;
        } /* end switch */
    } /* end while */
}

/* State machine: Respond depending on packet type and current state. */
void DHCP_Respond(dhcp_entry *de, dhcp_header *hdr, dhcp_opts_parsed *opts) 
{
    int force_bcast = 0;
    unsigned char mac[MAC_SIZE];
    
    Alarm(DEBUG_DHCP, PRINT_FUNCTION_HEADER);

    Alarm(DEBUG_DHCP,"Determining response to packet: ");
    Alarm(DEBUG_DHCP,"%s\n\n", _dhcp_msg_type[opts->msg_type]);

    memcpy(mac, hdr->chaddr, MAC_SIZE);

    switch(opts->msg_type) 
    {
    case DHCP_DISCOVER:
        /* respond with an offer */
        de->state = STATE_DHCP_HEARD;
        DHCP_Send_Packet(de, hdr->xid, ((hdr->flags & DHCP_BROADCAST) == DHCP_BROADCAST), 1);
        de->state = STATE_DHCP_OFFERED;
        break;
    case DHCP_REQUEST:
        if (opts->req_ip == 0) {
            opts->req_ip = hdr->ciaddr;
        }
        /* If the IP is the one assinged to the client */
        Alarm(PRINT, "BUG1: "IPF"  OPTS->req_ip = "IPF"  and HDR->ciaddr = "IPF" \n",
                IP(de->ip_addr), IP(opts->req_ip), IP(hdr->ciaddr));
        if (de->ip_addr == opts->req_ip) {
            de->state = STATE_DHCP_REQUESTED;
            DHCP_Send_Packet(de, hdr->xid, ((hdr->flags & DHCP_BROADCAST) == DHCP_BROADCAST), force_bcast);
            de->state = STATE_DHCP_REGISTERED;
        } else { 
            // Respond with a NACK to start Discovery again
            de->state = STATE_DHCP_INVALID;
            DHCP_Send_Packet(de, hdr->xid, ((hdr->flags & DHCP_BROADCAST) == DHCP_BROADCAST), 1);
            DHCP_Remove_Entry(de);
            return;
        } 
        break;
    case DHCP_RELEASE:
        Alarm(DEBUG_DHCP,"DHCP Release Received.\n");
        if(DHCP_IN_CLIENT_NET(hdr->ciaddr)) {
            DHCP_Remove_Entry(de);
            return;
        }
        break;
    case DHCP_DECLINE:
        Alarm(DEBUG_DHCP,"Someone has declined an offered IP: "IPF"\n", IP(ntohl(hdr->ciaddr)));
        if(DHCP_IN_CLIENT_NET(hdr->ciaddr)) {
            DHCP_Remove_Entry(de);
            return;
        }
        break;
    case DHCP_INFORM:
        Alarm(DEBUG_DHCP,"DHCP Inform Received.\n");
        break;
    default:
        Alarm(DEBUG_DHCP,"Not responding due to unknown dhcp state (%d): \n",opts->msg_type);
    }
    Alarm(DEBUG_DHCP, PRINT_FUNCTION_FOOTER);
}

void DHCP_Send_Packet(dhcp_entry *de, unsigned int32 xid, int bcast_flag, int force_bcast) 
{
    char packet[DHCP_PACKET_SIZE];
    char *dest_mac_addr;
    dhcp_header *hdr;
    unsigned int idx = 0;
    unsigned int32 ip_addr_net;
    unsigned int32 temp_int, dest_ip;

    Alarm(DEBUG_DHCP, PRINT_FUNCTION_HEADER);
    
    memset(packet, 0, sizeof(packet));
    hdr = (dhcp_header*) packet;

    ip_addr_net = htonl(de->ip_addr);

    /* build the DHCP header */
    hdr->op = DHCP_BOOTREPLY;
    hdr->htype = DHCP_ETHERNET;
    hdr->hlen = MAC_SIZE;
    hdr->hops = 0;
    hdr->xid = htonl(xid);
    hdr->secs = 0;
    if(bcast_flag) {
        hdr->flags = htons(DHCP_BROADCAST);
    } else {
        hdr->flags = htons(DHCP_UNICAST);
    }
    hdr->ciaddr = 0;
    hdr->yiaddr = ip_addr_net;
    hdr->siaddr = 0;
    hdr->giaddr = 0;
    memcpy(hdr->chaddr, de->mac_addr, MAC_SIZE);
    hdr->magic_cookie = htonl(DHCP_MAGIC_COOKIE);

    /****************/
    /* DHCP options */
    /****************/
    idx = sizeof(dhcp_header);

    /* message type */
    packet[idx++] = DHCP_O_MSG_TYPE;
    packet[idx++] = 1;
    if(de->state == STATE_DHCP_HEARD) {
        packet[idx++] = DHCP_OFFER;
        Alarm(DEBUG_DHCP,"Sending: offer\n"); 
    } else if (de->state == STATE_DHCP_INVALID) {
        packet[idx++] = DHCP_NAK;
        Alarm(DEBUG_DHCP,"Sending: nack\n"); 
    } else if (de->state == STATE_DHCP_REQUESTED){
        packet[idx++] = DHCP_ACK;
        Alarm(DEBUG_DHCP,"Sending: ack\n"); 
    }

    /* DHCP server ID */
    packet[idx++] = DHCP_O_SERVER;
    packet[idx++] = 4;
    temp_int = htonl(DHCP_FAKE_GATEWAY_X(de->ip_addr));
    memcpy(&packet[idx], &temp_int, 4);
    idx+=4;

    /* lease length */
    packet[idx++] = DHCP_O_LEASE_LENGTH;
    packet[idx++] = 4;
    temp_int = htonl((int) Main_Lease_Time);
    memcpy(&packet[idx], &temp_int, 4);
    idx+=4;

    /* T1 and T2 Timers */
    if (Metric & METRIC_DHCP) 
    {
    packet[idx++] = DHCP_O_T1;
    packet[idx++] = 4;
    if (Metric & METRIC_DHCP) {
        temp_int = htonl((int) Hello_Bcast_Timeout);
    } else {
        temp_int = htonl((int) (Main_Lease_Time*2.0/5.0));
    }
    memcpy(&packet[idx], &temp_int, 4);
    idx+=4;

    /* T1 and T2 Timers */
    packet[idx++] = DHCP_O_T2;
    packet[idx++] = 4;
    if (Metric & METRIC_DHCP) {
        temp_int = htonl((int) Hello_Bcast_Timeout-1);
    } else {
        temp_int = htonl((int) (Main_Lease_Time*4.0/5.0));
    }
    memcpy(&packet[idx], &temp_int, 4);
    idx+=4;
    }

    /* subnet mask */
    packet[idx++] = DHCP_O_SUBNET;
    packet[idx++] = 4;
    temp_int = htonl(DHCP_CLIENT_MASK);
    memcpy(&packet[idx], &temp_int, 4);
    idx+=4;

#if 0
  /* domain name */
  packet[idx++] = DHCP_O_DOMAIN;
  packet[idx++] = strlen(domain);
  memcpy(&packet[idx], domain, strlen(domain));
  idx+= strlen(domain);
#endif

    /* router IP */
    packet[idx++] = DHCP_O_ROUTER;
    packet[idx++] = 4;
    temp_int = htonl(DHCP_FAKE_GATEWAY_X(de->ip_addr));
    memcpy(&packet[idx], &temp_int, 4);
    idx+=4;

    /* DNS servers */
    packet[idx++] = DHCP_O_DNS;
    packet[idx++] = 4*3;
    temp_int = htonl(DNS1);
    memcpy(&packet[idx], &temp_int, 4);
    idx+=4;
    temp_int = htonl(DNS2);
    memcpy(&packet[idx], &temp_int, 4);
    idx+=4;
    temp_int = htonl(DNS3);
    memcpy(&packet[idx], &temp_int, 4);
    idx+=4;

    /* end message */
    packet[idx++] = DHCP_O_END;

    /* address the packet */
    if(force_bcast) {
        dest_ip = DHCP_BCAST_ADDR;
        dest_mac_addr = (char*)MAC_BCAST_ADDR;
    } else {
        dest_ip = de->ip_addr;
        dest_mac_addr = (char*)de->mac_addr;
    }

    Alarm(DEBUG_DHCP,"\nSending DHCP response to: "IPF" \n", IP(de->ip_addr));

    DHCP_send_pkt(packet, sizeof(packet), LAN_intf_ip, DHCP_PORT_S, dest_ip, DHCP_PORT_C, LAN_intf_ifindex, dest_mac_addr);
    Alarm(DEBUG_DHCP, PRINT_FUNCTION_FOOTER);
}

dhcp_entry* DHCP_Lookup_Entry(const char *mac_addr) 
{
    dhcp_entry *de;
    stdit it;

    stdhash_find(&DHCP_Table, &it, mac_addr);
    Alarm(DEBUG_DHCP, "Lookup: Looking for MAC "MACPF" \n", MAC(mac_addr));
    if(!stdhash_is_end(&DHCP_Table, &it)) {
        /* entry found */
        de = *((dhcp_entry **)stdhash_it_val(&it));
    } else { 
        de = NULL;
    }
    return de;
}

inline char verify_size(unsigned char field_size, unsigned char expected_size, unsigned int total_size, unsigned int idx)
{
    char ret = 1;
    /* Verify the expected size of the option */
    if(expected_size != 0 && field_size != expected_size) {
        Alarm(DEBUG_DHCP,"DHCP option with unexpected size\n");
        ret = 0;
    }
    /* Prevent overflow problems */
    if(field_size + idx >= total_size) {
        Alarm(DEBUG_DHCP,"DHCP option with overflow size\n");
        ret = 0;
    }
    return ret;
}

void DHCP_LinkState_Check()
{
    stdit dhcp_it;
    dhcp_entry *de, *de_array[5];
    sp_time now;
    int i;

    now = E_get_time();
    i = 0;

    stdhash_begin(&DHCP_Table, &dhcp_it);

    /* Go through all my DHCP clients nodes */
    while(!stdhash_is_end(&DHCP_Table, &dhcp_it) && i<5) {
        de = *((dhcp_entry **)stdhash_it_val(&dhcp_it));
        /* When do I want to stop taking packets from client */
        if ((now.sec - de->dhcp_last_time_heard.sec) > Main_Lease_Time) {
            de->state = STATE_DHCP_IDLE;
            de_array[i++] = DHCP_Lookup_Entry((char*)(de->mac_addr));
        } 
        stdhash_it_next(&dhcp_it);
    }
    while (i>0) {
        DHCP_Remove_Entry(de_array[--i]);
    }

    E_queue(DHCP_LinkState_Check, 0, NULL, dhcp_gb_timeout);
}


/* Remove DHCP Entry from DHCP Table and if a spines node
 * exists for this node, disconnect the link */
void DHCP_Remove_Entry(dhcp_entry *de)
{
    Alarm(DEBUG_DHCP,"Removing DHCP Client Node "IPF" MAC "MACPF"\n", 
          IP(de->ip_addr), MAC(de->mac_addr));

    if ((de->groups & GROUP_STAT_JOINED_CTRL) == GROUP_STAT_JOINED_CTRL) {
        smesh_drop_membership(Mcast_Control_sk, IP_TO_CTRL_MCAST(de->ip_addr));
    }
    if ((de->groups & GROUP_STAT_JOINED_DATA) == GROUP_STAT_JOINED_DATA) {
        if (Kernel_Routing == 0 || Kernel_Routing & KR_CLIENT_MCAST_PATH) {
            smesh_drop_membership(Mcast_Client_sk, IP_TO_DATA_MCAST(de->ip_addr));
        }
        if (Kernel_Routing & KR_CLIENT_ACAST_PATH) {
            smesh_drop_membership(Mcast_Client_sk, IP_TO_DATA_ACAST(de->ip_addr));
        }
    }

    stdhash_destruct(&(de->lq_hash));
    stdhash_erase_key(&DHCP_Table, de->mac_addr);
    free(de);
}


void DHCP_Create_Entry(const char *mac_addr) 
{
    dhcp_entry *de;
    stdit it;

    if ( (de = (dhcp_entry*) malloc(sizeof(dhcp_entry))) == NULL) {
        Alarm(EXIT, "DHCP_Create_Entry: Cannot allocate entry object\n");
    }

    memset(de, 0, sizeof(dhcp_entry));
    memcpy(de->mac_addr, mac_addr, MAC_SIZE);
    de->state = STATE_DHCP_IDLE;
    de->groups = GROUP_STAT_IDLE;
    de->dhcp_last_time_heard = E_get_time();
    de->barp_last_time_heard = E_get_time();
    de->uarp_last_time_heard = E_get_time();
    de->join_time = E_get_time();
    de->ip_addr = MAC_TO_IP((char*)mac_addr);

    de->bcast_lq_metric = 0;
    de->ucast_lq_metric = 0;
    de->rssi = 0;
    de->lq_leave_request_id = 0;

    stdhash_construct(&de->lq_hash, sizeof(int), sizeof(link_quality_entry),
                    NULL, NULL, 0);

    stdhash_insert(&DHCP_Table, &it, mac_addr, &de);
}

void DHCP_Print_Table() 
{
    dhcp_entry *de;
    stdit it;

    Alarm(PRINT,"DHCP Table\n");
    Alarm(PRINT,"\n");
    Alarm(PRINT,"[Quality] MAC Address        IP Address       State       Hostname\n");
    Alarm(PRINT,"--------------------------------------------------------------------------\n");

    stdhash_begin(&DHCP_Table, &it);
    while(!stdhash_is_end(&DHCP_Table, &it)) {
        de = *((dhcp_entry **)stdhash_it_val(&it));
        /* Alarm(PRINT, "%4d %4d ", de->lq_req_cnt[de->lq_max_time], de->lq_crt_time); */
        Alarm(PRINT, "%4d ", METRIC(de));
        Alarm(PRINT, MACPF"  "IPF"  ", MAC(de->mac_addr), IP(de->ip_addr));
        Alarm(PRINT,"%s  ", _dhcp_state[de->state]);
        Alarm(PRINT,"%s\n", de->hostname);
        stdhash_it_next(&it);
    }
    Alarm(PRINT,"\n--------------------------------------------------------------------------\n\n");
    E_queue(DHCP_Print_Table, 0, NULL, dhcp_print_timeout);
}

void DHCP_send_pkt(char *pkt, int pkt_size, int32 src_ip, 
                           int source_port, int32 dest_ip, 
                           int dest_port, int dest_ifindex, char *dest_mac)
{
    int ret;
    struct my_ip   *ip;
    struct my_udp  *udp;

    memset(Packet_Buff, 0, sizeof(Packet_Buff));

    /* Fill IP header */
    ip = (struct my_ip*)(Packet_Buff);
    IP_V_SET (ip, 4);
    IP_HL_SET (ip, 20);
    ip->ip_tos = 0;
    ip->ip_len = htons(_IP_SIZE + _UDP_SIZE + pkt_size);
    ip->ip_id = 0;
    ip->ip_off = 0;
    ip->ip_ttl = 16;
    ip->ip_p = IPPROTO_UDP;
    ip->ip_sum = 0;
    ip->ip_src.s_addr = htonl(src_ip);
    ip->ip_dst.s_addr = htonl(dest_ip);

    /* Fill UDP header */
    udp = (struct my_udp*)((char *)ip + _IP_SIZE);
    udp->source_port = htons(source_port);
    udp->dest_port = htons(dest_port);
    udp->len = htons(_UDP_SIZE + pkt_size); 
    udp->sum = 0;

    /* Fill Data and compute checksum */
    memcpy(((char*)udp + _UDP_SIZE), pkt, pkt_size);
    pkt_checksum((char *)ip);
  
    /* Send Packet */
    ret = send_raw_eth_pkt(Packet_Buff, ntohs(ip->ip_len), ETH_P_IP, dest_ifindex, dest_mac);
    if (ret <= 0) {
        Alarm(PRINT, "Error sending DHCP packet\n");
    }
}

/* update link quality counters for all clients */
void DHCP_lq_check(int dummy_i, void *dummy_p)
{
    stdit dhcp_it;
    dhcp_entry *de;
    sp_time now, diff, update_time;

    Alarm(DEBUG_LQ, PRINT_FUNCTION_HEADER);

    now = E_get_time();
    update_time.sec = Hello_Bcast_Timeout;
    update_time.usec = 500000;

    stdhash_begin(&DHCP_Table, &dhcp_it);
    while(!stdhash_is_end(&DHCP_Table, &dhcp_it)) {
        de = *((dhcp_entry **)stdhash_it_val(&dhcp_it));
        diff = E_sub_time(now, de->dhcp_last_time_heard);
        if (E_compare_time(diff, update_time) > 0) {
            de->bcast_lq_metric = de->bcast_lq_metric * (1 - LQ_decay_factor);
            if (de->groups & GROUP_STAT_JOINED_DATA)  {
                LQ_Check_DataGroup(Aggressive_Mode, de);
            }
        }
        Alarm(DEBUG_LQ, "DHCP LQ Update: Client="IPF"  heard_diff=%ld,%ld  METRIC=%d", 
                IP(de->ip_addr), de->dhcp_last_time_heard.sec, 
                de->dhcp_last_time_heard.usec, METRIC(de));
        stdhash_it_next(&dhcp_it);
    }
    Alarm(DEBUG_LQ, PRINT_FUNCTION_FOOTER);
    E_queue(DHCP_lq_check, 0, NULL, update_time);
}

// search for an IP address in DHCP table and return the MAC
dhcp_entry* DHCP_Reverse_Lookup(unsigned int ip_addr)
{
    stdit dhcp_it;
    dhcp_entry *de;

    stdhash_begin(&DHCP_Table, &dhcp_it);

    while(!stdhash_is_end(&DHCP_Table, &dhcp_it)) {
        de = *((dhcp_entry **)stdhash_it_val(&dhcp_it));

        if (ip_addr == de->ip_addr) {
            Alarm(DEBUG_DHCP, "dhcp_reverse_lookup: "IPF" -> "MACPF"\n", IP(ip_addr), MAC(de->mac_addr));
            return de;
        }
        stdhash_it_next(&dhcp_it);
    }
    Alarm(DEBUG_DHCP, "dhcp_reverse_lookup: "IPF" not found\n", IP(ip_addr));
        return NULL;
}

/* Periodic event to check if the node must join DATA group for a client
 * TODO: change to handle one client at a time
 */
void LQ_Check_DataGroup(int force_update, void* lr_de)
{
    stdit dhcp_it;
    stdit lq_it;
    link_quality_entry *lq_entry;
    dhcp_entry *de;
    char   log_msg[512];
    sp_time now, stop;
    unsigned char previous_group_state = 0;
    static int send_update_coin = -1;
    int i, j, update_freq;
    int ret, ignore;
    int ip_ctrl_num, ip_data_num;
    int nr_ctrl, nr_data;
    smesh_packet *smesh_pkt_p;
    struct sockaddr_in dest;
    link_quality_pkt lq_pkt;
    struct rec ip_ctrl[MAX_LISTENERS];
    struct rec ip_data[MAX_LISTENERS];
    static char SMesh_Packet[sizeof(smesh_packet)];

    Alarm(DEBUG_LQ, PRINT_FUNCTION_HEADER);

    now = E_get_time();
  
    /* new update */
    smesh_pkt_p = (smesh_packet *) &SMesh_Packet;
    smesh_pkt_p->p_type = htonl(LINK_QUALITY);
    smesh_pkt_p->sender_ip = htonl(LAN_intf_ip);

    if (Aggressive_Mode) {
        update_freq = 3;
    } else {
        update_freq = 6;
    }

    if (lr_de == NULL) {
        send_update_coin = (send_update_coin+1)%update_freq;
    }

    stdhash_begin(&DHCP_Table, &dhcp_it);
    while (!stdhash_is_end(&DHCP_Table, &dhcp_it)) {
        de = *((dhcp_entry **)stdhash_it_val(&dhcp_it));

        if (lr_de != NULL) {
            de = lr_de;
            stdhash_end(&DHCP_Table, &dhcp_it);
        } else {
            stdhash_it_next(&dhcp_it);
        }

        if (!(de->groups & GROUP_STAT_JOINED_CTRL)) {
            continue;
        }

        Alarm(DEBUG_LQ, "LQ_Check_DataGroup: checking "IPF":\n", IP(de->ip_addr));
        assert(de);

        /* fill the update */
        lq_pkt.linkq = htonl(METRIC(de));
        lq_pkt.leave_request_id = 0;
        lq_pkt.leave_ack_cnt = 0;
        memcpy(lq_pkt.client_mac, de->mac_addr, MAC_SIZE);
    
        /* Do not join if the link has not been up for some time, but 
           do send my metric later if necessary */
        ignore = 0;
        if ((now.sec - de->join_time.sec) < 5)  {
            ignore = 1;
        }

        ip_data_num = 0;
        ip_ctrl_num = 0;

        /* Create two vectors, one with everyone in the data group, and
           another with everyone in the control group, ordered by metric/ip.
           Table will not contain myself or expired updates for failover  */
        stdhash_begin(&de->lq_hash, &lq_it);
        while (!ignore && !stdhash_is_end(&de->lq_hash, &lq_it)) {
            lq_entry = (link_quality_entry *)stdhash_it_val(&lq_it);
            stdhash_it_next(&lq_it);

            Alarm(DEBUG_LQ, "\texamining "IPF"\n", IP(lq_entry->sender_ip));
        
            if (lq_entry->sender_ip == LAN_intf_ip)
                continue;

            /* If too old, possibly a failure, partition, or no longer hearing client */
            if ((now.sec - lq_entry->last_time_heard.sec) > (3*update_freq)+1) {
                Alarm(DEBUG_LQ, "\tignoring "IPF" - old\n", IP(lq_entry->sender_ip));
            } else {
                /* sort by the metric and then by IP */
                i = 0;
                if (lq_entry->groups & GROUP_STAT_JOINED_DATA) {
                    while (i < ip_data_num) {
                        if ((ip_data[i].metric < lq_entry->linkq) ||
                            ((ip_data[i].metric == lq_entry->linkq) && (ip_data[i].ip > lq_entry->sender_ip)))
                            break;
                        i++;
                    }
                    for (j = ip_data_num; j > i; j--) {
                        ip_data[j].metric = ip_data[j - 1].metric;
                        ip_data[j].ip = ip_data[j - 1].ip;
                    }
                    ip_data[j].metric = lq_entry->linkq;
                    ip_data[j].ip = lq_entry->sender_ip;
                    ip_data_num++;
                } else {
                    /* the same for control group... */
                    while (i < ip_ctrl_num) {
                        if ((ip_ctrl[i].metric < lq_entry->linkq) ||
                            ((ip_ctrl[i].metric == lq_entry->linkq) && 
                             (ip_ctrl[i].ip > lq_entry->sender_ip)))
                            break;
                        i++;
                    }
                    for (j = ip_ctrl_num; j > i; j--) {
                        ip_ctrl[j].metric = ip_ctrl[j - 1].metric;
                        ip_ctrl[j].ip = ip_ctrl[j - 1].ip;
                    }
                    ip_ctrl[j].metric = lq_entry->linkq;
                    ip_ctrl[j].ip = lq_entry->sender_ip;
                    ip_ctrl_num++;
                }
            }
        }
        /* debuging stuff... */
        if (Debug_Flags & DEBUG_LQ) {
            Alarm(DEBUG_LQ, "CTRL list (%d): ", ip_ctrl_num );

            for (i = 0; i < ip_ctrl_num; i++)
                Alarm(DEBUG_LQ, ""IPF" [%d] ", IP(ip_ctrl[i].ip), ip_ctrl[i].metric);
        
            Alarm(DEBUG_LQ, "\nDATA list (%d): ", ip_data_num );

            for (i = 0; i < ip_data_num; i++)
                Alarm(DEBUG_LQ, ""IPF" [%d] ", IP(ip_data[i].ip), ip_data[i].metric);
        }

        /* determine its position in each list */
        previous_group_state = de->groups; 
        if (!ignore) {
            if (!(de->groups & GROUP_STAT_JOINED_DATA)) 
            {
                i = 0;
                while ((i < ip_ctrl_num) &&
                       ((ip_ctrl[i].metric > METRIC(de)) ||
                       ((ip_ctrl[i].metric == METRIC(de)) && 
                        (LAN_intf_ip > ip_ctrl[i].ip)))) 
                {
                    i++;
                }
                nr_ctrl = i;
                sprintf(log_msg, "CTRL_GRP[%d]: ", nr_ctrl);

                /* ignore if not in best Num_Listeners + 1 */
                if (nr_ctrl < Num_Listeners + 1) {
                    /* check the DATA group with the threshold */
                    i = 0;
                    /* find my virtual position */
                    sprintf(log_msg + strlen(log_msg), "["IPF"] better nodes: [my_metric = %d]: ", IP(de->ip_addr), METRIC(de));
                    /* If the other metric with the threshold is better or 
                       equal, add to the number of boxes that should join, 
                       which lessens the probability that I will join */
                    while ((i < ip_data_num) && (METRIC(de) <= (ip_data[i].metric * (1 + LQ_threshold)))) {
                        sprintf(log_msg + strlen(log_msg), ""IPF" ", IP(ip_data[i].ip));
                        i++;
                    }
                    if (i < Num_Listeners) {
                        /* join the group */
                        sprintf(log_msg + strlen(log_msg), " : Total %d : JOINING\n", i);
                        ARP_send_gratuitous_arp(0, de->mac_addr, de->ip_addr); 
                        if (Kernel_Routing == 0 || Kernel_Routing & KR_CLIENT_MCAST_PATH) {
                            smesh_add_membership(Mcast_Client_sk, IP_TO_DATA_MCAST(de->ip_addr));
                        }
                        if (Kernel_Routing & KR_CLIENT_ACAST_PATH) {
                            smesh_add_membership(Mcast_Client_sk, IP_TO_DATA_ACAST(de->ip_addr));
                        }
                        de->groups |= GROUP_STAT_JOINED_DATA;
                        sprintf(log_msg + strlen(log_msg), "["IPF"] Gratuitous ARP Sent: [my_metric = %d]: ", 
                        IP(de->ip_addr), METRIC(de));
                    } else { 
                        sprintf(log_msg + strlen(log_msg), " : Total %d\n", i);
                    }
                }
            } else {
                i = 0;
                while ((i < ip_data_num) &&
                       ((ip_data[i].metric > METRIC(de)) ||
                       ((ip_data[i].metric == METRIC(de)) && (LAN_intf_ip > ip_data[i].ip)))) 
                {
                    i++;
                }
                nr_data = i;
                sprintf(log_msg, "DATA_GRP[%d]: ", nr_data);
        
                if (nr_data < Num_Listeners) {
                    stdhash_begin(&de->lq_hash, &lq_it);
      
                    while (!stdhash_is_end(&de->lq_hash, &lq_it)) {
                        lq_entry = (link_quality_entry *)stdhash_it_val(&lq_it);
                        if ((lq_entry->leave_request_id != 0) && (lq_entry->sender_ip != LAN_intf_ip)) 
                        {
                            /* add the id on ack list */
                            lq_pkt.lra_list[lq_pkt.leave_ack_cnt].ip = htonl(lq_entry->sender_ip);
                            lq_pkt.lra_list[lq_pkt.leave_ack_cnt].leave_request_id = htonl(lq_entry->leave_request_id);
                            lq_pkt.leave_ack_cnt++;
                        }
                        stdhash_it_next(&lq_it);
                    }
                    if (Debug_Flags & DEBUG_LQ) {
                        Alarm(DEBUG_LQ, "new lq_pkt: LR: %d LRA [%d]: ", lq_pkt.leave_request_id, lq_pkt.leave_ack_cnt);
                        for (i = 0; i < lq_pkt.leave_ack_cnt; i++) {
                            Alarm(DEBUG_LQ, ""IPF"[%d] ", IP(ntohl((lq_pkt.lra_list[i]).ip)), ntohl((lq_pkt.lra_list[i]).leave_request_id));
                        }
                        Alarm(DEBUG_LQ, "\n");
                    }
                    if ( (lr_de != NULL && lq_pkt.leave_ack_cnt > 0) || 
                         (lr_de == NULL && send_update_coin == 0)) {
                        sprintf(log_msg + strlen(log_msg), "["IPF"] Gratuitous ARP Sent: [my_metric = %d]: ", IP(de->ip_addr), METRIC(de));
                        ARP_send_gratuitous_arp(0, de->mac_addr, de->ip_addr); 
                    }
                } else {
                    /* request to leave */
                    if (de->lq_leave_request_id == 0) {
                        de->lq_leave_request_id = LQ_last_leave_request_id++;
                    }
                    lq_pkt.leave_request_id = htonl(de->lq_leave_request_id);

                    sprintf(log_msg + strlen(log_msg), "["IPF"] better nodes: [my_metric = %d]: ", IP(de->ip_addr), METRIC(de));
                    for (i =0; i < nr_data; i++) 
                        sprintf(log_msg + strlen(log_msg), ""IPF" ", IP(ip_data[i].ip));
                }
            }
            sprintf(log_msg + strlen(log_msg), "\n");
            Alarm(DEBUG_LQ, "%s", log_msg);
            if (Debug_Flags & DEBUG_LQ && lr_de == NULL) {
                Log(log_msg);
            }
        }

        /* If we just want to ACK a leave request or we are schedule to update */

        if ((lr_de != NULL && lq_pkt.leave_ack_cnt > 0) || lr_de == NULL || force_update) {
            if ((send_update_coin == 0 && lr_de == NULL) || previous_group_state != de->groups || lq_pkt.leave_ack_cnt > 0 || lq_pkt.leave_request_id > 0 || force_update) 
            {
                lq_pkt.groups = de->groups;
                memcpy(smesh_pkt_p->data, &lq_pkt, P_SIZE+LinkQuality_S);
                dest.sin_family = AF_INET;
                dest.sin_port = htons(DUMMY_PORT);
                dest.sin_addr.s_addr = htonl(IP_TO_CTRL_MCAST(de->ip_addr));

                ret = spines_sendto(Mcast_Control_sk, (char *)smesh_pkt_p, P_SIZE+LinkQuality_S, 0, (struct sockaddr *)&dest, sizeof(struct sockaddr)); 
                if (ret != P_SIZE+LinkQuality_S) { 
                    Alarm(EXIT,"error in writing control socket\n");
                }
                sprintf(log_msg, "Client Edge: "IPF" -> "IPF" : %d   Quality: %d   GS: %d   LR: %d \n", 
                        IP(LAN_intf_ip), IP(de->ip_addr), ((de->groups & GROUP_STAT_JOINED_DATA) == GROUP_STAT_JOINED_DATA), 
                        METRIC(de), de->groups, de->lq_leave_request_id); 
                Alarm(DEBUG_LQ, "%s", log_msg);
                if (lr_de == NULL) {
                    Log(log_msg);
                }
            }
        }
    }

    stop = E_get_time();

    if (lr_de == NULL) {
        if (send_update_coin == 0) {
            LQ_check_time = (stop.sec - now.sec)*1000000;
            LQ_check_time += stop.usec - now.usec;
        }
        E_queue(LQ_Check_DataGroup, 0, NULL, link_quality_check_time);
    }
    Alarm(DEBUG_LQ, PRINT_FUNCTION_FOOTER);
}

/* Hash MAC address to an IP with Avalanche Property */
unsigned int oat_hash(void *mac)
{
    unsigned char *p = mac;
    unsigned int h = 0;
    int i;

    for ( i = 0; i < MAC_SIZE; i++ ) {
        h += p[i];
        h += ( h << 10 );
        h ^= ( h >> 6 );
    }

    h += ( h << 3 );
    h ^= ( h >> 11 );
    h += ( h << 15 );

    /* Now convert to a valid IP */
    h = ( (LAN_intf_ip & CLIENT_NETMASK) | (h & 0xFFFFFF) );

    /* Make sure client does not get a backbone ip */
    if ( (h & BACKBONE_NETMASK) == (LAN_intf_ip & BACKBONE_NETMASK) ) {
        h = ( (LAN_intf_ip & CLIENT_NETMASK) | (~h & 0xFFFFFF) );
    }

    /* Client needs address with valid broadcast address */
    h = h & 0xFFFFFFF8;
    h = h | 0x00000001;

    return h;
}


/* Send data to the log group */
void Log(char *str)
{
    int ret;
    smesh_packet *smesh_pkt_p;
    struct sockaddr_in dest;
    static smesh_packet Log_Pkt;

    assert(str);

    smesh_pkt_p = (smesh_packet *) &Log_Pkt;
    smesh_pkt_p->p_type = htonl(LOG);
    smesh_pkt_p->sender_ip = htonl(LAN_intf_ip);

    /* avoiding buffer overflow */
    if (strlen(str) > Log_S - 16) {
        Alarm(PRINT, "Log message too big - ignored");
        return;
    }
    sprintf(smesh_pkt_p->data, ""IPF" %s", IP(LAN_intf_ip), str);
   
    /* sending data to LOG_GROUP */
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DUMMY_PORT);
    dest.sin_addr.s_addr = htonl(LOG_GROUP);

    ret = spines_sendto(Mcast_Control_sk, (char *)smesh_pkt_p, P_SIZE+Log_S, 0, (struct sockaddr *)&dest, sizeof(struct sockaddr)); 
    if (ret != P_SIZE+Log_S) 
        Alarm(EXIT,"error in writing control socket\n");

}

/* Compute the global metric for a client */
inline unsigned int compute_metric(dhcp_entry *de)
{
    int link_metric = 0;
    int temp = 0;
    sp_time now;

    if (Metric & METRIC_UARP) {
        link_metric += de->ucast_lq_metric;
    }
    if (Metric & METRIC_BARP || Metric & METRIC_DHCP) {
        link_metric += de->bcast_lq_metric;
    }
    if (Metric & METRIC_RSSI) {
        if (de->rssi < 0)  {
            temp = 95 + de->rssi;
        } else {
            temp = de->rssi;
        }
        if (temp > 60) {
            temp = 60;
        } else if (temp < 0) {
            temp = 0;
        }

        /* At this point, RSSI is a value between 0 and 60 */
        if (Metric & METRIC_RSSI_L) {
            temp = (int)(LQ_max*((float)temp)/60.0);
        } else if (Metric & METRIC_RSSI_S) {
            /* rssi can be represented well with a sigmoid graph
               check out gnuplot with: plot [-110:0] -1/(1+exp(0.1*x+8)))+1 */
            temp = (int)(LQ_max*(-1/(1+exp(0.1*(int)(temp-95)+8))+1));
            //de->rssi = (int)(LQ_max*(-1/(1+pow(2.7183,(0.1*(int)((wlan->rssi).data)+8))))+1);
            //de->rssi = LQ_max*(140+(int)(wlan->rssi).data)/100;
        }
        /* Ok...no such thing as 0 RSSI, so lets go up one */
        if (temp <= 0) {
            temp = 1;
        }
    }
    now = E_get_time();
    if ((now.sec - de->dhcp_last_time_heard.sec) < (3*Hello_Ucast_Timeout+1)) {
        link_metric += temp + 10;
    }
    return link_metric;
}

