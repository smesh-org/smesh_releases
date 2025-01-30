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
#include "stdutil/src/stdutil/stdhash.h"
#include "stdutil/src/stdutil/stddll.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include <netinet/in.h>
#include <assert.h>

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
#include "spines_lib.h"
#include "pcap.h"
#include "smesh_proxy.h"
#include "ip_cap.h"
#include "dhcp.h"
#include "arp.h"
#include "rssi.h"

int32    LAN_intf_ip;       /* Mesh interface ip */
int32    WAN_intf_ip;       /* Up Link WAN interface ip */
int32    Loopback_ip;
int32    DNS1, DNS2, DNS3; 
int32    DMZ_ip;
int32    Client_Net;
int32    Main_Lease_Time;
int32    Hello_Bcast_Timeout;
int32    Hello_Ucast_Timeout;
int32    LQ_max;
float    LQ_threshold;
float    LQ_decay_factor;
int32    Num_Listeners;
int32    Debug_Flags;
int      LAN_intf_ifindex;
int      WAN_intf_ifindex;
char     LAN_intf_mac[6];
char     WAN_intf_mac[6];
char     LAN_intf_name[20];
char     WAN_intf_name[20];
char     RSSI_intf_name[20];
int      Private_sk, Mcast_Client_sk, Mcast_Control_sk, Hybrid_Mcast_sk, Hybrid_Private_sk; 
int      Wan_sk;
int      SMesh_GW, SMesh_Server, Self_Trans_Proxy, WAN_Available, SMesh_RSSI; 
int      Kernel_Routing, Hybrid_Network; 
char     Metric;
pcap_t*  Pcap_Handler[3];
int      Spines_Port, Spines_Link_Prot;
char     Packet_Buff[PKT_BUFF_SIZE];
char     Local_Packet_Buff[PKT_BUFF_SIZE];
int      Aggressive_Mode;
int      LQ_check_time;

char     Logging;
char*    Log_buffer[MAX_LOG_NUM];
int      Log_msg_num;
char*    Log_filename;


stdhash    NAT_hash;
stdhash    WAN_list_hash;
stdit      it;
NAT_key    nat_k;
NAT_entry  nat_e;

/* Firewall IPs. Currently value has no meaning */
stdhash     Firewall_hash;

/* Stats for debugging */
long pkt_count = 0;
long pkt_wan_count = 0;
long pkt_wan_good_count = 0;
long pkt_mesh_count = 0;
long pkt_mesh_good_count = 0;
long pkt_zero_count = 0;

const sp_time gw_request_fast_timeout = {60,0};   /* Send request for GW Info */
const sp_time gw_request_timeout = {300,0};       /* Send request for GW Info */
const sp_time hybrid_nat_timeout = {5,0};         /* Max time to get Hybrid NAT Node */
const sp_time nat_gc_timeout = {300,0};           /* Garbage collector timeout */
const sp_time nat_expiration_timeout = {6000,0};  /* Max time entry is valid for */
const sp_time print_log_timeout = {20,0};         /* Print the Log_buffer into the file */

int main(int argc, char* argv[]) 
{
    int ret;
    int pcap_sk[3];         /* Hold libpcap sockets */
    char smesh_bpf[500];    /* Hold Berkeley Packet Filter String */
    int loopback;

    Alarm( PRINT, "/===========================================================================\\\n");
    Alarm( PRINT, "| SMesh                                                                     |\n");
    Alarm( PRINT, "| Copyright (c) 2005 - 2008 Johns Hopkins University                        |\n");
    Alarm( PRINT, "| All rights reserved.                                                      |\n");
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "| SMesh is licensed under the SMesh Open-Source License.                    |\n");
    Alarm( PRINT, "| You may only use this software in compliance with the License.            |\n");
    Alarm( PRINT, "| A copy of the License can be found at the LICENSE.txt file provided       |\n");
    Alarm( PRINT, "| with your distribution or by contacting us at smesh@smesh.org.            |\n");
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "| SMesh is developed at the Distributed Systems and Networks Lab,           |\n");
    Alarm( PRINT, "| The Johns Hopkins University.                                             |\n");
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "| Creators:                                                                 |\n");
    Alarm( PRINT, "|    Yair Amir                 yairamir@dsn.jhu.edu                         |\n");
    Alarm( PRINT, "|    Claudiu Danilov           claudiu@dsn.jhu.edu                          |\n");
    Alarm( PRINT, "|    Raluca Musaloiu-Elefteri  ralucam@dsn.jhu.edu                          |\n");
    Alarm( PRINT, "|    Nilo Rivera               nrivera@dsn.jhu.edu                          |\n");
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "| Major Contributors:                                                       |\n");
    Alarm( PRINT, "|    Michael Hilsdale          mhilsdale@dsn.jhu.edu                        |\n");
    Alarm( PRINT, "|    Michael Kaplan            kaplan@dsn.jhu.edu                           |\n");
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "| WWW:     www.smesh.org      www.dsn.jhu.edu                               |\n");
    Alarm( PRINT, "| Contact: smesh@smesh.org                                                  |\n");
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "| Version %s, Built Apr 1, 2008                                             |\n", SMESH_VERSION);
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "| This product uses Spines                                                  |\n");
    Alarm( PRINT, "| For more information about Spines, see http://www.spines.org              |\n");
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "| This product uses software developed by Spread Concepts LLC               |\n");
    Alarm( PRINT, "| for use in the Spread toolkit.                                            |\n");
    Alarm( PRINT, "| For more information about Spread, see http://www.spread.org              |\n");
    Alarm( PRINT, "\\===========================================================================/\n");
    Alarm( PRINT, "| This product uses libpcap with the following copyright:                   |\n");
    Alarm( PRINT, "\\===========================================================================/\n");
    Alarm( PRINT, "  * Copyright (c) 1993, 1994, 1995, 1996, 1997, 1998\n");
    Alarm( PRINT, "  *  The Regents of the University of California.  All rights reserved.\n");
    Alarm( PRINT, "  *\n");
    Alarm( PRINT, "  * Redistribution and use in source and binary forms, with or without\n");
    Alarm( PRINT, "  * modification, are permitted provided that the following conditions\n");
    Alarm( PRINT, "  * are met:\n");
    Alarm( PRINT, "  * 1. Redistributions of source code must retain the above copyright\n");
    Alarm( PRINT, "  *    notice, this list of conditions and the following disclaimer.\n");
    Alarm( PRINT, "  * 2. Redistributions in binary form must reproduce the above copyright\n");
    Alarm( PRINT, "  *    notice, this list of conditions and the following disclaimer in the\n");
    Alarm( PRINT, "  *    documentation and/or other materials provided with the distribution.\n");
    Alarm( PRINT, "  * 3. All advertising materials mentioning features or use of this software\n");
    Alarm( PRINT, "  *    must display the following acknowledgement:\n");
    Alarm( PRINT, "  *  This product includes software developed by the Computer Systems\n");
    Alarm( PRINT, "  *  Engineering Group at Lawrence Berkeley Laboratory.\n");
    Alarm( PRINT, "  * 4. Neither the name of the University nor of the Laboratory may be used\n");
    Alarm( PRINT, "  *    to endorse or promote products derived from this software without\n");
    Alarm( PRINT, "  *   specific prior written permission.\n");
    Alarm( PRINT, "  *\n");
    Alarm( PRINT, "  * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND\n");
    Alarm( PRINT, "  * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n");
    Alarm( PRINT, "  * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE\n");
    Alarm( PRINT, "  * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE\n");
    Alarm( PRINT, "  * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL\n");
    Alarm( PRINT, "  * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS\n");
    Alarm( PRINT, "  * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)\n");
    Alarm( PRINT, "  * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT\n");
    Alarm( PRINT, "  * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY\n");
    Alarm( PRINT, "  * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF\n");
    Alarm( PRINT, "  * SUCH DAMAGE.\n");
    Alarm( PRINT, "\\===========================================================================/\n\n");


    Loopback_ip = (127 << 24) + 1;      /* 127.0.0.1 */
    WAN_Available = FALSE;

    pcap_sk[0] = 0; 
    pcap_sk[1] = 0; 
    pcap_sk[2] = 0; 

    usage(argc, argv);
    init_signals();
    E_init();

    /* Socket to communicate control information */
    Mcast_Control_sk = smesh_socket(LAN_intf_ip, CONTROL_PORT, SOFT_REALTIME_LINKS);
    Mcast_Client_sk = smesh_socket(LAN_intf_ip, 0, Spines_Link_Prot);
    ret = max_rcv_buff(Mcast_Client_sk);
    Alarm(PRINT, "MCAST Client Receive Buffer: %d\n", ret);
    Private_sk = smesh_socket(LAN_intf_ip, PRIVATE_PORT, Spines_Link_Prot);
    ret = max_rcv_buff(Private_sk);
    Alarm(PRINT, "Private Socket Receive Buffer: %d\n", ret);
    ret = max_snd_buff(Private_sk);
    Alarm(PRINT, "Private Socket Send Buffer: %d\n", ret);

    /* Turn off loopback */
    loopback = 0;
    if(spines_setsockopt(Private_sk, IPPROTO_IP, SPINES_MULTICAST_LOOP, (void *)&loopback, sizeof(char)) < 0) {
        printf("Mcast: problem in setsockopt to join multicast address");
        exit(0);
    }
    if(spines_setsockopt(Mcast_Client_sk, IPPROTO_IP, SPINES_MULTICAST_LOOP, (void *)&loopback, sizeof(char)) < 0) {
        printf("Mcast: problem in setsockopt to join multicast address");
        exit(0);
    }

    /* Initialize SMesh Gateway, which takes packets from spines,
     * performs NAT, and forwards to Internet.  Also performs 
     * reverse NAT and sends back to node on the mesh with spines.
     */
    if (SMesh_GW == TRUE) { 
        memset(smesh_bpf, 0, sizeof(smesh_bpf));

        /* Need to set BPF filter to only get what I need through this IF */
        sprintf(smesh_bpf, "ip and dst host "IPF" and (! udp port %d) and (! udp port %d) and (! udp port %d) and (! udp port %d) and (! ip broadcast) and (! udp port %d) and (! tcp port %d)", IP(WAN_intf_ip), Spines_Port, Spines_Port+1, Spines_Port+2, Spines_Port+3, DHCP_PORT_C, SSH_PORT);

        smesh_add_membership(Private_sk, GW_ANYCAST_DATA_GROUP);
        smesh_add_membership(Mcast_Control_sk, GW_ANYCAST_CTRL_GROUP);
        if (Kernel_Routing == 0) 
        {
            pcap_sk[WAN_PKT] = init_pcap(WAN_intf_name, 0, &Pcap_Handler[WAN_PKT], smesh_bpf);
            Wan_sk = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            ret = max_rcv_buff(pcap_sk[WAN_PKT]);
            /* NAT for source and destination address mapping */
            stdhash_construct(&NAT_hash, sizeof(NAT_key), sizeof(NAT_entry),
                              NULL, NULL, 0);
            nat_garbage_collector();
        }
        if (Hybrid_Network) {
            Hybrid_Mcast_sk = smesh_socket(WAN_intf_ip, 0, Spines_Link_Prot);
            Hybrid_Private_sk = smesh_socket(WAN_intf_ip, PRIVATE_PORT, Spines_Link_Prot);
            smesh_add_membership(Hybrid_Mcast_sk, HYBRID_MCAST_DATA_GROUP);
            smesh_add_membership(Mcast_Control_sk, HYBRID_MCAST_CTRL_GROUP);
            send_wan_gw_status();
        }
        WAN_Available = TRUE;
        stdhash_construct(&WAN_list_hash, sizeof(int32), sizeof(short), 
                          NULL, NULL, 0);
        Alarm(PRINT, "SMesh PCAP WAN Receive Buffer: %d\n", ret);
    } 

    /* Initialize SMesh Server which takes and return packets
     * to the the clients on defined interface
     */
    if (SMesh_Server == TRUE) {

    /* Process only IP packets for which  destination is not a backbone
     * node, source is in my network, not a Spines packet, 
     * not a broadcast packet, and not a DHCP packet */

        DHCP_Init();
        ARP_Init();
        smesh_add_membership(Mcast_Control_sk, DHCPS_MCAST_CTRL_GROUP);

        memset(smesh_bpf, 0, sizeof(smesh_bpf));

        /* Need to set BPF filter to only get what I need through this IF */
        sprintf(smesh_bpf, "ip and (src net "IPF" mask "IPF") and (ether dst "MACPF") and (! udp port %d) and (! udp port %d) and (! udp port %d) and (! udp port %d) and (! ip broadcast) and (! udp port %d)", IP(LAN_intf_ip&CLIENT_NETMASK), IP(CLIENT_NETMASK), MAC(LAN_intf_mac), Spines_Port, Spines_Port+1, Spines_Port+2, Spines_Port+3, DHCP_PORT_S);

        if (Kernel_Routing == 0) 
        {
            pcap_sk[LAN_PKT] = init_pcap(LAN_intf_name, 0, &Pcap_Handler[LAN_PKT], smesh_bpf);
            ret = max_rcv_buff(pcap_sk[LAN_PKT]);
        } 
        if (SMesh_RSSI) {
            RSSI_Init();
        }
        send_wan_gw_request();
        Alarm(PRINT, "SMesh PCAP LAN Receive Buffer: %d\n", ret);
    } 

    /* If Self Transparent Proxy then activate loopback
     * Need to set default route to loopback
     *   Application ->  Loopback -> Spines -> Internet
     */
    if (Self_Trans_Proxy == TRUE) { 
        /* Careful not to get sent and received packets */
        pcap_sk[LO_PKT] = init_pcap(LOOPBACK_INTF_NAME, 0, &Pcap_Handler[LO_PKT], "tcp or udp or icmp");
    }

    if (Logging == 1) {
        /* join the LOG group*/
        Alarm(PRINT, "Joining LOG group ["IPF"]\n", IP(LOG_GROUP));
        smesh_add_membership(Mcast_Control_sk, LOG_GROUP);
    }

    /****************************************************
     * Declare Events 
     ****************************************************/
    if (SMesh_Server && Kernel_Routing == 0) {
        /* Check for incomming client packets through sniffer */
        E_attach_fd(pcap_sk[LAN_PKT], READ_FD, process_pcap_pkt, 
                    LAN_PKT, NULL, LOW_PRIORITY );
        /* Handle packets from the backbone to the client */
        E_attach_fd(Mcast_Client_sk, READ_FD, process_backbone_pkt, 
                    MCAST_CLI_PORT, NULL, MEDIUM_PRIORITY );
    } 
    if (SMesh_GW && Kernel_Routing == 0)  {
        /* Check for incomming packets from wan (internet) through sniffer */
        E_attach_fd(pcap_sk[WAN_PKT], READ_FD, process_pcap_pkt, 
                    WAN_PKT, NULL, LOW_PRIORITY ); 
        /* Check for incomming backbone packets */
        E_attach_fd(Private_sk, READ_FD, process_backbone_pkt, 
                    PRIVATE_PORT, NULL, MEDIUM_PRIORITY );
        if (Hybrid_Network) {
            /* Check for incomming hybrid-node packets */
            E_attach_fd(Hybrid_Private_sk, READ_FD, process_backbone_pkt, 
                        PRIVATE_PORT, NULL, MEDIUM_PRIORITY );
            E_attach_fd(Hybrid_Mcast_sk, READ_FD, process_backbone_pkt, 
                        HYBRID_MCAST_DATA_PORT, NULL, MEDIUM_PRIORITY );
        }
    }
    if (Self_Trans_Proxy) {
        /* Check for incomming client (this computer) packets through sniffer */
        E_attach_fd(pcap_sk[LO_PKT], READ_FD, process_pcap_pkt, 
                    LO_PKT, NULL, LOW_PRIORITY );
    }
    E_attach_fd(Mcast_Control_sk, READ_FD, process_control_pkt, 
                CONTROL_PORT, NULL, HIGH_PRIORITY );

    if (Logging == 1) {
        /* Write the Log_buffer into the file */
        E_queue(Print_Log_buffer, 0, NULL, print_log_timeout);
    }
 
    Alarm(PRINT, "\n\nSMESH READY!\n\n", ret);
    E_handle_events();

    return(1);
}

/* Process a Backbone packet */
void process_backbone_pkt(int sk, int port, void *dummy_p) 
{
    int bytes, i;
    struct sockaddr_in from;

    i = sizeof(struct sockaddr);
    bytes = spines_recvfrom(sk, Packet_Buff, PKT_BUFF_SIZE, 0, 
                            (struct sockaddr *)&from, (unsigned int*)&i);

    if(bytes <= 0) {
        Alarm(DEBUG_SMESH,"mcast_recv: Error reading from backbone socket\n");
        clean_exit(0);
    }
    process_backbone_pkt2(Packet_Buff, bytes, port);
}

/* Process a backbone packet */
void process_backbone_pkt2(char *buff, int bytes, int port)
{
    struct my_ip *ip;
    unsigned char *dest_mac;
    ip = (struct my_ip *) buff;

    /* Self-Discard packets that are from myself..not good for gw */
    /*
    if (from.sin_addr.s_addr == htonl(WAN_intf_ip) || 
             from.sin_addr.s_addr == htonl(LAN_intf_ip)) 
    {
        return;
    }
    */

    if (port == PRIVATE_PORT) {
        /* Are we restricting outbound access? */
        if (!stdhash_empty(&Firewall_hash)) {
            stdhash_find(&Firewall_hash, &it, &((ip->ip_src).s_addr));
            if(stdhash_is_end(&Firewall_hash, &it)) {
                return;
            }
        }
        /* Perform forward NAT to destination */
        Alarm(DEBUG_SMESH, "RECEIVED BACKBONE PKT CLIENT->INTERNET\n");
        if (forward_nat(buff, bytes, port)) {
            /* Now forward message to the internet */
            send_raw_ip_pkt(Wan_sk, buff, bytes);
        }
    } else if (port == MCAST_CLI_PORT) {
        /* Deliver back to client computer. Get the MAC from DHCP_Table */
        dest_mac = (DHCP_Reverse_Lookup(ntohl(ip->ip_dst.s_addr)))->mac_addr;
        Alarm(DEBUG_SMESH, "RECEIVED BACKBONE PKK INTERNET->CLIENT ["MACPF"\n",
                MAC(dest_mac));
        send_raw_eth_pkt(buff, bytes, ETH_P_IP, LAN_intf_ifindex, (char*)dest_mac);  
    } else if (port == HYBRID_MCAST_DATA_PORT) {
        Alarm(DEBUG_SMESH, "RECEIVED BACKBONE HYBRID PKT CLIENT->INTERNET\n");
        /* Perform forward NAT to destination */
        if (forward_nat(buff, bytes, port)) {
            /* Now forward message to the internet */
            send_raw_ip_pkt(Wan_sk, buff, bytes);
        }
    }
    if (Debug_Flags & DEBUG_SMESH) {
        print_packet(buff, bytes);
    }
}

/* Process incoming packet by using interceptor on all protocols/ports */
void process_pcap_pkt(int sk, int port, void *dummy_p)
{
    int bytes, dest_addr, ret, pkt_type;
    struct sockaddr_in dest;
    char *recv_packet = NULL;
    dhcp_entry *de;
    
    Alarm(DEBUG_SMESH, PRINT_FUNCTION_HEADER);
    bytes = get_next_ip_packet(&recv_packet, Pcap_Handler[port], &pkt_type);

    if (pkt_type == ETHER_ARP) {
        Alarm(DEBUG_SMESH, "ARP Packet Received. Unexpected\n");
        return;
    } else if (pkt_type != ETHER_IP) {
        Alarm(DEBUG_SMESH, "UNKNOWN Packet Received [%d]\n", pkt_type);
            Alarm(DEBUG_ARP, PRINT_FUNCTION_FOOTER);
        return;
    }

    pkt_count++;

    if (bytes == 0) pkt_zero_count++;
    if (port == WAN_PKT) pkt_wan_count++;
    if (port == LAN_PKT) pkt_mesh_count++;

    if (bytes > 0 && recv_packet != NULL && filter_packet(bytes, recv_packet) != TRUE)
    {
        dest_addr = ntohl(((struct my_ip*)(recv_packet))->ip_dst.s_addr);
        Alarm(DEBUG_SMESH, "START process_pcap_pkt: "IPF"\n", IP(dest_addr));

        /* If packet received from WAN interface */
        if (dest_addr == WAN_intf_ip && port == WAN_PKT) {
            pkt_wan_good_count++;
            /* If packet from the internet, perform reverse NAT to dest */
            if (reverse_nat(recv_packet, bytes) < 0 ) {
                Alarm(DEBUG_SMESH, "Unknown NAT int addr. Ignoring Packet.\n");
                if (Debug_Flags & DEBUG_NAT) {
                    print_packet(recv_packet, bytes);
                }
                return;
            }

            dest_addr = ntohl(((struct my_ip*)(recv_packet))->ip_dst.s_addr);

            /* send to TO_DATA_MCAST also */
            Alarm(DEBUG_SMESH, "process_pcap_pkt [WAN]: sending to "IPF"\n", IP(IP_TO_DATA_MCAST(dest_addr)));
            dest.sin_family = AF_INET;
            dest.sin_port = htons(DUMMY_PORT);
            dest.sin_addr.s_addr = htonl(IP_TO_DATA_MCAST(dest_addr));

            /* Send through backbone to wherever the client is located */
            ret = spines_sendto(Private_sk, (char *)recv_packet, bytes, 0, (struct sockaddr *)&dest, sizeof(struct sockaddr)); 
            if(ret != bytes) {
                Alarm(EXIT, "error in writing socket\n");
            }
            /* If I am servicing the client, send data packet */
            if ((de = DHCP_Reverse_Lookup(dest_addr)) != NULL) {
                if (de->groups & GROUP_STAT_JOINED_DATA) {
                    process_backbone_pkt2((char*) recv_packet, bytes, MCAST_CLI_PORT);
                }
            }

            if (Debug_Flags & DEBUG_SMESH) {
                print_packet(recv_packet, bytes);
            }
        } // end WAN_PKT
        else if ( dest_addr != LAN_intf_ip && port == LAN_PKT) {
            pkt_mesh_good_count++;
            /* If packet from a client in the mesh or loopback */
            dest.sin_family = AF_INET;

            if (!(IP_IN_MY_NET(dest_addr))) {
                /* Want to access the internet */
                Alarm(DEBUG_SMESH, "SENDING THROUGH SPINES TO GATEWAY\n");
                dest.sin_port = htons(PRIVATE_PORT);
                dest.sin_addr.s_addr = htonl(GW_ANYCAST_DATA_GROUP);
                if (!SMesh_GW) {
                    ret = spines_sendto(Private_sk, (char *)recv_packet, bytes, 0, (struct sockaddr *)&dest, sizeof(struct sockaddr)); 
                    if(ret != bytes) {
                        Alarm(EXIT, "error in writing socket\n");
                    } 
                } else {
                    process_backbone_pkt2((char*)recv_packet, bytes, PRIVATE_PORT);
                }
            } else {
                /* Peer to Peer support */
                Alarm(DEBUG_SMESH, "SENDING TO SOMEONE IN MY NETWORK\n");
                Alarm(DEBUG_SMESH, "process_pcap_pkt [P2P]: sending to "IPF"\n", IP(IP_TO_DATA_MCAST(dest_addr)));
                dest.sin_port = htons(DUMMY_PORT);
                dest.sin_addr.s_addr = htonl(IP_TO_DATA_MCAST(dest_addr));
                ret = spines_sendto(Private_sk, (char *)recv_packet, bytes, 0, (struct sockaddr *)&dest, sizeof(struct sockaddr)); 
                if(ret != bytes) {
                    Alarm(EXIT, "error in writing socket\n");
                } 
                if ((de = DHCP_Reverse_Lookup(dest_addr)) != NULL) {
                    if (de->groups & GROUP_STAT_JOINED_DATA) {
                        process_backbone_pkt2((char*)recv_packet, bytes, MCAST_CLI_PORT);
                    }
                }
            }
        } else if (Debug_Flags & DEBUG_SMESH) { // END_LAN_PKT
            Alarm(DEBUG_SMESH, "NOT-FILTERED NOT-PROCESSED");
            print_packet(recv_packet, bytes);
        }
        Alarm(DEBUG_SMESH, "END process_pcap_pkt: "IPF"\n", IP(dest_addr));
    } else if (bytes > 0 && recv_packet != NULL) {
        /* Filtered Packet...check...should be in BPF */
        if (Debug_Flags & DEBUG_SMESH) {
            if (port == WAN_PKT) Alarm(PRINT, "FILTERED WAN PKT\n");
            if (port == LAN_PKT) Alarm(PRINT, "FILTERED LAN PKT\n");
            print_packet(recv_packet, bytes);
        }
    }
    Alarm(DEBUG_DHCP, PRINT_FUNCTION_FOOTER);
}

/* Process a node-to-node SMesh control packet */
void process_control_pkt(int sk, int port, void *dummy_p) 
{
    int i, bytes, ret, status, *pint;
    smesh_packet *smesh_pkt_p;
    gw_response *gw_resp_p;
    gw_status *gw_status_p;
    hybrid_nat *hybrid_nat_p;
    link_quality_pkt *lq_pkt;
    struct sockaddr_in host;
    struct sockaddr_in from_addr;
    unsigned int from_len;
    dhcp_entry *de;
    char   log_msg[255];
    link_quality_entry *lq_entry;
    leave_request_ack lr_ack;
    sp_time recv_time;
    NAT_entry *nat_ep;
    int32 ipaddr;

    Alarm(DEBUG_SMESH, "START: process_control_pkt\n"); 

    from_len = sizeof(from_addr);
    bytes = spines_recvfrom(sk, (char *)Packet_Buff, PKT_BUFF_SIZE, 0, (struct sockaddr *)&from_addr, &from_len);

    if(bytes <= 0) {
        Alarm(PRINT, "recvfrom: Error reading control packet from backbone socket\n");
        clean_exit(0);
    }
    smesh_pkt_p = (smesh_packet*) Packet_Buff;
    Alarm(DEBUG_SMESH, "Received Control Packet: Type %d\n", ntohl(smesh_pkt_p->p_type));

    switch(ntohl(smesh_pkt_p->p_type)) { 
    case LOG:
        // Timestamp
        recv_time = E_get_time();
        Alarm(DEBUG_SMESH, "log: %ld:%ld %s\n", recv_time.sec, recv_time.usec, smesh_pkt_p->data);

        if (Logging == 1) {
            if (Log_msg_num == MAX_LOG_NUM) {
                Alarm(DEBUG_SMESH, "Log message received: not enough space in Log_buff!\n");
            } else {
                Log_buffer[Log_msg_num] = (char *) malloc(Log_S);
                sprintf(Log_buffer[Log_msg_num], "log: %ld:%ld %s", recv_time.sec, recv_time.usec, smesh_pkt_p->data);
                Log_msg_num++;
            }
        }
        break;  
    case LINK_QUALITY:
        lq_pkt = (link_quality_pkt *) smesh_pkt_p->data;
        if (Debug_Flags & DEBUG_LQ) {
            Alarm(DEBUG_LQ, "\nLINK QUALITY PACKET RECEIVED: lq: %d; client: "MACPF" [source: "IPF"]; ",
                    lq_pkt->linkq, MAC(lq_pkt->client_mac), 
                    IP(ntohl(from_addr.sin_addr.s_addr)));
            Alarm(DEBUG_LQ, "GS: %d; LR: %d; %d LRA: ", 
                    lq_pkt->groups, ntohl(lq_pkt->leave_request_id), 
                    lq_pkt->leave_ack_cnt);
            for (i = 0; i < lq_pkt->leave_ack_cnt; i++) {
                lr_ack = lq_pkt->lra_list[i];
                Alarm(DEBUG_LQ, ""IPF"[%d]", IP(ntohl(lr_ack.ip)), 
                    ntohl(lr_ack.leave_request_id));
            }
            Alarm(DEBUG_LQ, "\n");
        }

        /* locate the client and add the update to its hash (was queue) */
        if (!(de = DHCP_Lookup_Entry(lq_pkt->client_mac))) {
            Alarm(DEBUG_LQ, "process_control_pkt: client MAC not found - link quality update ignored\n");
            return;
        }
    
        lq_entry = (link_quality_entry *) malloc(sizeof(link_quality_entry));
        lq_entry->sender_ip = ntohl(from_addr.sin_addr.s_addr);
        lq_entry->linkq = ntohl(lq_pkt->linkq);
        lq_entry->groups = lq_pkt->groups;
        lq_entry->leave_request_id = ntohl(lq_pkt->leave_request_id);
        lq_entry->last_time_heard = E_get_time();
    
        if (Debug_Flags & DEBUG_LQ) {
            sprintf(log_msg, "lq_entry: sender_id: "IPF" group: "IPF" linkq: %d timeval: %d %d GS: %d LR: %d\n", 
                IP(lq_entry->sender_ip), IP(de->ip_addr), lq_entry->linkq, (int)lq_entry->last_time_heard.sec, 
                (int)lq_entry->last_time_heard.usec, lq_entry->groups, lq_entry->leave_request_id);
            Alarm(DEBUG_LQ, "%s", log_msg);
            if (lq_entry->sender_ip == LAN_intf_ip) {
                Log(log_msg);
            }
        }

        /* Update link quality entry */
        stdhash_find(&de->lq_hash, &it, &(lq_entry->sender_ip));
        if(stdhash_is_end(&de->lq_hash, &it)) {
            stdhash_insert(&de->lq_hash, &it, &(lq_entry->sender_ip), (void *)lq_entry);
        } else {
            memcpy(stdhash_it_val(&it), lq_entry, sizeof(link_quality_entry));
        }

        /* leave the data group if a valid ack was received */
        if (Debug_Flags & DEBUG_LQ) {
            Alarm(DEBUG_LQ, "process_control_pkt: de->lq_leave_request_id = %d\n", de->lq_leave_request_id);
            Alarm(DEBUG_LQ, "process_control_pkt: lq_pkt->leave_ack_cnt = %d\n", lq_pkt->leave_ack_cnt);
            Alarm(DEBUG_LQ, "process_control_pkt: lq_pkt->linkq = %d\n", lq_pkt->linkq);
        }
        for (i = 0; i < lq_pkt->leave_ack_cnt; i++) {
            Alarm(DEBUG_LQ, "\t\t\t"IPF"[%d]\n", IP(ntohl(lq_pkt->lra_list[i].ip)), ntohl(lq_pkt->lra_list[i].leave_request_id));
            if ((ntohl(lq_pkt->lra_list[i].ip) == LAN_intf_ip) && (de->lq_leave_request_id != 0) &&
                (ntohl(lq_pkt->lra_list[i].leave_request_id) == de->lq_leave_request_id)) 
            {
                Alarm(DEBUG_LQ, "\tLRA received: %d, LR requested: %d\n", ntohl(lq_pkt->lra_list[i].leave_request_id), de->lq_leave_request_id);
                Alarm(DEBUG_LQ, "\tLeaving DATA group ["IPF"]\n", IP(IP_TO_DATA_MCAST(de->ip_addr)));
                if (Kernel_Routing == 0 || Kernel_Routing & KR_CLIENT_MCAST_PATH) {
                    smesh_drop_membership(Mcast_Client_sk, IP_TO_DATA_MCAST(de->ip_addr));
                }
                if (Kernel_Routing & KR_CLIENT_ACAST_PATH) {
                    smesh_drop_membership(Mcast_Client_sk, IP_TO_DATA_ACAST(de->ip_addr));
                }
                de->lq_leave_request_id = 0;
                de->groups &= ~GROUP_STAT_JOINED_DATA;
                Alarm(DEBUG_LQ, "\tgroups->state = %d\n", de->groups);
            }
        }
    
        /* if a leave request is received, do a check and update immediately */
        if ((lq_entry->sender_ip != LAN_intf_ip) && (lq_entry->leave_request_id != 0) && ((de->groups & GROUP_STAT_JOINED_DATA) == GROUP_STAT_JOINED_DATA)) 
        {
            LQ_Check_DataGroup(0, de);
        }
        free(lq_entry);
        break;
    case WAN_GW_REQUEST:
        /* If I still have internet, respond to sender */
        if (WAN_Available == TRUE) {
            // Address to respond to. TODO: Reverse Anycast?
            host.sin_family = AF_INET;
            host.sin_port = htons(CONTROL_PORT);
            host.sin_addr.s_addr = smesh_pkt_p->sender_ip;

            /* Respond with my ip and DNS information */
            Alarm(DEBUG_SMESH, "Received request from "IPF" for gateway information\n", 
                    IP(ntohl(smesh_pkt_p->sender_ip)));

            smesh_pkt_p->p_type = htonl(WAN_GW_RESPONSE);
            smesh_pkt_p->sender_ip = htonl(LAN_intf_ip);
            gw_resp_p = (gw_response *) smesh_pkt_p->data;
            gw_resp_p->dns1 = htonl(DNS1);
            gw_resp_p->dns2 = htonl(DNS2);
            gw_resp_p->dns3 = htonl(DNS3);
            ret = spines_sendto(Mcast_Control_sk, (char *)Packet_Buff, WanGwResp_S+P_SIZE, 0, 
                    (struct sockaddr *)&host, sizeof(struct sockaddr)); 
            if (ret != WanGwResp_S+P_SIZE) {
                Alarm(PRINT,"error in writing socket\n");
                clean_exit(0);
            } 
        }
        break;
    case WAN_GW_RESPONSE:
        if (WAN_Available == FALSE) {
            /* Update Database with gateway info */
            Alarm(DEBUG_SMESH, "Anycast GW: "IPF"\n", IP(smesh_pkt_p->sender_ip));
            gw_resp_p = (gw_response *) smesh_pkt_p->data;
            DNS1 = ntohl(gw_resp_p->dns1);
            DNS2 = ntohl(gw_resp_p->dns2);
            DNS3 = ntohl(gw_resp_p->dns3);
        }
        break;
    case WAN_GW_STATUS:
        gw_status_p = (gw_status *) smesh_pkt_p->data;
        ipaddr = ntohl(gw_status_p->wan_ip);
        status = (int)ntohs(gw_status_p->status);
        Alarm(DEBUG_SMESH, "Received Gateway Information: SMesh_IP: "IPF" :: GW_IP: "IPF" :: Status: %d\n", 
              IP(ntohl(smesh_pkt_p->sender_ip)), IP(ipaddr), status);
        stdhash_find(&WAN_list_hash, &it, &ipaddr);
        if(stdhash_is_end(&WAN_list_hash, &it)) {
            stdhash_insert(&WAN_list_hash, &it, &ipaddr, &status);
            host.sin_addr.s_addr = gw_status_p->wan_ip;
            if (gw_status_p->wan_ip != htonl(WAN_intf_ip)) {
                Alarm(DEBUG_SMESH, "\t--calling SPINES_ADD_NEIGHBOR \n"); 
                spines_ioctl(Hybrid_Mcast_sk, 0, SPINES_ADD_NEIGHBOR, 
                    (struct sockaddr *)&host, sizeof(struct sockaddr));
            }
        }
        pint = (int32 *)stdhash_it_val(&it);
        *pint = status;
        break;
    case HYBRID_NAT_ENTRY:
        /* Self Discard */
        if (smesh_pkt_p->sender_ip == htonl(WAN_intf_ip) ||
            smesh_pkt_p->sender_ip == htonl(LAN_intf_ip)) {
            return;
        }
        /* NAT entry is already in Network Byte Order */
        hybrid_nat_p = (hybrid_nat *)smesh_pkt_p->data;
        memcpy(&nat_k, &(hybrid_nat_p->nat_key), sizeof(NAT_key));
        stdhash_find(&NAT_hash, &it, &nat_k);
        if(stdhash_is_end(&NAT_hash, &it)) {
            nat_e.ip_src = hybrid_nat_p->nat_value;
            nat_e.first_time_heard = E_get_time();
            nat_e.hybrid_req_cnt = 0;
            nat_e.ip_hybrid = 0;
            stdhash_insert(&NAT_hash, &it, &nat_k, &nat_e);
        } 
        nat_ep = (NAT_entry *)stdhash_it_val(&it);
        nat_ep->last_time_heard = E_get_time();
        /* If no one has claimed the connection, or I declared and someone else
           with a lower IP declared also, choose that sender */
        if (nat_ep->ip_hybrid == 0 || ntohl(smesh_pkt_p->sender_ip) < ntohl(nat_ep->ip_hybrid)) {
            nat_ep->ip_hybrid = smesh_pkt_p->sender_ip;
        }
        break;
    case REGISTER_DHCP_CLIENT:
        break;
  } /* end switch(ntohl(smesh_pkt_p->p_type))  */
}

/* Control packet sent by a node to discover an Internet gateway */
void send_wan_gw_request() 
{
    int ret;
    smesh_packet *smesh_pkt_p;
    struct sockaddr_in host;

    /* If already received GW information, do not send request */
    Alarm(DEBUG_SMESH, "Sending GW Request\n");
    smesh_pkt_p = (smesh_packet*) Packet_Buff;
    smesh_pkt_p->p_type = htonl(WAN_GW_REQUEST);
    smesh_pkt_p->sender_ip = htonl(LAN_intf_ip);

    host.sin_family = AF_INET;
    host.sin_port = htons(DUMMY_PORT);
    host.sin_addr.s_addr = htonl(GW_ANYCAST_CTRL_GROUP);

    ret = spines_sendto(Mcast_Control_sk, (char *)Packet_Buff, WanGwRqst_S+P_SIZE, 0, 
            (struct sockaddr *)&host, sizeof(struct sockaddr)); 
    if (ret != WanGwRqst_S+P_SIZE) {
        Alarm(EXIT,"error in writing control socket\n");
    } 
    if (DNS1 == 0) {
        E_queue(send_wan_gw_request, 0, NULL, gw_request_fast_timeout);
    } else {
        E_queue(send_wan_gw_request, 0, NULL, gw_request_timeout);
    }
}

/* Control packet sent by an Internet gateway to notify other gateways of its 
 * WAN IP address (for hybrid environments only) 
 */
void send_wan_gw_status() 
{
    int ret;
    smesh_packet *smesh_pkt_p;
    gw_status *gw_status_p;
    struct sockaddr_in host;

    /* TODO: test_wan_status to bring up and down the wan status */

    /* If already received GW information, do not send request */
    Alarm(DEBUG_SMESH, "Sending GW Status\n");
    smesh_pkt_p = (smesh_packet*) Packet_Buff;
    smesh_pkt_p->p_type = htonl(WAN_GW_STATUS);
    smesh_pkt_p->sender_ip = htonl(LAN_intf_ip);
    gw_status_p = (gw_status *) smesh_pkt_p->data;
    gw_status_p->wan_ip = htonl(WAN_intf_ip);
    gw_status_p->status = htons(1);

    host.sin_family = AF_INET;
    host.sin_port = htons(DUMMY_PORT);
    host.sin_addr.s_addr = htonl(HYBRID_MCAST_CTRL_GROUP);

    ret = spines_sendto(Mcast_Control_sk, (char *)Packet_Buff, WanGwStatus_S+P_SIZE, 0, (struct sockaddr *)&host, sizeof(struct sockaddr)); 
    if (ret != WanGwStatus_S+P_SIZE) {
        Alarm(EXIT,"error in writing control socket\n");
    } 
    E_queue(send_wan_gw_status, 0, NULL, gw_request_timeout);
}

/* Garbage collect NAT */
void nat_garbage_collector() 
{
    stdit it;
    sp_time now, time_elapsed;
    NAT_entry      *nat_ep;

    now = E_get_time();
    stdhash_begin(&NAT_hash, &it);
    while(!stdhash_is_end(&NAT_hash, &it)) {
        nat_ep = (NAT_entry *)stdhash_it_val(&it);
        time_elapsed = E_sub_time(now, nat_ep->last_time_heard);
        if (E_compare_time(time_elapsed, nat_expiration_timeout) > 0) {
            /* remove the entry if it hasn't been used in a while */
            stdhash_erase(&NAT_hash, &it);
        } else {
            stdhash_it_next(&it);
        }
    }
    E_queue(nat_garbage_collector, 0, NULL, nat_gc_timeout);
}

/* Filter the packet for unwanted traffic
 * Returns TRUE if unwanted, FALSE if wanted
 */
int filter_packet(int bytes, char *packet) 
{
    const struct my_ip   *ip;
    const struct my_icmp *icmp;
    const struct my_udp  *udp;
    const struct my_tcp  *tcp;

    /* Set packet pointers and determine origin */
    ip = (struct my_ip*)(packet);

    /* Ignore packets sent by myself or if the source is 0 (although BPF filter
     * is doing this before...) */
    if ( (int32)(ip->ip_src.s_addr) == htonl(WAN_intf_ip) || 
         (int32)(ip->ip_src.s_addr) == htonl(LAN_intf_ip) ||
         (int32)(ip->ip_src.s_addr) == htonl(Loopback_ip) ||  
         (int32)(ip->ip_src.s_addr) == 0 ) 
    {
        return(TRUE);
    } 

    if (ip->ip_p == IPPROTO_TCP) {
        tcp = (struct my_tcp*)((char *)ip + _IP_SIZE);
    }
    else if (ip->ip_p == IPPROTO_UDP) {
        udp = (struct my_udp*)((char *)ip + _IP_SIZE);

        /* Ignore DHCP Packets */
        if ( ntohs(udp->source_port)== DHCP_PORT_S || 
            ntohs(udp->dest_port)  == DHCP_PORT_S ||
            ntohs(udp->source_port)== DHCP_PORT_C || 
            ntohs(udp->dest_port)  == DHCP_PORT_C) 
        {
            return(TRUE);
        }

        /* Ignore packet if is a spines packet */
        if ( (ntohs(udp->source_port)>=Spines_Port && 
              ntohs(udp->source_port)<Spines_Port+4   ) || 
             (ntohs(udp->dest_port) >= Spines_Port &&
              ntohs(udp->dest_port) < Spines_Port+4) )  
        {
            return(TRUE);
        }
    }
    else if (ip->ip_p == IPPROTO_ICMP) {
        icmp = (struct my_icmp*)((char *)ip + _IP_SIZE);
        return(FALSE);
    }

    /* If WAN packet, accept at this point */
    if ((int32)(ip->ip_dst.s_addr) == htonl(WAN_intf_ip)) {
        return(FALSE);
    }

    /* When receiving a packet from a client in LAN, grab all 
     * packets that have destination that are not for myself nor
     * backbone nodes
     */
    if ( ( (ntohl(ip->ip_dst.s_addr)&BACKBONE_NETMASK) != (LAN_intf_ip&BACKBONE_NETMASK)) &&
       ( ntohl(ip->ip_dst.s_addr) != LAN_intf_ip ) &&
       ( ntohl(ip->ip_dst.s_addr) != Loopback_ip ) )
    {
        return(FALSE);
    }
    return(TRUE);
}

/* Try to exit cleanly from smesh */
void clean_exit(int signum)
{
    Alarm(PRINT,"\nPACKET REPORT: Total: %ld  Mesh: %ld  WAN: %ld\n",
    pkt_count, pkt_mesh_count, pkt_wan_count);
    Alarm(PRINT,"               Mesh Bad: %ld   WAN Bad: %ld   Zero: %ld\n",
    pkt_mesh_count-pkt_mesh_good_count, 
    pkt_wan_count-pkt_wan_good_count, pkt_zero_count);
    Alarm(PRINT, "\nExit Signal: %d\n", signum);

    /* Proxy Server Specific */
    if (SMesh_GW) {
        close_pcap(Pcap_Handler[WAN_PKT]);
        stdhash_destruct(&NAT_hash);
    }

    /* Proxy Client Specific */
    if (SMesh_Server) {
        close_pcap(Pcap_Handler[LAN_PKT]);
    }

    /* Self Transparent Proxy Specific */
    if (Self_Trans_Proxy) {
        close_pcap(Pcap_Handler[LO_PKT]);
    }

    spines_close(Private_sk);
    spines_close(Mcast_Client_sk);
    spines_close(Mcast_Control_sk); 
    //close(Wan_sk);

    Alarm(PRINT,"\nMesh Proxy Exiting Cleanly\n\n");
    exit(1);
}

/* Perform NAT for the packets going to the Internet */
int forward_nat(char* packet, int bytes, int hybrid_port) 
{
    int32 temp_ip;
    struct my_ip   *ip;
    struct my_icmp *icmp;
    struct my_udp  *udp;
    struct my_dns  *dns;
    struct my_tcp  *tcp;
    NAT_entry      *nat_ep;
    hybrid_nat     *hybrid_nat_p;
    sp_time time_elapsed;
    struct sockaddr_in dest;
    smesh_packet *smesh_pkt_p;
    int ret, new_entry;

    ip = (struct my_ip*)(packet);

    nat_k.dest_addr = (ip->ip_dst).s_addr;

    /* Default to 0 in case of none of the following protocols */
    nat_k.dest_port = 0; 
    nat_k.source_port = 0;
    if (ip->ip_p == IPPROTO_TCP) {
        tcp = (struct my_tcp*)((char *)ip + _IP_SIZE);
        nat_k.dest_port = tcp->dest_port;
        nat_k.source_port = tcp->source_port;
    }
    else if (ip->ip_p == IPPROTO_UDP) {
        udp = (struct my_udp*)((char *)ip + _IP_SIZE);
        nat_k.dest_port = udp->dest_port;
        nat_k.source_port = udp->source_port;
        /* If a DNS packet, change destination port 53 to query id */
        if (ntohs(udp->dest_port) == DNS_PORT) {
            dns = (struct my_dns*)((char *)udp + _UDP_SIZE);
            nat_k.dest_port = dns->id;
        }
    }
    else if (ip->ip_p == IPPROTO_ICMP) {
        icmp = (struct my_icmp*)((char *)ip + _IP_SIZE);
        nat_k.source_port = icmp->un.echo.id;
        nat_k.dest_port = icmp->un.echo.id;
    }

    stdhash_find(&NAT_hash, &it, &nat_k);
    if(stdhash_is_end(&NAT_hash, &it)) {
        nat_e.ip_src = (ip->ip_src).s_addr;
        nat_e.ip_hybrid = 0;
        nat_e.first_time_heard = E_get_time();
        nat_ep = &nat_e;
        new_entry = TRUE;
    }  else {
        nat_ep = (NAT_entry *)stdhash_it_val(&it);
        new_entry = FALSE;
    }
    nat_ep->last_time_heard = E_get_time();

    if (Hybrid_Network) {
        /* If received on the mcast group, I should ignore the packet unless I am the owner */
        if (hybrid_port == HYBRID_MCAST_DATA_PORT && nat_ep->ip_hybrid != htonl(WAN_intf_ip)) {
            return(0);
        }
        time_elapsed = E_sub_time(nat_ep->last_time_heard, nat_ep->first_time_heard);
        /* Can I declare stream as my own */
        if (ip->ip_p == IPPROTO_TCP) {
            tcp = (struct my_tcp*)((char *)ip + _IP_SIZE);
            /* If SYN packet, make myself the gateway for this connection */
            if (tcp->tcp_syn == 1 || nat_ep->ip_hybrid == htonl(WAN_intf_ip)) {
                nat_ep->ip_hybrid = htonl(WAN_intf_ip);
            } else if (nat_ep->ip_hybrid != 0) {
                /* If I am not the one and there is a GW, forward */
                dest.sin_family = AF_INET;
                dest.sin_port = htons(PRIVATE_PORT);
                dest.sin_addr.s_addr = nat_ep->ip_hybrid;
                ret = spines_sendto(Hybrid_Mcast_sk, (char *)packet, bytes, 0, 
                        (struct sockaddr *)&dest, sizeof(struct sockaddr)); 
                if(ret != bytes) {
                    Alarm(EXIT, "error in writing socket\n");
                }
                return(0);
            } else if (nat_ep->ip_hybrid == 0 &&
                     E_compare_time(time_elapsed, hybrid_nat_timeout) < 0 &&
                     hybrid_port != HYBRID_MCAST_DATA_PORT) {
                /* Forward to Hybrid group */
                dest.sin_family = AF_INET;
                dest.sin_port = htons(DUMMY_PORT);
                dest.sin_addr.s_addr = htonl(HYBRID_MCAST_DATA_GROUP);
                ret = spines_sendto(Hybrid_Mcast_sk, (char *)packet, bytes, 0, 
                        (struct sockaddr *)&dest, sizeof(struct sockaddr)); 
                if(ret != bytes) {
                    Alarm(EXIT, "error in writing socket\n");
                }
                return(0);
            } else {
                /* Too much time elapsed....Declare myself as owner */
                /* Hope I was handling him.  If not the connection will be reset */
                nat_ep->ip_hybrid = htonl(WAN_intf_ip);
            }
        } else if (ip->ip_p == IPPROTO_UDP) {
            udp = (struct my_udp*)((char *)ip + _IP_SIZE);
            if (nat_ep->ip_hybrid == htonl(WAN_intf_ip) ||
                ntohs(udp->dest_port) == DNS_PORT || 
                (ntohs(udp->dest_port) >= 5000 && ntohs(udp->dest_port) < 6000)) {
                /* Good .... I will handle the connection */
                nat_ep->ip_hybrid = htonl(WAN_intf_ip);
            } else if (nat_ep->ip_hybrid != 0) {
                /* If I am not the one and there is a GW, forward */
                dest.sin_family = AF_INET;
                dest.sin_port = htons(PRIVATE_PORT);
                dest.sin_addr.s_addr = nat_ep->ip_hybrid;
                ret = spines_sendto(Hybrid_Mcast_sk, (char *)packet, bytes, 0, 
                        (struct sockaddr *)&dest, sizeof(struct sockaddr)); 
                if(ret != bytes) {
                    Alarm(EXIT, "error in writing socket\n");
                }
                return(0);
            } else if (nat_ep->ip_hybrid == 0 &&
                     E_compare_time(time_elapsed, hybrid_nat_timeout) < 0 &&
                     hybrid_port != HYBRID_MCAST_DATA_PORT) {
                /* Forward to Hybrid group */
                dest.sin_family = AF_INET;
                dest.sin_port = htons(DUMMY_PORT);
                dest.sin_addr.s_addr = htonl(HYBRID_MCAST_DATA_GROUP);
                ret = spines_sendto(Hybrid_Mcast_sk, (char *)packet, bytes, 0, (struct sockaddr *)&dest, sizeof(struct sockaddr)); 
                if(ret != bytes) {
                    Alarm(EXIT, "error in writing socket\n");
                }
            } else {
                /* Too much time elapsed....Declare myself as owner */
                nat_ep->ip_hybrid = htonl(WAN_intf_ip);
            }
        } else {
            nat_ep->ip_hybrid = htonl(WAN_intf_ip);
        }
        /* If it was received from the hybrid mcast group, then inform
           them that I have control of this connection */
        if (hybrid_port == HYBRID_MCAST_DATA_PORT && nat_ep->ip_hybrid == htonl(WAN_intf_ip)) {
            smesh_pkt_p = (smesh_packet*) Local_Packet_Buff;
            smesh_pkt_p->p_type = htonl(HYBRID_NAT_ENTRY);
            smesh_pkt_p->sender_ip = htonl(WAN_intf_ip);
            hybrid_nat_p = (hybrid_nat *)smesh_pkt_p->data;
            memcpy(&(hybrid_nat_p->nat_key), &nat_k, sizeof(NAT_key));
            hybrid_nat_p->nat_value = nat_ep->ip_src;
            dest.sin_family = AF_INET;
            dest.sin_port = htons(DUMMY_PORT);
            dest.sin_addr.s_addr = htonl(HYBRID_MCAST_CTRL_GROUP);
            ret = spines_sendto(Mcast_Control_sk, (char *)smesh_pkt_p, sizeof(hybrid_nat)+P_SIZE, 0, 
                    (struct sockaddr *)&dest, sizeof(struct sockaddr)); 
            if (ret != sizeof(hybrid_nat)+P_SIZE) {
                Alarm(EXIT,"error in writing control socket\n");
            } 
        }
    }
    /* Should I insert this entry? */
    if (new_entry) {
        stdhash_insert(&NAT_hash, &it, &nat_k, &nat_e);//
    }

    /* Done per packet... save on some conversions */
    if (Debug_Flags & DEBUG_NAT) {
        Alarm(DEBUG_NAT,"\nFORWARD NAT MAP: "IPF" [%d] [%d] -> "IPF" \n", IP(ntohl((ip->ip_dst).s_addr)), ntohs(nat_k.dest_port), ntohs(nat_k.source_port), IP(ntohl((ip->ip_src).s_addr)));
        if (Hybrid_Network) {
            Alarm(DEBUG_NAT,"\t-- Hybrid Destination: "IPF"\n", IP(ntohl(nat_ep->ip_hybrid)));
        }
    }

    /* Change source addr to my own and compute checksum */
    temp_ip = htonl(WAN_intf_ip);
    memcpy(&(ip->ip_src), &temp_ip, sizeof(struct in_addr));
    pkt_checksum(packet);
    return(1);
}

/* Perform reverse NAT for the packets coming from the Internet */
int reverse_nat(char* packet, int bytes) 
{
    struct my_ip   *ip;
    struct my_icmp *icmp;
    struct my_udp  *udp;
    struct my_dns  *dns;
    struct my_tcp  *tcp;
    NAT_entry      *nat_ep;

    ip = (struct my_ip*)(packet);

    nat_k.dest_addr = (ip->ip_src).s_addr;
    nat_k.dest_port = 0;
    nat_k.source_port = 0;

    if (ip->ip_p == IPPROTO_TCP) {
        tcp = (struct my_tcp*)((char *)ip + _IP_SIZE);
        nat_k.dest_port = tcp->source_port;
        nat_k.source_port = tcp->dest_port;
    }
    else if (ip->ip_p == IPPROTO_UDP) {
        udp = (struct my_udp*)((char *)ip + _IP_SIZE);
        nat_k.dest_port = udp->source_port;
        nat_k.source_port = udp->dest_port;

        /* If a DNS packet, change destination port 53 to query id */
        if (ntohs(udp->source_port) == DNS_PORT) {
            dns = (struct my_dns*)((char *)udp + _UDP_SIZE);
            nat_k.dest_port = dns->id;
        }
    }
    else if (ip->ip_p == IPPROTO_ICMP) {
        icmp = (struct my_icmp*)((char *)ip + _IP_SIZE);
        nat_k.dest_port = icmp->un.echo.id;
        nat_k.source_port = icmp->un.echo.id;
    }

    stdhash_find(&NAT_hash, &it, &nat_k);
    if(stdhash_is_end(&NAT_hash, &it)) {
        if (DMZ_ip) {
            nat_e.ip_src = htonl(DMZ_ip);
            nat_e.ip_hybrid = 0;
            nat_e.first_time_heard = E_get_time();
            nat_e.last_time_heard = E_get_time();
            nat_e.ip_hybrid = htonl(WAN_intf_ip);
            stdhash_insert(&NAT_hash, &it, &nat_k, &nat_e);
        } else {
            return(-1);
        }
    }
    nat_ep = (NAT_entry *)stdhash_it_val(&it);

    /* Change dest addr to NAT destination from table and compute checksum */
    memcpy(&(ip->ip_dst), &(nat_ep->ip_src), sizeof(struct in_addr));
    pkt_checksum(packet);

    /* Done per packet... save some conversions */
    if (Debug_Flags & DEBUG_NAT) {
        Alarm(DEBUG_NAT,"\nREVERSE NAT MAP: "IPF" [%d] [%d] -> "IPF"\n", IP(htonl((ip->ip_src).s_addr)), ntohs(nat_k.dest_port), ntohs(nat_k.source_port),IP(htonl((ip->ip_dst).s_addr)));
    }
    return(0);
}


/* Return a datagram Spines socket (bind to specified port using specified
 * link protocol)
 */
int smesh_socket(int32 ipaddr, int port, int link_protocol)
{
    int temp_sk;
    struct sockaddr_in host;

    host.sin_family = AF_INET;
    host.sin_addr.s_addr = htonl(ipaddr);
    host.sin_port = htons(Spines_Port);

    temp_sk = spines_socket(PF_INET, SOCK_DGRAM, link_protocol, (struct sockaddr*)&host);
    if(temp_sk <= 0) {
        Alarm(EXIT, "spines socket error\n");
    }

    Alarm(PRINT, "Socket created to spines @ "IPF" port %d\n", 
          IP(ntohl(host.sin_addr.s_addr)), ntohs(host.sin_port));

    if (port > 0) {
        host.sin_family = AF_INET;
        host.sin_addr.s_addr = INADDR_ANY;
        host.sin_port = htons(port);

        if(spines_bind(temp_sk, (struct sockaddr *)&host, sizeof(host) ) < 0) {
            Alarm(EXIT, "spines bind error\n");
        }

        Alarm(PRINT, "\t--Bind to Port %d\n", ntohs(host.sin_port));
    }

    return temp_sk;
}

/* Join a multicast group */
void smesh_add_membership(int sk, int32 mcast_addr) 
{
    struct ip_mreq mreq;

    mreq.imr_multiaddr.s_addr = htonl(mcast_addr);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (spines_setsockopt(sk, IPPROTO_IP, SPINES_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) < 0) {
        Alarm(EXIT, "Mcast: problem in setsockopt to join multicast address");
    }
}

/* Leave a multicast group */
void smesh_drop_membership(int sk, int32 mcast_addr) 
{
    struct ip_mreq mreq;

    mreq.imr_multiaddr.s_addr = htonl(mcast_addr);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if(spines_setsockopt(sk, IPPROTO_IP, SPINES_DROP_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) < 0) 
    {
        Alarm(EXIT, "Mcast: problem in setsockopt to leave multicast address");
    }
}

inline void init_signals() 
{
    /* Try to exit cleanly */
    signal(SIGINT,  clean_exit);
    signal(SIGTERM, clean_exit);
    signal(SIGKILL, clean_exit);
    signal(SIGQUIT, clean_exit);
    signal(SIGHUP,  SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
}

void Print_Log_buffer()
{
    FILE*    Log_file;
    int i;
    char filename[128];

    sprintf(filename, "%s.tmp", Log_filename);

    if ((Log_file = fopen(filename, "w")) < 0) {
        Alarm(EXIT, "Cannot open %s (log file)\n");
    }
  
    fprintf(Log_file, "LOG FILE -- LAST LQ CHECK TIME [%d]\n\n", LQ_check_time);
    for (i = 0; i < Log_msg_num; i++) {
        fprintf(Log_file, "%s", Log_buffer[i]);
        free(Log_buffer[i]);
    }

    Log_msg_num = 0;
    fclose(Log_file);
    rename(filename, Log_filename);
    E_queue(Print_Log_buffer, 0, NULL, print_log_timeout);
}

void smesh_set_debug(int debug_level) 
{
    /* Set Debug Flags based on level */
    if (debug_level == 1) {
        Debug_Flags = Debug_Flags | DEBUG_SMESH;
    }
    if (debug_level == 2) {
        Debug_Flags = Debug_Flags | DEBUG_DHCP;
    }
    if (debug_level == 3) {
        Debug_Flags = Debug_Flags | DEBUG_ARP;
    }
    if (debug_level == 4) {
        Debug_Flags = Debug_Flags | DEBUG_LQ;
    }
    if (debug_level == 5) {
        Debug_Flags = Debug_Flags | DEBUG_IPCAP;
    }
    if (debug_level == 6) {
        Debug_Flags = Debug_Flags | DEBUG_PACKET;
    }
    if (debug_level == 7) {
        Debug_Flags = Debug_Flags | DEBUG_HEX;
    }
    Alarm_set(Debug_Flags);
}

void usage(int argc, char* argv[]) 
{
    int32 temp_ip, tmp;
    int print_usage = 0;
    int debug_level = 0;
    int i1, i2, i3, i4;
    char ip_str[16];
    FILE *file;

    SMesh_GW = FALSE;
    SMesh_Server = FALSE;
    SMesh_RSSI = FALSE;
    Self_Trans_Proxy = FALSE;
    Hybrid_Network = FALSE;
    WAN_intf_ip = 0;
    LAN_intf_ip = 0;
    Spines_Port = DEFAULT_SPINES_PORT;
    Spines_Link_Prot = UDP_LINKS; /* UDP_LINKS, RELIABLE_LINKS, SOFT_REALTIME_LINKS */
    Main_Lease_Time = 120;
    Hello_Bcast_Timeout = 2;
    Hello_Ucast_Timeout = 4;
    LQ_max = 50; 
    LQ_threshold = 0.3;
    LQ_decay_factor= 0.2;
    Num_Listeners = 1;
    Debug_Flags = 0;
    Logging = 0;
    DNS1 = DNS2 = DNS3 = 0;
    Kernel_Routing = 0;
    Metric = 0;
    Aggressive_Mode = FALSE;
    DMZ_ip = 0;

    stdhash_construct(&Firewall_hash, sizeof(int32), sizeof(int32), 
                       NULL, NULL, 0);

    while(--argc > 0) {
        argv++;
        if(!strncmp(*argv, "-p", 2)) {
            sscanf(argv[1], "%d", (int*)&Spines_Port);
            argc--; argv++;
        }else if(!strncmp(*argv, "-k", 2)) {
            sscanf(argv[1], "%d", (int*)&tmp);
            if (tmp == 1) Kernel_Routing |= KR_CLIENT_ACAST_PATH;
            if (tmp == 2) Kernel_Routing |= KR_CLIENT_MCAST_PATH;
            argc--; argv++;
        } else if(!strncmp(*argv, "-bht", 4)) {
            sscanf(argv[1], "%d", &Hello_Bcast_Timeout);
            argc--; argv++;
        } else if(!strncmp(*argv, "-uht", 4)) {
            sscanf(argv[1], "%d", &Hello_Ucast_Timeout);
            argc--; argv++;
        }else if(!strncmp(*argv, "-hybrid", 7)) {
            Hybrid_Network= TRUE;
        }else if(!strncmp(*argv, "-mesh_if", 8)) {
            sscanf(argv[1], "%s", LAN_intf_name);
            get_device_info(LAN_intf_name, &LAN_intf_ip, &LAN_intf_ifindex, LAN_intf_mac);
            argc--; argv++;
        } else if(!strncmp(*argv, "-max", 4)) {
            sscanf(argv[1], "%d", &LQ_max);
            argc--; argv++;
        }else if(!strncmp(*argv, "-m", 2)) {
            if (!strncmp(*(argv+1), "dhcp", 4)) {
                Metric |= METRIC_DHCP;
            } else if (!strncmp(*(argv+1), "arp", 3)) {
                Metric |= METRIC_UARP;
            } else if (!strncmp(*(argv+1), "barp", 4)) {
                Metric |= METRIC_BARP;
            } else if (!strncmp(*(argv+1), "rssi", 4)) {
                Metric |= METRIC_RSSI | METRIC_RSSI_L;
            } else if (!strncmp(*(argv+1), "rssi_s", 6)) {
                Metric |= METRIC_RSSI | METRIC_RSSI_S;
            } else {
                print_usage = 1;
            }
            argc--; argv++;
        }else if(!strncmp(*argv, "-dhcp", 5)) {
            SMesh_Server = TRUE;
            sscanf(argv[1], "%d", &Main_Lease_Time);
            argc--; argv++;
        }else if(!strncmp(*argv, "-igw_if", 7)) {
            SMesh_GW = TRUE;
            sscanf(argv[1], "%s", WAN_intf_name);
            get_device_info(WAN_intf_name, &WAN_intf_ip, &WAN_intf_ifindex, WAN_intf_mac);
            argc--; argv++;
        }else if(!strncmp(*argv, "-rssi_if", 8)) {
            SMesh_RSSI = TRUE;
            sscanf(argv[1], "%s", RSSI_intf_name);
            argc--; argv++;
        }else if(!strncmp(*argv, "-link", 5)) {
            sscanf(argv[1], "%d", (int*)&Spines_Link_Prot);
            argc--; argv++;
        }else if(!strncmp(*argv, "-self_tp", 8)) {
            Self_Trans_Proxy = TRUE;
        }else if(!strncmp(*argv, "-dmz", 4)) {
            sscanf(argv[1], "%s", ip_str);
            sscanf(ip_str,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
            DMZ_ip = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
            argc--; argv++;
        }else if(!strncmp(*argv, "-dns", 4)) {
            sscanf(argv[1], "%s", ip_str);
            sscanf(ip_str,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
            if (DNS1 == 0) {
                DNS1 = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
            } else if (DNS2 == 0) {
                DNS2 = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
            } else if (DNS3 == 0) {
                DNS3 = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
            } else {
                printf("More than 3 DNS servers. Ignoring after 3.\n");
            }
            argc--; argv++;
        }else if(!strncmp(*argv, "-fw", 3)) {
            file = fopen(argv[1], "r");
            if (file == NULL) {
                printf("Error: Can't open file\n");
                print_usage = 1;
            }
            while (!feof(file)) {
                fscanf(file, "%d.%d.%d.%d", &i1, &i2, &i3, &i4);
                temp_ip = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
                temp_ip = htonl(temp_ip);
                stdhash_insert(&Firewall_hash, NULL, &temp_ip, &temp_ip);
            }
            fclose(file);
            argc--; argv++;
        } else if (!strncmp(*argv, "-best", 5)) {
            sscanf(argv[1], "%d", &Num_Listeners);
            argc--; argv++;
        } else if (!strncmp(*argv, "-ts", 3)) {
            sscanf(argv[1], "%f", &LQ_threshold);
            argc--; argv++;
        } else if (!strncmp(*argv, "-df", 3)) {
            sscanf(argv[1], "%f", &LQ_decay_factor);
            argc--; argv++;
        } else if (!strncmp(*argv, "-log", 4)) {
            Logging = 1;
            Log_msg_num = 0;
            Log_filename = argv[1];
            argc--; argv++;
        } else if (!strncmp(*argv, "-a", 2)) {
            Aggressive_Mode = TRUE;
        } else if (!strncmp(*argv, "-debug", 6)) {
            sscanf(argv[1], "%d", (int*)&debug_level);
            smesh_set_debug(debug_level);
            argc--; argv++;
        } else {
            print_usage = 1;
        }
    }
    if (Metric == 0) {
        Metric |= METRIC_UARP;
    }
    if (Spines_Port == 0 || 
        (SMesh_Server && LAN_intf_ip == 0) || 
        (SMesh_GW && WAN_intf_ip == 0) ||
        (Hybrid_Network && Kernel_Routing))
    {
        fprintf(stderr, "ERROR: Could be that an interface does not have an ip\n");
        print_usage = 1;
    }
    if (print_usage) {
        Alarm(PRINT, "\n\nSMesh Version %s\n", SMESH_VERSION);
        Alarm(PRINT, "Usage: smesh_proxy [options] \n\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n",
          "[-p <port number>   ] : spines overlay router port on this host, default: 8100",
          "[-k <level>         ] : [0,1,2] kernel routing level, default: 1",
          "[-dhcp <seconds>    ] : service clients and use supplied dhcp lease time",
          "[-mesh_if <if name> ] : mesh interface",
          "[-igw_if <if name>  ] : internet gateway wan interface",
          "[-rssi_if <if name> ] : monitoring interface where rssi can be retrieved",
          "[-log <filename>    ] : log client connection information on this node",
          "[-debug <type>      ] : enable debugging mode (1=SMESH, 2=DHCP, 3=ARP, 4=LQ, 5=IPCAP,",
          "                                               6=PACKET, 7=HEX",
          "\nMesh Node Servicing Clients Specific:",
          "[-m <metric type>   ] : [arp, dhcp, rssi, barp], default: arp",
          "[-max <value>       ] : maximum value for each metric type, default: 50",
          "[-uht <seconds>     ] : unicast heartbit timer, when needed, default: 4 seconds",
          "[-bht <seconds>     ] : broadcast heartbit timer, when needed, default: 2 seconds",
          "[-df <value>        ] : [0.0-1.0] decay factor, default: 0.2",
          "[-ts <value>        ] : [0.0-1.0] handoff threshold, default: 0.3",
          "\nInternet Gateway Specific:",
          "[-dns <ip address>  ] : dns address, at most 3",
          "[-hybrid            ] : enable specialized hybrid mode, valid in overlay mode",
          "[-dmz <ip address>  ] : set internal dmz ip address in overlay mode",
          "[-fw <filename>     ] : allow only specific ip addresses when in overlay mode");
        exit(1);
    }
}

