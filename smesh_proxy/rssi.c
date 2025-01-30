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
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

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

//#include <netpacket/packet.h>
#include <net/ethernet.h>    /* the L2 protocols */
#include <math.h>
#include <tgmath.h>

#include "pcap.h"
#include "packet.h"
#include "dhcp.h"
#include "ip_cap.h"
#include "smesh_proxy.h"
#include "rssi.h"

/* Global variables */
extern int32    LAN_intf_ip;
extern int      LAN_intf_ifindex;
extern char     LAN_intf_mac[MAC_SIZE];
extern int32    Debug_Flags;
extern char     Local_Packet_Buff[PKT_BUFF_SIZE];
extern char     LAN_intf_name[20];
extern char     RSSI_intf_name[20];
extern int32    LQ_max;
extern int32    Hello_Bcast_Timeout;
extern int32    Hello_Ucast_Timeout;
extern stdhash  DHCP_Table;
extern int      Mcast_Control_sk;
extern char     Metric;

void RSSI_Init() 
{
    int rssi_sk;     
    char bpf[200];  
    pcap_t* pcap_handler;

    memset(bpf, 0, sizeof(bpf));
    /*
    sprintf(bpf, "! ether src "MACPF" and ( arp or udp port %d ) ", 
            MAC(LAN_intf_mac), DHCP_PORT_S);
    */
    /* Some ARP pad data... */
    sprintf(bpf, "len>200 and len<216");
    rssi_sk = init_p80211(RSSI_intf_name, 1, &pcap_handler, bpf);
    max_rcv_buff(rssi_sk);
    max_snd_buff(rssi_sk);
    E_attach_fd(rssi_sk, READ_FD, RSSI_process_pkt, 0, 
            (void*)pcap_handler, LOW_PRIORITY);
}

void RSSI_process_pkt(int sk, int dummy_i, void *pcap_handler)
{
    int ret;
    dhcp_entry *de;
    const u_char *packet;
    u_int16_t eth_type;

    struct pcap_pkthdr *pkthdr;
    wlan_header *wlan;
    ieee_802_11_header *i802;

    //Alarm(DEBUG_ARP, PRINT_FUNCTION_HEADER);

    ret = pcap_next_ex((pcap_t*)pcap_handler, &pkthdr, &packet);
    if (ret < 0) { 
        printf("pcap_next_ex: error\n");
        exit(1);
    } else if(ret == 0) {
        /* Timeout Elapsed */
        return;
    }
    if (pkthdr->caplen < 199) {
        //printf("Not a meaningful packet\n");
        return;
    }

    wlan = (wlan_header *)packet;
    i802 = (ieee_802_11_header *)(packet + wlan->msglen);
    eth_type = ntohs(((llc*)(packet+wlan->msglen+sizeof(ieee_802_11_header)))->unknown1);

    if (eth_type == ETHERTYPE_ARP) {
        if ((de = DHCP_Lookup_Entry((char*)i802->mac2))) {
            de->rssi = (int)(wlan->rssi).data;
        }
    }
}

inline int init_p80211(char *dev, int promisc, pcap_t** descr, char *my_filter)
{
    struct bpf_program fp;
    int pcap_socket;
    char errbuf[PCAP_ERRBUF_SIZE];

    Alarm(DEBUG_IPCAP, PRINT_FUNCTION_HEADER);

    if (dev == NULL) {
        dev = pcap_lookupdev(errbuf);
        if(dev == NULL) { printf("%s\n",errbuf); exit(1); }
    }

    /* open device for reading. Need only 2024 as Spines packets will be less */
    *descr = pcap_open_live(dev,250,promisc,0,errbuf);
    if(*descr == NULL)
    { printf("pcap_open_live(): %s\n", errbuf); exit(1); }

    /* Put device in non-blocking mode */
    if(pcap_setnonblock(*descr, 1, errbuf) == -1)
    { printf("pcap_setnonblock(): %s\n", errbuf); exit(1); }

    /* Compile/Set filter */
    if (my_filter != NULL) {
        if(pcap_compile(*descr,&fp,my_filter,0,0) == -1)
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

