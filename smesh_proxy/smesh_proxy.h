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


#ifndef SMESH_PROXY_H
#define SMESH_PROXY_H

#define SMESH_VERSION "2.3"

/* Define some spines variables */
#define IPINT(a,b,c,d) ((int32) ((a << 24) + (b << 16) + (c << 8) + (d)))


#define PKT_BUFF_SIZE           2200
#define MAX_LOG_NUM             200
#define PRIVATE_PORT            8420
#define MCAST_CLI_PORT          8430
#define DUMMY_PORT              8440
#define CONTROL_PORT            8440
#define HYBRID_MCAST_DATA_PORT  8450
#define GW_ANYCAST_DATA_GROUP   (IPINT(240,220,11,1))
#define GW_ANYCAST_CTRL_GROUP   (IPINT(240,220,11,2))
#define DHCPS_MCAST_CTRL_GROUP  (IPINT(225,220,11,2))
#define HYBRID_MCAST_CTRL_GROUP (IPINT(225,220,11,3))
#define HYBRID_MCAST_DATA_GROUP (IPINT(225,220,11,4))
#define LOG_GROUP               (IPINT(225,220,11,5))
#define SSH_PORT                722

#define KR_MCAST_GROUP_PREFIX   227
#define KR_ACAST_GROUP_PREFIX   247

#define KR_CLIENT_ACAST_PATH    0x0002
#define KR_CLIENT_MCAST_PATH    0x0004

#define LOOPBACK_INTF_NAME "lo"

#define BACKBONE_NETMASK (IPINT(255,255,255,0))
#define CLIENT_NETMASK   (IPINT(255,0,0,0))

/* Determine if I should send this packet to the internet gateway or 
   to a peer in my network */
#define IP_IN_MY_NET(x) ( ((x) & CLIENT_NETMASK) == (CLIENT_NETMASK & LAN_intf_ip) && ((x) & (CLIENT_NETMASK^0xFFFFFFFF)) != 255 )

/* MAC to IP Hash Functions */
#define MAC_TO_IP(x) ( oat_hash(x) )

/* IP to DATA group for internet gateway incomming traffic and P2P */
#define IP_TO_DATA_MCAST(x) ( (KR_MCAST_GROUP_PREFIX << 24) | (x & 0xFFFFFF) )
#define IP_TO_DATA_ACAST(x) ( (KR_ACAST_GROUP_PREFIX << 24) | (x & 0xFFFFFF) )
#define IP_TO_CTRL_MCAST(x) ( (226 << 24) | ((x) & 0xFFFFFF) ) 

/* Type of pcap (sniffed) packets that could be received */
#define LAN_PKT 0
#define WAN_PKT 1
#define LO_PKT 2

#define  MAX_ALT_MACS 5

#define METRIC_DHCP    0x01 // =1
#define METRIC_UARP    0x02 // =2
#define METRIC_BARP    0x04 // =3
#define METRIC_RSSI    0x10 // Generalization
#define METRIC_RSSI_S  0x20 // =4
#define METRIC_RSSI_L  0x40 // =5

/*
 * NAT key struct to map key private-network to internet addr
 * Assumes the source is always the private network side, and the dest
 * is in the outside world - internet side.
 */
typedef 
struct _NAT_key {
    int32           dest_addr;
    unsigned short  dest_port;
    unsigned short  source_port;
} NAT_key;

typedef 
struct _NAT_entry {
    int32           ip_src;
    int32           ip_hybrid;
	int32           hybrid_req_cnt;
	sp_time         first_time_heard;
	sp_time         last_time_heard;
} NAT_entry;


/*
 * Define types of packet that may be received on the Proxy-To-Proxy protocol
 */

/* Change ctrl_type_name and size[] in C file when changing values here */
typedef 
enum {WAN_GW_REQUEST=1, WAN_GW_RESPONSE, WAN_GW_STATUS, HYBRID_NAT_ENTRY, 
      LINK_QUALITY, REGISTER_DHCP_CLIENT, LOG} ctrl_type;

typedef
struct _gw_response  {
                        int32 dns1;
                        int32 dns2;
                        int32 dns3;
                    }   gw_response;

typedef
struct _gw_status    {
                        int32 wan_ip;
                        short status;
                        short dummy;
                    }   gw_status;

typedef
struct _hybrid_nat  {
                        NAT_key nat_key;
                        int32 nat_value;
                    }   hybrid_nat;


typedef
struct _leave_request_ack {
	unsigned int ip;
	unsigned int leave_request_id;
} leave_request_ack;

typedef
struct _link_quality_pkt {
	int linkq;
	unsigned int leave_request_id;
	leave_request_ack lra_list[10];
	char client_mac[MAC_SIZE]; /* this is needed to detect on which group the message was sent ;) */
	unsigned char groups;
	unsigned char leave_ack_cnt;			/* number of acknowledges */
} link_quality_pkt;

/* entry from link quality queue */
typedef
struct _link_quality_entry {
	unsigned int sender_ip;
	int linkq;
	sp_time last_time_heard;
	unsigned int leave_request_id;
	unsigned char groups;
	unsigned char dummy1;
	unsigned char dummy2;
	unsigned char dummy3;
} link_quality_entry;

#define WanGwResp_S     sizeof(gw_response)
#define WanGwStatus_S   sizeof(gw_status)
#define WanGwRqst_S     0
#define LinkQuality_S   sizeof(link_quality_pkt)
#define Log_S           512

#define MAX_DATA_SIZE   (max(WanGwRqst_S, \
			 max(WanGwResp_S, \
			 max(LinkQuality_S, \
			 max(Log_S, 1)))))
			  
typedef
struct smesh_packet {
                        ctrl_type   p_type;                 /* Packet Type */
                        int32       sender_ip;              /* Sender IP Addr */
                        char        data[MAX_DATA_SIZE];    /* Any specific packet */
                    }   smesh_packet;

#define MAX_P_SIZE      sizeof(smesh_packet)
#define P_SIZE          MAX_P_SIZE-sizeof(char[MAX_DATA_SIZE])


/* Function Prototypes */
void      usage(int argc, char* argv[]);
void      process_backbone_pkt(int sk, int port, void *dummy_p);
void      process_pcap_pkt(int sk, int port, void *dummy_p);
void      process_backbone_pkt2(char *buff, int bytes, int port);
void      process_control_pkt(int sk, int port, void *dummy_p);
int       smesh_socket(int32 ipaddr, int port, int link_protocol);
void      smesh_add_membership(int sk, int32 mcast_addr);
void      smesh_drop_membership(int sk, int32 mcast_addr);

void      send_wan_gw_request();
void      send_wan_gw_status();
int       forward_nat(char* packet, int bytes, int hybrid_port);
int       reverse_nat(char* packet, int bytes);
int       filter_packet(int bytes, char *packet);
void      nat_garbage_collector();
void      clean_exit(int signum);
inline void init_signals();
void      Print_Log_buffer();

#endif
