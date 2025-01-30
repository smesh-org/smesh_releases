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


#ifndef DHCP_H
#define DHCP_H

#define MAX_LISTENERS 20
#define VERIFY_SIZE(x) if(!verify_size(buffer[idx], x, size, idx)) {printf("returning early\n");return;}

#define DHCP_FAKE_GATEWAY_X(x) ((x & 0xFFFFFFF8) | 0x00000002)

#define DHCP_CLIENT_MASK  (IPINT(255,255,255,248)) 
#define DHCP_FAKE_GATEWAY ((LAN_intf_ip & CLIENT_NETMASK) + (20<<16) + (30<<8) + 40)
#define DHCP_BCAST_ADDR   (IPINT(255,255,255,255))
#define DHCP_IN_CLIENT_NET(x) ((DHCP_FAKE_GATEWAY & CLIENT_NETMASK) == ((x) & CLIENT_NETMASK))

#define DHCP_PORT_S 67
#define DHCP_PORT_C 68

/* DHCP constants */
#define DHCP_BOOTREQUEST  0x01
#define DHCP_BOOTREPLY    0x02

#define DHCP_ETHERNET     0x01

#define DHCP_UNICAST      0x0000
#define DHCP_BROADCAST    0x8000

/* DHCP message types (option 53) */
#define DHCP_DISCOVER     0x01
#define DHCP_OFFER        0x02
#define DHCP_REQUEST      0x03
#define DHCP_DECLINE      0x04
#define DHCP_ACK          0x05
#define DHCP_NAK          0x06
#define DHCP_RELEASE      0x07
#define DHCP_INFORM       0x08

#define STATE_DHCP_IDLE       0x00
#define STATE_DHCP_HEARD      0x01
#define STATE_DHCP_OFFERED    0x02
#define STATE_DHCP_REQUESTED  0x03
#define STATE_DHCP_REGISTERED 0x04
#define STATE_DHCP_INVALID    0x05

/* both may be set */
#define GROUP_STAT_IDLE        0x00
#define GROUP_STAT_JOINED_CTRL 0x01
#define GROUP_STAT_JOINED_DATA 0x02

#define DHCP_MAGIC_COOKIE (0x63825363)

/**********
 DHCP Options
**********/

#define DHCP_O_PADDING       0
#define DHCP_O_SUBNET        1
#define DHCP_O_ROUTER        3
#define DHCP_O_DNS           6
#define DHCP_O_HOSTNAME     12
#define DHCP_O_DOMAIN       15
#define DHCP_O_REQ_IP       50
#define DHCP_O_LEASE_LENGTH 51
#define DHCP_O_MSG_TYPE     53
#define DHCP_O_SERVER       54
#define DHCP_O_PARAM_REQ    55
#define DHCP_O_T1           58
#define DHCP_O_T2           59
#define DHCP_O_VENDOR       60
#define DHCP_O_CLIENT_ID    61
#define DHCP_O_AUTO_CONFIG 116
#define DHCP_O_END         255

#define DHCP_MAX_OPT_LEN   128


/* DHCP header */
/* per RFC 2131 */
typedef struct dummy_dhcp_header {
  unsigned char op;
  unsigned char htype;
  unsigned char hlen;
  unsigned char hops;
  unsigned int32 xid;
  unsigned int16 secs;
  unsigned int16 flags;
  unsigned int32 ciaddr;
  unsigned int32 yiaddr;
  unsigned int32 siaddr;
  unsigned int32 giaddr;
  unsigned char chaddr[16];
  unsigned char sname[64];
  unsigned char file[128];
  unsigned int32 magic_cookie;
  /*unsigned char options[308];*/
} dhcp_header;
#define DHCP_PACKET_SIZE (sizeof(dhcp_header)+308)

typedef struct dummy_dhcp_entry {
  unsigned int ip_addr;
  unsigned char mac_addr[6];
  unsigned char dummy1;
  unsigned char dummy2;
  sp_time join_time; 
  int bcast_lq_metric;
  int ucast_lq_metric;
  sp_time dhcp_last_time_heard;
  sp_time barp_last_time_heard;
  sp_time uarp_last_time_heard;
  unsigned int lq_leave_request_id;
  int rssi;
  stdhash lq_hash;
  char hostname[DHCP_MAX_OPT_LEN];
  unsigned char state;
  unsigned char groups;
} dhcp_entry;

typedef struct dummy_dhcp_opts_parsed {
  unsigned int hostname_len;
  char hostname[DHCP_MAX_OPT_LEN];
  unsigned int req_ip;
  unsigned char msg_type;
  unsigned int vendor_len;
  char vendor[DHCP_MAX_OPT_LEN];
  unsigned int server_ip;
} dhcp_opts_parsed;


/* FUNCTION PROTOTYPES */

void DHCP_Init();
void DHCP_Receive(int sk, int dummy, void *pcap_hanlder);
void DHCP_Respond(dhcp_entry *de, dhcp_header *hdr, dhcp_opts_parsed *opts);
void DHCP_Send_Packet(dhcp_entry *de, unsigned int32 xid, int bcast_flag, int force_bcast);
void DHCP_grab_header(dhcp_header* hdr, char *buffer, const int size);
void DHCP_parse_options(dhcp_opts_parsed *opts, char *buffer, const int size);
void DHCP_LinkState_Check();
void DHCP_Print_Table();
void DHCP_Create_Entry(const char *mac_addr);
void DHCP_Remove_Entry(dhcp_entry *de);
dhcp_entry* DHCP_Lookup_Entry(const char *mac_addr);

void DHCP_send_pkt(char *pkt, int pkt_size, int32 src_ip, 
                   int source_port, int32 dest_ip, int dest_port, 
                   int dest_ifindex, char *dest_mac);

inline char verify_size(unsigned char field_size, unsigned char expected_size, unsigned int total_size, unsigned int idx);

unsigned int32 allocate_dhcp_ip(int32 ip_addr, unsigned char *hw_addr);

void DHCP_lq_check(int dummy_i, void *dummy_p);
void LQ_Check_DataGroup();
dhcp_entry* DHCP_Reverse_Lookup(unsigned int ip_addr);
unsigned int oat_hash(void *mac);

void Log(char *);

#endif

