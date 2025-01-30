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


#ifndef ARP_H
#define ARP_H

void ARP_Init();
void ARP_process_pkt(int sk, int dummy_i, void *pcap_handler);
void ARP_send_raw_pkt(int dest_ifindex, unsigned char *ether_src, unsigned char *ether_dst,
                      unsigned short op, unsigned char *arp_sha, unsigned char *arp_sip,
                      unsigned char *arp_tha, unsigned char *arp_tip);
void ARP_send_gratuitous_arp(int dummy_int, void *mac, int ip);
void ARP_print_packet(const char *packet);
void ARP_send_request(int arp_request_type, void *dummy);
void ARP_lq_check(int arp_request_type, void *dummy);

#endif
