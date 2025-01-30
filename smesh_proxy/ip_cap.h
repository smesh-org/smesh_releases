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


#ifndef IPCAP_H
#define IPCAP_H

/* Defines ETHER_HDRLEN */
#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif

#define ETHER_IP    1
#define ETHER_ARP   2

/* Function Prototypes */
int       init_pcap(char *dev, int promisc, pcap_t** descr, char *filter);
int       dhcp_init_pcap(char *dev, int promisc, pcap_t** descr);
int       get_next_ip_packet(char** ip_packet, pcap_t* descr, int *type);
void      print_packet(char *packet, int bytes);
void      close_pcap(pcap_t* descr);
int       handle_IP (struct pcap_pkthdr* pkthdr, const u_char* packet);
void      get_device_info(char *dev, int *io_ip, int *io_ifindex, char *io_mac);

u_int16_t handle_ethernet (struct pcap_pkthdr* pkthdr, const u_char* packet);

#endif
