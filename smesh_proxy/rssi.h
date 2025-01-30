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


#ifndef RSSI_H
#define RSSI_H

// Prism 802.11 headers from wlan-ng tacked on to the beginning of a
// pcap packet... Snagged from the wlan-ng source

typedef struct {
    uint32_t did;
    uint16_t status;
    uint16_t len;
    uint32_t data;
} p80211item_uint32_t;

typedef struct {
    uint32_t msgcode;
    uint32_t msglen;
    uint8_t devname[16];
    p80211item_uint32_t hosttime;
    p80211item_uint32_t mactime;
    p80211item_uint32_t ch; /*channel*/
    p80211item_uint32_t rssi;
    p80211item_uint32_t sq;
    p80211item_uint32_t signal;
    p80211item_uint32_t noise;
    p80211item_uint32_t rate;
    p80211item_uint32_t istx;
    p80211item_uint32_t frmlen;
} wlan_header;

typedef struct {
        unsigned short frame_control; // needs to be subtyped
        unsigned short duration;
        unsigned char mac1[6];
        unsigned char mac2[6];
        unsigned char mac3[6];
        unsigned short SeqCtl;
        //unsigned char mac4[6];
        //unsigned short gapLen;
        //unsigned char gap[8];
} ieee_802_11_header;

typedef struct {
    unsigned char dsap;   
    unsigned char ssap;           /* always 0xAA */
    unsigned char ctrl;           /* always 0x03 */
    unsigned char oui[3];         /* organizational universal id */
    unsigned short unknown1;      /* packet type ID fields */
    //unsigned short unknown2;      /* here is something like length in some cases */
} llc;

void RSSI_Init();
void RSSI_process_pkt(int sk, int dummy_i, void *pcap_handler);
inline int init_p80211(char *dev, int promisc, pcap_t** descr, char *my_filter);

#endif
