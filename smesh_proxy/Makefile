BASE=..
SP_INC=$(BASE)/spines
SP_LIB=$(BASE)/spines/spines_lib.a
PCAP_INC=$(BASE)/libpcap
PCAP_LIB=$(BASE)/libpcap/libpcap.a
STDUTIL_INC=stdutil/src
STDUTIL_LIB=stdutil/lib/libstdutil.a

CC ?= gcc
AR ?= ar
RANLIB ?= ranlib
                                                                                
SUBDIRS=stdutil/src

CFLAGS = -g -Wall -O3 -DCOMBINED_BINARY $(ARCH_DEFINE) 

OBJECTS = util/alarm.o util/events.o util/memory.o util/data_link.o 
OBJECTS2 = ip_cap.o arp.o rssi.o packet.o dhcp.o smesh_proxy.o

OBJS_SHARED = options.o socket.o packet.o pidfile.o get_time.o
DHCPD_OBJS = udhcpd/dhcpd.o udhcpd/arpping.o udhcpd/files.o udhcpd/leases.o udhcpd/serverpacket.o
OBJS1 = $(DHCPD_OBJS) $(DHCPC_OBJS) $(OBJS_SHARED) frontend.o

ALL_INC = -I$(PCAP_INC) -I$(SP_INC) -I$(STDUTIL_INC)
ALL_LIB = $(SP_LIB) $(STDUTIL_LIB) $(PCAP_LIB)

SRC=.

all: stdutil ip_cap packet arp rssi dhcp smesh_proxy

stdutil: stdutil/src/Makefile
	for dir in $(SUBDIRS); do \
          ( $(MAKE) -C $$dir); \
    done

stdutil/src/Makefile:
	cd stdutil; make distclean; ./configure
                                                                                                
ip_cap:  $(OBJECTS)
	    $(CC) $(CFLAGS) -o ip_cap.o -c $(SRC)/ip_cap.c -I$(PCAP_INC)

packet: 
	    $(CC) $(CFLAGS) -o packet.o -c $(SRC)/packet.c 

arp: 
	    $(CC) $(CFLAGS) -o arp.o -c $(SRC)/arp.c -I$(STDUTIL_INC) -I$(PCAP_INC)

rssi: 
	    $(CC) $(CFLAGS) -o rssi.o -c $(SRC)/rssi.c -I$(STDUTIL_INC) -I$(PCAP_INC)

dhcp: 
	    $(CC) $(CFLAGS) -o dhcp.o -c $(SRC)/dhcp.c -I$(STDUTIL_INC)  -I$(PCAP_INC) -I$(SP_INC)

smesh_proxy: $(OBJECTS)
	    $(CC) $(CFLAGS) -o smesh_proxy.o -c $(SRC)/smesh_proxy.c $(ALL_INC)
	    $(CC) -o smesh_proxy $(OBJECTS) $(OBJECTS2) $(ALL_LIB) -lm

clean: 
	    rm -f *.o *.to
	    rm -f util/*.o util/*.to 
	    rm -f core
		for dir in $(SUBDIRS); do \
			( $(MAKE) -C $$dir clean); \
		done

distclean: clean
	    rm smesh_proxy 
		for dir in $(SUBDIRS); do \
			( $(MAKE) -C $$dir distclean); \
		done



