#ifndef EN_TETES_H
#define EN_TETES_H

#include <string.h>

#define UDP 17
#define TCP 6

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include "bootp.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <ctype.h>

void callback_ethernet (u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void callback_ip (const u_char *packet);
void callback_udp (const u_char *packet);
void callback_bootp (const u_char *packet);
void callback_tcp (const u_char *packet);
void callback_dhcp (const u_char *packet);
void callback_arp (const u_char *packet);
void callback_http (const u_char *packet);
void callback_smtp (const u_char *packet);
void callback_ftp (const u_char *packet);
void callback_pop (const u_char *packet);
void callback_imap (const u_char *packet);
void callback_telnet (const u_char *packet);

#endif
