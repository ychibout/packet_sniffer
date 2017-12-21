#include "../headers/en_tetes.h"

void callback_ethernet (u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	const struct ether_header *ether;
	ether = (struct ether_header*)(packet);
	const struct ether_addr *ether_src = (struct ether_addr*)(ether->ether_shost);
	const struct ether_addr *ether_dst = (struct ether_addr*)(ether->ether_dhost);

	printf("\n\n\n-Ethernet-\n\n");
	printf("Adresse Source : %s\n", ether_ntoa(ether_src));
	printf("Adresse Destination : %s\n", ether_ntoa(ether_dst));
	printf("Type : ");

	switch (ntohs(ether->ether_type)) {
		case ETHERTYPE_IP :
			printf("IP\n");
			callback_ip(packet + sizeof(struct ether_header));
			break;
		case ETHERTYPE_IPV6 :
			printf("IPv6\n");
			break;
		case ETHERTYPE_ARP :
			printf("ARP\n");
			callback_arp(packet + sizeof(struct ether_header));
			break;
		default :
			printf("Non IP\n");
	}
}

void callback_ip (const u_char *packet) {
	const struct ip *ip;
	ip = (struct ip*)(packet);

	printf("\n\t-IP-\n\n");
	printf("\tAdresse Source : %s\n", inet_ntoa(ip->ip_src));
	printf("\tAdresse Destination : %s\n", inet_ntoa(ip->ip_dst));
	printf("\tProtocole : ");

	switch (ip->ip_p) {
		case UDP :
			printf("UDP\n");
			callback_udp(packet + ip->ip_hl*4);
			break;
		case TCP :
			printf("TCP\n");
			callback_tcp(packet + ip->ip_hl*4);
			break;
		default :
			printf("Ni TCP ni UDP");
	}
}

void callback_udp (const u_char *packet) {
	const struct udphdr *udp;
	udp = (struct udphdr*)(packet);

	printf("\n\t\t-UDP-\n\n");

	printf("\t\tPort Source : %d", ntohs(udp->source));
	switch (ntohs(udp->source)) {
		case 68:
			printf(" (BOOTP Client)\n");
			break;
		case 67:
			printf(" (BOOTP Server)\n");
			break;
		default:
			printf("\n");
	}

	printf("\t\tPort Destination : %d", ntohs(udp->dest));
	switch (ntohs(udp->source)) {
		case 68:
			printf(" (BOOTP Client)\n");
			callback_bootp(packet + 8);
			break;
		case 67:
			printf(" (BOOTP Server)\n");
			callback_bootp(packet + 8);
			break;
		default:
			printf("\n");
	}
}

void callback_bootp (const u_char *packet) {
	const struct bootp *bootp;
	bootp = (struct bootp*)(packet);

	printf("\n\t\t\t-BOOTP-\n\n");
	printf("\t\t\tOpcode : %d\n", bootp->bp_op);
	printf("\t\t\tHardware type : %d", bootp->bp_htype);
	if (bootp->bp_htype == 1) {
		printf(" => Ethernet");
	}
	printf("\n");
	printf("\t\t\tTransaction ID : 0x%0x\n", bootp->bp_xid);	// à revoir
	printf("\t\t\tIP Client : %s\n", inet_ntoa(bootp->bp_ciaddr));
	printf("\t\t\tYour IP : %s\n", inet_ntoa(bootp->bp_yiaddr));
	printf("\t\t\tIP Serveur : %s\n", inet_ntoa(bootp->bp_siaddr));
	printf("\t\t\tIP Passerelle : %s\n", inet_ntoa(bootp->bp_giaddr));

	if (bootp->bp_vend[0] == 0x63 && bootp->bp_vend[1] == 0x82 && bootp->bp_vend[2] == 0x53 && bootp->bp_vend[3] == 0x63) {
		printf("\t\t\tMagic Cookie détecté : DHCP\n");
		callback_dhcp(bootp->bp_vend+4);
	}
}

void callback_tcp (const u_char *packet) {
	const struct tcphdr *tcp;
	tcp = (struct tcphdr*)(packet);
	int port;

	printf("\n\t\t-TCP-\n\n");

	printf("\t\tNuméro de séquence : %d\n", ntohs(tcp->seq));
	printf("\t\tNuméro d'acquitement : %d\n", ntohs(tcp->ack_seq));
	printf("\t\tTaille de la fenêtre : %d\n", ntohs(tcp->window));
	printf("\t\tFlags : ");
	if (tcp->th_flags & TH_URG)
		printf("URG ");
	if (tcp->th_flags & TH_ACK)
		printf("ACK ");
	if (tcp->th_flags & TH_PUSH)
		printf("PUSH ");
	if (tcp->th_flags & TH_RST)
		printf("RST ");
	if (tcp->th_flags & TH_SYN)
		printf("SYN ");
	if (tcp->th_flags & TH_FIN)
		printf("FIN ");

	printf("\n");
	printf("\t\tPort Source : %d", ntohs(tcp->source));
	switch (ntohs(tcp->source)) {
		case 20:
			printf(" (FTP Server Data Port)\n");
			port = 21;
			break;
		case 21:
			printf(" (FTP Server Control Port)\n");
			port = 21;
			break;
		case 23:
			printf(" (Telnet)\n");
			port = 23;
			break;
		case 25:
			printf(" (SMTP)\n");
			port = 25;
			break;
		case 80:
			printf(" (HTTP Server)\n");
			port = 80;
			break;
		case 110:
			printf(" (POP3)\n");
			port = 110;
		case 143:
			printf(" (IMAP)\n");
			port = 143;
		case 993:
			printf(" (IMAP over SSL/TLS)\n");
			port = 143;
		default:
			printf("\n");
	}

	printf("\t\tPort Destination : %d", ntohs(tcp->dest));
	switch (ntohs(tcp->dest)) {
		case 20:
			printf(" (FTP Server Data Port)\n");
			port = 21;
			break;
		case 21:
			printf(" (FTP Server Control Port)\n");
			port = 21;
			break;
		case 23:
			printf(" (Telnet)\n");
			port = 23;
			break;
		case 25:
			printf(" (SMTP)\n");
			port = 25;
			break;
		case 80:
			printf(" (HTTP Server)\n");
			port = 80;
			break;
		case 110:
			printf(" (POP3)\n");
			port = 110;
		case 143:
			printf(" (IMAP)\n");
			port = 143;
		case 993:
			printf(" (IMAP over SSL/TLS)\n");
			port = 143;
		default:
			printf("\n");
	}

	// Options ?

	switch (port) {
		case 21:
			callback_ftp(packet + tcp->th_off*4);
			break;
		case 23:
			callback_telnet(packet + tcp->th_off*4);
			break;
		case 25:
			callback_smtp(packet + tcp->th_off*4);
			break;
		case 80:
			callback_http(packet + tcp->th_off*4);
			break;
		case 110:
			callback_pop(packet + tcp->th_off*4);
			break;
		case 143:
			callback_imap (packet + tcp->th_off*4);
			break;
	}

}

void callback_dhcp (const u_char *packet) {
	printf("\n\t\t\t\t-DHCP-\n\n");
	int i = 0;
	int j = 0;
	int k = 0;
	int size = 0;
	u_int32_t t;
	int mode;
	while (packet[i] != 0xff) {
		mode = packet[i];
		switch (mode) {
			case 1:
				printf("\t\t\t\tSubnet mask : ");
				i+=2;
				for (j = 0; j < 4; j++) {
					printf("%d", packet[i+j]);
					if (j < 3)
						printf(".");
				}
				i+=4;
				break;
			case 2:
				printf("\t\t\t\tTime offset : ");
				i+=2;
				memcpy(&t, &packet[i], 4);
				printf("%d", t);
				i+=4;
				break;
			case 3:
				printf("\t\t\t\tRouter : ");	//Liste de routeurs
				i++;
				size = packet[i];
				i++;
				j = 0;
				while (j != size) {
					for (k = 0; k < 4; j++) {
						printf("%d", packet[i+j+k]);
						if (k < 3)
							printf(".");
					}
					j+=4;
					i+=4;
					printf(" | ");
				}
				break;
			case 6:
				printf("\t\t\t\tDNS : ");	//Liste de DNS
				i++;
				size = packet[i];
				i++;
				j = 0;
				while (j != size) {
					for (k = 0; k < 4; j++) {
						printf("%d", packet[i+j+k]);
						if (k < 3)
							printf(".");
					}
					j+=4;
					i+=4;
					printf(" | ");
				}
				break;
			case 12:
				printf("\t\t\t\tHost Name : ");
				i++;
				size = packet[i];
				i++;
				for (j = 0; j < size; j++) {
					printf("%c", packet[i]);
					i++;
				}
				break;
			case 15:
				printf("\t\t\t\tDomain Name : ");
				i++;
				size = packet[i];
				i++;
				for (j = 0; j < size; j++) {
					printf("%c", packet[i]);
					i++;
				}
				i++;
				break;
			case 28:
				printf("\t\t\t\tBroadcast Address : ");
				i+=2;
				for (j = 0; j < 4; j++) {
					printf("%d", packet[i+j]);
					if (j < 3)
						printf(".");
				}
				i+=4;
				break;
			case 44:
				printf("\t\t\t\tNetbios name server : ");
				i++;
				size = packet[i];
				i++;
				j = 0;
				while (j != size) {
					for (k = 0; k < 4; j++) {
						printf("%d", packet[i+j+k]);
						if (k < 3)
							printf(".");
					}
					j+=4;
					i+=4;
					printf(" | ");
				}
				break;
			case 47:
				printf("\t\t\t\tNetbios scope : ");
				i++;
				size = packet[i];
				i++;
				j = 0;
				while (j != size) {
					for (k = 0; k < 4; j++) {
						printf("%d", packet[i+j+k]);
						if (k < 3)
							printf(".");
					}
					j+=4;
					i+=4;
					printf(" | ");
				}
				break;
			case 50:
				printf("\t\t\t\tRequested IP : ");
				i+=2;
				for (j = 0; j < 4; j++) {
					printf("%d", packet[i+j]);
					if (j < 3)
						printf(".");
				}
				i+=4;
				break;
			case 51:
				printf("\t\t\t\tLease time : ");
				i+=2;
				memcpy(&t, &packet[i], 4);
				printf("%d", t);
				i+=4;
				break;
			case 53:
				printf("\t\t\t\tDHCP message type : ");
				i += 2;
				switch(packet[i]) {
					case 1:
						printf("Discover");
						break;
					case 2:
						printf("Offer");
						break;
					case 3:
						printf("Request");
						break;
					case 4:
						printf("Ack");
						break;
					case 5:
						printf("Release");
						break;
				}
				i++;
				break;
			case 54:
				printf("\t\t\t\tServer identifier : ");
				i+=2;
				for (j = 0; j < 4; j++) {
					printf("%d", packet[i+j]);
					if (j < 3)
						printf(".");
				}
				i+=4;
				break;
			case 55:
				printf("\t\t\t\tParameter request list : ");
				i++;
				size = packet[i];
				i++;
				printf("\n");
				for (j = 0; j < size; j++) {
					switch(packet[i+j]) {
						case 1:
							printf("\t\t\t\t\t- Subnet Mask");
							break;
						case 2:
							printf("\t\t\t\t\t- Time offset");
							break;
						case 3:
							printf("\t\t\t\t\t- Router");
							break;
						case 6:
						 	printf("\t\t\t\t\t- DNS");
							break;
						case 12:
							printf("\t\t\t\t\t- Host name");
							break;
						case 15:
							printf("\t\t\t\t\t- Domain name");
							break;
						case 28:
							printf("\t\t\t\t\t- Broadcast name");
							break;
						case 44:
							printf("\t\t\t\t\t- Netbios name server");
							break;
						case 47:
							printf("\t\t\t\t\t- Netbios scope");
							break;
						case 50:
							printf("\t\t\t\t\t- Requested IP");
							break;
						case 51:
							printf("\t\t\t\t\t- Lease time");
							break;
						case 54:
							printf("\t\t\t\t\t- Server identifier");
							break;
						case 61:
							printf("\t\t\t\t\t- Client identifier");
							break;
						default:
							printf("\t\t\t\t\t- Option : %d", packet[i+j]);
							break;
					}
					if (j != size-1)
						printf("\n");
				}
				i+=size;
				break;
			case 61:
				printf("\t\t\t\tClient identifer : ");
				i++;
				size = packet[i];
				i++;
				for (j = 0; j < size; j++) {
					printf("%d", packet[i]);
					i++;
				}
				i++;
				break;
			default:
				printf("\t\t\t\tOption : %d", mode);
				i++;
				break;
		}

		printf("\n");

	}
}

void callback_arp (const u_char *packet) {
	const struct arphdr *arp;
	arp = (struct arphdr*)(packet);

	printf("\n\t-ARP-\n\n");

	printf("\tHardware Type : %d", ntohs(arp->ar_hrd));
	if (ntohs(arp->ar_hrd) == 1)
		printf(" => Ethernet");
	printf("\n");
	printf("\tProtocol Type : 0x%0x", ntohs(arp->ar_pro));
	if (ntohs(arp->ar_pro) == 0x0800)
	 	printf(" => IPv4");
	printf("\n");
	printf("\tOpcode : %d", ntohs(arp->ar_op));
	switch (ntohs(arp->ar_op)) {
		case ARPOP_REQUEST:
			printf(" => Request");
			break;
		case ARPOP_REPLY:
			printf(" => Reply");
			break;
		case ARPOP_RREQUEST:
			printf(" => RRequest");
			break;
		case ARPOP_InREQUEST:
			printf(" => InRequest");
			break;
		case ARPOP_InREPLY:
			printf(" => InReply");
			break;
		case ARPOP_NAK:
			printf(" => Nack");
	}
	printf("\n");
	/*
	printf("\tHardware Adress Sender : %s\n", ether_ntoa(arp->__ar_sha));
	printf("\tIP Adress Sender : %s\n", inet_ntoa(arp->__ar_sip));
	printf("\tHarware Adress Target : %s\n", ether_ntoa(arp->__ar_tha));
	printf("\tIP Adress Target : %s\n", inet_ntoa(arp->__ar_tip));
	*/
}

void callback_http (const u_char *packet) {
	printf("\n\t\t\t-HTTP-\n\n");
	for (size_t i = 0; i < strlen(packet); i++) {
		if ((packet[i] > 31 && packet[i] < 128) || packet[i] == '\n' || packet[i] == '\r')
			printf("%c", packet[i]);
		else
			printf(".");
	}
}

void callback_smtp (const u_char *packet) {
	printf("\n\t\t\t-SMTP-\n\n");
	for (size_t i = 0; i < strlen(packet); i++) {
		if ((packet[i] > 31 && packet[i] < 128) || packet[i] == '\n' || packet[i] == '\r')
			printf("%c", packet[i]);
		else
			printf(".");
	}
}

void callback_ftp (const u_char *packet) {
	printf("\n\t\t\t-FTP-\n\n");
	for (size_t i = 0; i < strlen(packet); i++) {
		if ((packet[i] > 31 && packet[i] < 128) || packet[i] == '\n' || packet[i] == '\r')
			printf("%c", packet[i]);
		else
			printf(".");
	}
}

void callback_pop (const u_char *packet) {
	printf("\n\t\t\t-POP3-\n\n");
	for (size_t i = 0; i < strlen(packet); i++) {
		if ((packet[i] > 31 && packet[i] < 128) || packet[i] == '\n' || packet[i] == '\r')
			printf("%c", packet[i]);
		else
			printf(".");
	}
}

void callback_imap (const u_char *packet) {
	printf("\n\t\t\t-IMAP-\n\n");
	for (size_t i = 0; i < strlen(packet); i++) {
		if ((packet[i] > 31 && packet[i] < 128) || packet[i] == '\n' || packet[i] == '\r')
			printf("%c", packet[i]);
		else
			printf(".");
	}
}

void callback_telnet (const u_char *packet) {
	char type;
	printf("\n\t\t\t-Telnet-\n\n");
	for (size_t i = 0; i < strlen(packet); i++) {
		// Caractère d'échappement reconnu
		if (packet[i] == 255) {
			i++;
			// char de contrôle de session
			// cas spécifique de SB
			if(packet[i] == 250) {
				printf("SUBOPTION for ");
				i++;
				switch(packet[i]) {
					case 24:
						printf("terminal type : ");
						type = 24;
						break;
					case 31:
						printf("window size : ");
						type = 31;
						break;
					case 32:
						printf("terminal speed : ");
						type = 32;
						break;
					case 36:
						printf("environment variables : ");
						type = 36;
						break;
					case 39:
						printf("new environment variables : ");
						type = 39;
						break;
					default:
						printf("unrecongized option : ");
						break;
				}
				i++;
				// 0 : valeur fournie / 1 : valeur requise
				switch(packet[i]) {
					case 0: {
						i++;
						// Affichage valeur
						switch(type) {
							// terminal type => string
							case 24: {
								while (packet[i] != 255 && packet[i+1] != 240) {
									printf("%c ", packet[i]);
									i++;
								}
								break;
							}
							// window size => 2 * 2 bytes (short)
							case 31: {
								unsigned short val;
								memcpy(&val, packet[i], 2);
								printf("%hu * ", val);
								i+=2;
								memcpy(&val, packet[i], 2);
								printf("%hu", val);
								i+=2;
								break;
							}
						}
						i+=2;
						break;
					}
					case 1:
						printf("required");
						i++;
						break;
				}
				printf("\n");
			} else {
				// négociation classique d'options
				switch(packet[i]) {
					case 251:
						printf("WILL ");
						break;
					case 252:
						printf("WON'T ");
						break;
					case 253:
						printf("DO ");
						break;
					case 254:
						printf("DON'T ");
					default:
						printf("unrecongized request ");
				}
				i++;
				switch(packet[i]) {
					case 1:
						printf("echo\n");
						break;
					case 3:
						printf("suppress go ahead\n");
						break;
					case 24:
						printf("terminal type\n");
						break;
					case 31:
						printf("window size\n");
						break;
					case 32:
						printf("terminal speed\n");
						break;
					case 34:
						printf("line mode\n");
						break;
					case 36:
						printf("environment variables\n");
						break;
					case 39:
						printf("new environment variables\n");
						break;
					default:
						printf("unrecongized option (%d)\n", packet[i]);
						break;
				}
			}
		} else {
			// Affichage texte si pas de caractère d'échappement
			if (isprint(packet[i]) || isspace(packet[i]))
				printf("%c", packet[i]);
			else
				printf(".");
		}
	}
}
