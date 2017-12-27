#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "../headers/en_tetes.h"

int main (int argc, char ** argv) {

	if (argc < 2) {
		fprintf(stderr, "Usage : %s <-f interface | -o file> <-v verbosity> [-f filter]  \n", argv[0]);
		exit(EXIT_FAILURE);
	}

	int c;
	extern char* optarg;
	char mode;
	char* interface = NULL;
	char* file = NULL;
	char* filter = NULL;
	int verbo = 0;
	char ivalid = 0;

	// Option affichage interfaces ?

	while ((c = getopt(argc , argv, "i:o:f:v:")) != -1) {
		switch(c) {
			case 'i':
				mode = 'i';
				interface = strdup(optarg);
				break;
			case 'o':
				mode = 'o';
				file = strdup(optarg);
				break;
			case 'f':
				filter = strdup(optarg);
				break;
			case 'v':
				if (atoi(optarg) <= 3 && atoi(optarg) >= 1)
					verbo = atoi(optarg);
				break;
		}
	}

	if (interface == NULL && file == NULL) {
		fprintf(stderr, "%s: option -i or -o is required\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (!verbo) {
		fprintf(stderr, "%s: option -v is required\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	pcap_t* capture = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	switch (mode) {
		case 'i': {
			pcap_if_t *alldevsp;
			pcap_if_t *d;

			// Véfification existance interface
			if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
				fprintf(stderr, "%s: %s\n", argv[0], errbuf);
				exit(EXIT_FAILURE);
			}

			for (d = alldevsp; d != NULL; d = d->next) {
				if (!strcmp(interface, d->name)) {
					ivalid = 1;
					break;
				}
			}
			if (!ivalid) {
				fprintf(stderr, "%s: Unknown interface\n", argv[0]);
				exit(EXIT_FAILURE);
			}

			// Création de la capture
			capture = pcap_open_live(interface, 65535, 1, 1000, errbuf);
			if (capture == NULL) {
				fprintf(stderr, "%s: %s\n", argv[0], errbuf);
				exit(EXIT_FAILURE);
			}

			// Filtre possible en mode offline ?
			if (filter != NULL) {
				// Récupération du masque pour le filtre
				bpf_u_int32 *netaddr = NULL, *netmask = NULL;
				if (pcap_lookupnet(interface, netaddr, netmask, errbuf) == -1) {
					fprintf(stderr, "%s: %s\n", argv[0], errbuf);
					exit(EXIT_FAILURE);
				}

				// Compilation du filtre
				struct bpf_program *cf = NULL;
				if (pcap_compile(capture, cf, filter, 1, *netmask) == -1) {
					fprintf(stderr, "%s: Unable to compile filter\n", argv[0]);
					exit(EXIT_FAILURE);
				}

				// Association du filtre à la capture
				if (pcap_setfilter(capture, cf) == -1) {
					fprintf(stderr, "%s: Unable to associate filter to capture\n", argv[0]);
					exit(EXIT_FAILURE);
				}
			}
			break;
		}

		case 'o': {
			FILE* fd;
			if ((fd = fopen(file, "r")) == NULL) {
				fprintf(stderr, "%s: Unable to open file %s\n", argv[0], file);
				exit(EXIT_FAILURE);
			}
			fclose(fd);

			capture = pcap_open_offline (file, errbuf);
			break;
		}
	}


	if (pcap_loop(capture, -1, callback_ethernet, NULL) == -1) {
		fprintf(stderr, "%s: Unable to launch capture\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	pcap_close(capture);

	return 0;
}
