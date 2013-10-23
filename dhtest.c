/*
 * DHCP client simulation tool. For testing pursose only.
 * This program needs to be run with root privileges. 
 * Author - Saravanakumar.G E-mail: saravana815@gmail.com
 */

#include<stdio.h>
#include<string.h>
#include<sys/types.h>
#include<unistd.h>
#include<sys/socket.h>
#include<net/if.h>
#include<linux/if_packet.h>
#include<getopt.h>
#include<time.h>
#include<stdlib.h>
#include "headers.h"

int sock_packet, iface = 2;	/* Socket descripter & transmit interface index */
struct sockaddr_ll ll = { 0 };	/* Socket address structure */
u_int16_t vlan = 0;		
u_int8_t l3_tos = 0;		
u_int16_t l2_hdr_size = 14;	
u_int16_t l3_hdr_size = 20;	
u_int16_t l4_hdr_size = 8;	
u_int16_t dhcp_hdr_size = sizeof(struct dhcpv4_hdr);

/* All protocheader sizes */

/* DHCP packet, option buffer and size of option buffer */
u_char dhcp_packet_disc[1518] = { 0 };
u_char dhcp_packet_offer[1518] = { 0 };
u_char dhcp_packet_request[1518] = { 0 };
u_char dhcp_packet_ack[1518] = { 0 };
u_char dhcp_packet_release[1518] = { 0 };

u_char dhopt_buff[500] = { 0 };
u_int32_t dhopt_size = { 0 };
u_char dhmac[ETHER_ADDR_LEN] = { 0 };
u_char dmac[ETHER_ADDR_LEN];

char dhmac_fname[20];
char iface_name[30] = { 0 };
char ip_str[128];
u_int8_t dhmac_flag = 0;
u_int32_t server_id = { 0 }, option50_ip = { 0 };
u_int32_t dhcp_xid = 0;  
u_int16_t bcast_flag = 0; /* DHCP broadcast flag */ 
u_int8_t vci_buff[256] = { 0 }; /* VCI buffer*/
u_int16_t vci_flag = 0;
u_int8_t hostname_buff[256] = { 0 }; /* Hostname buffer*/
u_int16_t hostname_flag = 0;
u_int8_t fqdn_buff[256] = { 0 }; /* FQDN buffer*/
u_int16_t fqdn_flag = 0;
u_int16_t fqdn_n = 0;
u_int16_t fqdn_s = 0;
u_int32_t option51_lease_time = 0;
u_int32_t port = 67;
u_char *giaddr = "0.0.0.0";

/* Pointers for all layer data structures */
struct ethernet_hdr *eth_hg = { 0 };
struct vlan_hdr *vlan_hg = { 0 };
struct iphdr *iph_g = { 0 };
struct udphdr *uh_g = { 0 };
struct dhcpv4_hdr *dhcph_g = { 0 };


u_int8_t *dhopt_pointer_g = { 0 };
u_int8_t verbose = 0;
u_int8_t dhcp_release_flag = 0;
u_int8_t padding_flag = 0;
u_int16_t timeout = 0;
time_t time_now, time_last;

/* Used for ip listening functionality */
struct arp_hdr *arp_hg = { 0 };
struct icmp_hdr *icmp_hg = { 0 };

u_int32_t ip_address;
u_char ip_listen_flag = 0;
struct timeval tval_listen = { 3600, 0 };
u_int32_t listen_timeout = 3600;
u_char arp_icmp_packet[1514] = { 0 };
u_char arp_icmp_reply[1514] = { 0 };
u_int16_t icmp_len = 0;

/* Help routine for the command line interface */
void print_help(char *cmd)
{
	fprintf(stdout, "Usage: %s [ options ] -m mac_address\n", cmd);
	fprintf(stdout, "  -r, --release\t\t\t\t# Releases obtained DHCP IP for corresponding MAC\n");
	fprintf(stdout, "  -L, --option51-lease_time [ Lease_time ] # Option 51. Requested lease time in secondes\n");
	fprintf(stdout, "  -I, --option50-ip\t[ IP_address ]\t# Option 50 IP address on DHCP discover\n");
	fprintf(stdout, "  -o, --option60-vci\t[ VCI_string ]\t# Vendor Class Idendifier string\n");
	fprintf(stdout, "  -h, --option12-hostname [ hostname_string ] # Client hostname string\n");
	fprintf(stdout, "  -v, --vlan\t\t[ vlan_id ]\t# VLAN ID. Range(1 - 4094)\n");
	/* fprintf(stdout, "  -x, --dhcp_xid\t[ dhcp_xid ]\n"); */
	fprintf(stdout, "  -t, --tos\t\t[ TOS_value ]\t# IP header TOS value\n");
	fprintf(stdout, "  -i, --interface\t[ interface ]\t# Interface to use. Default eth0\n");
	fprintf(stdout, "  -T, --timeout\t\t[ cmd_timeout ]\t# Command returns within specified timout in seconds\n");
	fprintf(stdout, "  -b, --bind-ip\t\t\t\t# Listens on the obtained IP. Supported protocols - ARP and ICMP\n");
	fprintf(stdout, "  -k, --bind-timeout\t[ timeout ]\t# Listen timout in seconds. Default 3600 seconds\n");
	fprintf(stdout, "  -f, --bcast_flag\t\t\t# Sets broadcast flag on DHCP discover and request\n");
	fprintf(stdout, "  -d, --fqdn-domain-name   [ fqdn ]\t# FQDN domain name to use\n");
	fprintf(stdout, "  -n, --fqdn-server-not-update\t\t# Sets FQDN server not update flag\n");
	fprintf(stdout, "  -s, --fqdn-server-update-a\t\t# Sets FQDN server update flag\n");
	fprintf(stdout, "  -p, --padding\t\t\t\t# Add padding to packet to be at least 300 bytes\n");
	fprintf(stdout, "  -P, --port\t\t[ port ]\t# Use port instead of 67\n");
	fprintf(stdout, "  -g, --giaddr\t\t[ giaddr ]\t# Use giaddr instead of 0.0.0.0\n");
	fprintf(stdout, "  -V, --verbose\t\t\t\t# Prints DHCP offer and ack details\n");
	fprintf(stdout, "  dhtest version 1.2\n");
}


int main(int argc, char *argv[])
{
	int get_tmp = 1, get_cmd;

	if(argc < 3) {
		print_help(argv[0]);
		exit(1);
	}

	int option_index = 0;
	static struct option long_options[] = {
		{ "mac", required_argument, 0, 'm' },
		{ "interface", required_argument, 0, 'i' },
		{ "vlan", required_argument, 0, 'v' },
		{ "dhcp_xid", required_argument, 0, 'x' },
		{ "tos", required_argument, 0, 't' },
		{ "option51-lease_time", required_argument, 0, 'L' },
		{ "option50-ip", required_argument, 0, 'I' },
		{ "option60-vci", required_argument, 0, 'o' },
		{ "option12-hostname", required_argument, 0, 'h' },
		{ "timeout", required_argument, 0, 'T' },
		{ "bind-ip", no_argument, 0, 'b' },
		{ "bind-timeout", required_argument, 0, 'k' },
		{ "bcast_flag", no_argument, 0, 'f'},
		{ "verbose", no_argument, 0, 'V'},
		{ "fqdn-server-not-update", no_argument, 0, 'n'},
		{ "fqdn-server-update-a", no_argument, 0, 's'},
		{ "fqdn-domain-name", required_argument, 0, 'd'},
		{ "padding", no_argument, 0, 'p'},
		{ "port", required_argument, 0, 'P'},
		{ "giaddr", required_argument, 0, 'g'},
		{ "release", no_argument, 0, 'r'},
		{ 0, 0, 0, 0 }
	};

	/*getopt routine to get command line arguments*/
	while(get_tmp < argc) {
		get_cmd  = getopt_long(argc, argv, "m:i:v:t:bfVrpT:P:g:I:o:k:L:h:n:s:d:",\
				long_options, &option_index);
		if(get_cmd == -1 ) {
			break;
		}
		switch(get_cmd) {
			case 'm':
				{
					u_char aux_dhmac[ETHER_ADDR_LEN + 1];

					if(strlen(optarg) > 18) {
						fprintf(stdout, "Invalid mac address\n");
						exit(1);
					}
					strcpy(dhmac_fname, optarg);
					sscanf((char *)optarg, "%2X:%2X:%2X:%2X:%2X:%2X",
							(u_int32_t *) &aux_dhmac[0], (u_int32_t *) &aux_dhmac[1],
							(u_int32_t *) &aux_dhmac[2], (u_int32_t *) &aux_dhmac[3],
							(u_int32_t *) &aux_dhmac[4], (u_int32_t *) &aux_dhmac[5]);
					memcpy(dhmac, aux_dhmac, sizeof(dhmac));
					dhmac_flag = 1;
				}
				break;

			case 'i':
				iface = if_nametoindex(optarg);
				if(iface == 0) {
					fprintf(stdout, "Interface doesnot exist\n");
					exit(1);
				}
				strncpy(iface_name, optarg, 29);
				break;

			case 'v':
				if(atoi(optarg) < 1 || atoi(optarg) > 4095)
				{
					fprintf(stdout, "VLAN ID is not valid. Range 1 to 4095\n");
					exit(1);
				}
				vlan = atoi(optarg);
				l2_hdr_size = 18;
				break;

			case 'r':
				dhcp_release_flag = 1;
				break;

			case 'b':
				ip_listen_flag = 1;
				break;

			case 'k':
				listen_timeout = atoi(optarg);
				tval_listen.tv_sec = listen_timeout;
				break;

			case 'x':
				{
					u_int32_t aux_dhcp_xid[2];
					aux_dhcp_xid[0] = 0;
					sscanf((char *)optarg, "%X", &aux_dhcp_xid[0]);
					dhcp_xid = aux_dhcp_xid[0];
				}
				break;

			case 't':
				if(atoi(optarg) >= 256 || atoi(optarg) < 0) {
					fprintf(stdout, "Invalid TOS value\n");
					exit(1);
				}
				l3_tos = atoi(optarg);
				break;

			case 'L':
				option51_lease_time = atoi(optarg);
				break;

			case 'I':
				option50_ip = inet_addr(optarg);
				break;

			case 'o':
				if(strlen(optarg) > 256) {
					fprintf(stdout, "VCI string size should be less than 256\n");
					exit(1);
				}
				vci_flag = 1;
				memcpy(vci_buff, optarg, sizeof(vci_buff));
				break;

			case 'h':
				if(strlen(optarg) > 256) {
					fprintf(stdout, "Hostname string size should be less than 256\n");
					exit(1);
				}
				hostname_flag = 1;
				memcpy(hostname_buff, optarg, sizeof(hostname_buff));
				break;

			case 'd':
				if(strlen(optarg) > 256) {
					fprintf(stdout, "FQDN domain name string size should be less than 256\n");
					exit(1);
				}
				fqdn_flag = 1;
				memcpy(fqdn_buff, optarg, sizeof(fqdn_buff));
				break;

			case 'n':
				fqdn_n = 1;
				break;

			case 's':
				fqdn_s = 1;
				break;

			case 'T':
				if(atoi(optarg) < 5 || atoi(optarg) > 3600) {
					fprintf(stdout, "Invalid timout value. Range 5 to 3600\n");
					exit(1);
				}
				timeout = atoi(optarg);
				break;

			case 'P':
				if(atoi(optarg) <=0 || atoi(optarg) > 65535) {
					fprintf(stdout, "Invalid portt value. Range 1 to 65535\n");
					exit(1);
				}
				port = atoi(optarg);
				break;

			case 'g':
				giaddr = optarg;
				break;

			case 'p':
				padding_flag = 1;
				break;

			case 'f':
				bcast_flag = htons(0x8000);
				break;

			case 'V':
				verbose = 1;
				break;

			default:
				exit(1);
		}
		get_tmp++;
	}	

	if(!dhmac_flag) {
		print_help(argv[0]);
		exit(1);
	}
	/* Opens the PF_PACKET socket */
	if(open_socket() < 0) {
		fprintf(stdout, "Socket error\n");
		exit(1);
	}

	/* Sets the promiscuous mode */
	set_promisc();

	/* Sets a random DHCP xid */
	set_rand_dhcp_xid(); 

	/*
	 * If DHCP release flag is set, send DHCP release packet
	 * and exit. get_dhinfo parses the DHCP info from log file
	 * and unlinks it from the system
	 */
	if(dhcp_release_flag) {
		if(get_dhinfo() == ERR_FILE_OPEN) {
			fprintf(stdout, "Error on opening DHCP info file\n");
			fprintf(stdout, "Release the DHCP IP after acquiring\n");
			exit(1);
		}
		build_option53(DHCP_MSGRELEASE); /* Option53 DHCP release */
		if(hostname_flag) {
			build_option12_hostname();
		}
		if(fqdn_flag) {
			build_option81_fqdn();
		}
		build_option54();		 /* Server id */
		build_optioneof();		 /* End of option */
		build_dhpacket(DHCP_MSGRELEASE); /* Build DHCP release packet */
		send_packet(DHCP_MSGRELEASE);	 /* Send DHCP release packet */
		clear_promisc();		 /* Clear the promiscuous mode */
		close_socket();
		return 0; 
	}
	if(timeout) {
		time_last = time(NULL);
	}
	build_option53(DHCP_MSGDISCOVER);	/* Option53 for DHCP discover */
	if(hostname_flag) {
		build_option12_hostname();
	}
	if(fqdn_flag) {
		build_option81_fqdn();
	}
	if(option50_ip) {
		build_option50();		/* Option50 - req. IP  */
	}
	if(option51_lease_time) {
		build_option51();               /* Option51 - DHCP lease time requested */
	}

	if(vci_flag == 1) {
		build_option60_vci(); 		/* Option60 - VCI  */
	}
	build_optioneof();			/* End of option */
	build_dhpacket(DHCP_MSGDISCOVER);	/* Build DHCP discover packet */

	int dhcp_offer_state = 0;
	while(dhcp_offer_state != DHCP_OFFR_RCVD) {

		/* Sends DHCP discover packet */
		send_packet(DHCP_MSGDISCOVER);
		/*
		 * recv_packet functions returns when the specified 
		 * packet is received
		 */
		dhcp_offer_state = recv_packet(DHCP_MSGOFFER); 

		if(timeout) {
			time_now = time(NULL);
			if((time_now - time_last) > timeout) {
				close_socket();
				exit(1);
			}
		}
		if(dhcp_offer_state == DHCP_OFFR_RCVD) {
			fprintf(stdout, "DHCP offer received\t - ");
			set_serv_id_opt50();
			fprintf(stdout, "Offered IP : %s\n", get_ip_str(dhcph_g->dhcp_yip));
			if(verbose) { 
				print_dhinfo(DHCP_MSGOFFER);
			}
		}
	}
	/* Reset the dhopt buffer to build DHCP request options  */
	reset_dhopt_size();
	build_option53(DHCP_MSGREQUEST); 
	build_option50();
	build_option54();
	if(hostname_flag) {
		build_option12_hostname();
	}
	if(fqdn_flag) {
		build_option81_fqdn();
	}
	if(vci_flag == 1) {
		build_option60_vci();  
	}
	if(option51_lease_time) {
		build_option51();                       /* Option51 - DHCP lease time requested */
	}
	build_option55();
	build_optioneof();
	build_dhpacket(DHCP_MSGREQUEST); 		/* Builds specified packet */
	int dhcp_ack_state = 1;
	while(dhcp_ack_state != DHCP_ACK_RCVD) { 

		send_packet(DHCP_MSGREQUEST);
		dhcp_ack_state = recv_packet(DHCP_MSGACK); 

		if(timeout) {
			time_now = time(NULL);
			if((time_now - time_last) > timeout) {
				fprintf(stdout, "Timeout reached. Exiting\n");
				close_socket();
				exit(1);
			}
		}

		if(dhcp_ack_state == DHCP_ACK_RCVD) {
			fprintf(stdout, "DHCP ack received\t - ");
			fprintf(stdout, "Acquired IP: %s\n", get_ip_str(dhcph_g->dhcp_yip));

			/* Logs DHCP IP details to log file. This file is used for DHCP release */
			log_dhinfo(); 
			if(verbose) {
				print_dhinfo(DHCP_MSGACK);
			}
		} else if (dhcp_ack_state == DHCP_NAK_RCVD) {
			fprintf(stdout, "DHCP nack received\t - ");
			fprintf(stdout, "Client MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", \
					dhmac[0], dhmac[1], dhmac[2], dhmac[3], dhmac[4], dhmac[5]); 
		}
	}
	/* If IP listen flag is enabled, Listen on obtained for ARP, ICMP protocols  */
	if(ip_listen_flag) {
		fprintf(stdout, "\nListening on %s for ARP and ICMP protocols\n", iface_name);
		fprintf(stdout, "IP address: %s, Listen timeout: %d seconds\n", get_ip_str(htonl(ip_address)), listen_timeout);
		int arp_icmp_rcv_state = 0;
		while(arp_icmp_rcv_state != LISTEN_TIMOUET) { 
			arp_icmp_rcv_state = recv_packet(ARP_ICMP_RCV);
			/* Send ARP reply if ARP request received */
			if(arp_icmp_rcv_state == ARP_RCVD) {
				/*if(verbose) {
				  fprintf(stdout, "ARP request received\n");
				  fprintf(stdout, "Sending ARP reply\n");
				  }*/
				build_packet(ARP_SEND);
				send_packet(ARP_SEND);
			} else if(arp_icmp_rcv_state == ICMP_RCVD) {
				/* Send ICMP reply if ICMP echo request received */
				/*if(verbose) {
				  fprintf(stdout, "ICMP request received\n");
				  fprintf(stdout, "Sending ICMP reply\n");
				  }*/
				build_packet(ICMP_SEND);
				send_packet(ICMP_SEND);  
			} 
		}
		fprintf(stdout, "Listen timout reached\n");
	}
	/* Clear the promiscuous mode */
	clear_promisc();
	/* Close the socket */
	close_socket();
	return 0;
}
