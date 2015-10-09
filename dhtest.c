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
#include<netinet/in.h>
#include<arpa/inet.h>
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

/* 
* For Custom DHCP options
* Static arrays for custom_dhcp_option_hdr
*/
#define MAX_CUSTOM_DHCP_OPTIONS 64
u_int8_t no_custom_dhcp_options = { 0 };
struct custom_dhcp_option_hdr custom_dhcp_options[MAX_CUSTOM_DHCP_OPTIONS];

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
u_int8_t unicast_flag = 0;
u_int8_t nagios_flag = 0;
u_int8_t json_flag = 0;
u_int8_t json_first = 1;
u_char *giaddr = "0.0.0.0";
u_char *server_addr = "255.255.255.255";

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

u_int32_t unicast_ip_address = 0;
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
	fprintf(stdout, "Usage: %s [ options ]\n", cmd);
	fprintf(stdout, "  -m mac_address\n");
	fprintf(stdout, "  -r, --release\t\t\t\t# Releases obtained DHCP IP for corresponding MAC\n");
	fprintf(stdout, "  -L, --option51-lease_time [ Lease_time ] # Option 51. Requested lease time in secondes\n");
	fprintf(stdout, "  -I, --option50-ip\t[ IP_address ]\t# Option 50 IP address on DHCP discover\n");
	fprintf(stdout, "  -o, --option60-vci\t[ VCI_string ]\t# Vendor Class Idendifier string\n");
	fprintf(stdout, "  -h, --option12-hostname [ hostname_string ] # Client hostname string\n");
	fprintf(stdout, "  -c, --custom-dhcp-option [ option_format ] # option_format - option_number,type_of_option_value(str|num|hex|ip),option_value\n");
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
	fprintf(stdout, "  -u, --unicast\t\t[ ip ]\t\t# Unicast request, IP is optional. If not specified, the interface address will be used. \n");
	fprintf(stdout, "  -a, --nagios\t\t\t\t# Nagios output format. \n");
	fprintf(stdout, "  -S, --server\t\t[ address ]\t# Use server address instead of 255.255.255.255\n");
	fprintf(stdout, "  -j, --json\t\t\t\t# Set the output format to json\n");
	fprintf(stdout, "  -V, --verbose\t\t\t\t# Prints DHCP offer and ack details\n");
	fprintf(stdout, "  dhtest version 1.4\n");
}


int main(int argc, char *argv[])
{
	int get_tmp = 1, get_cmd;

	if(argc < 3) {
		print_help(argv[0]);
		exit(2);
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
		{ "custom-dhcp-option", required_argument, 0, 'c' },
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
		{ "unicast", optional_argument, 0, 'u'},
		{ "nagios", no_argument, 0, 'a'},
		{ "server", required_argument, 0, 'S'},
		{ "release", no_argument, 0, 'r'},
		{ "json", no_argument, 0, 'j'},
		{ 0, 0, 0, 0 }
	};

	/*getopt routine to get command line arguments*/
	while(get_tmp < argc) {
		get_cmd  = getopt_long(argc, argv, "m:i:v:t:bfVrpansju::T:P:g:S:I:o:k:L:h:d:c:",\
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
						exit(2);
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
					exit(2);
				}
				strncpy(iface_name, optarg, 29);
				break;

			case 'v':
				if(atoi(optarg) < 1 || atoi(optarg) > 4095)
				{
					fprintf(stdout, "VLAN ID is not valid. Range 1 to 4095\n");
					exit(2);
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
					exit(2);
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
					exit(2);
				}
				vci_flag = 1;
				memcpy(vci_buff, optarg, sizeof(vci_buff));
				break;

			case 'h':
				if(strlen(optarg) > 256) {
					fprintf(stdout, "Hostname string size should be less than 256\n");
					exit(2);
				}
				hostname_flag = 1;
				memcpy(hostname_buff, optarg, sizeof(hostname_buff));
				break;

			case 'd':
				if(strlen(optarg) > 256) {
					fprintf(stdout, "FQDN domain name string size should be less than 256\n");
					exit(2);
				}
				fqdn_flag = 1;
				memcpy(fqdn_buff, optarg, sizeof(fqdn_buff));
				break;

			case 'c':
                                if (no_custom_dhcp_options == MAX_CUSTOM_DHCP_OPTIONS) {
					fprintf(stdout, "MAX custom DHCP options reached. MAX custom DHCP options supported : %d\n", \
                                            MAX_CUSTOM_DHCP_OPTIONS);
					exit(2);
                                }

                                //scanf the custom dhcp option
                                //format - option_no_dec,str|num|hex|ip,option_value
                                
                                u_int8_t option_no, option_type;
                                u_char option_value[256] = { 0 };
                                u_int32_t option_value_num = { 0 }, option_value_ip = { 0 };
                                int option_index = 0;
                                int scanf_state;

                                if ((sscanf((char *)optarg, "%u,str,%255[^\n]s", (u_int32_t *) &option_no, option_value)) == 2) {
                                    if ((strlen(option_value) >= 256)) {
                                        fprintf(stdout, "dhcp custom option value string length is more than 255\n");
                                        exit(2);
                                    }
                                    no_custom_dhcp_options = no_custom_dhcp_options + 1;
                                    option_index = no_custom_dhcp_options - 1;

                                    custom_dhcp_options[option_index].option_no = option_no;
                                    custom_dhcp_options[option_index].option_type = CUST_DHCP_OPTION_STRING; 
                                    custom_dhcp_options[option_index].option_len = strlen((const char *) option_value); 
                                    memcpy(custom_dhcp_options[option_index].option_value, option_value, sizeof(custom_dhcp_options[option_index].option_value));

                                } else if ((sscanf((char *)optarg, "%u,num,%u", (u_int32_t *) &option_no, &option_value_num)) == 2) {
                                    no_custom_dhcp_options = no_custom_dhcp_options + 1;
                                    option_index = no_custom_dhcp_options - 1;

                                    custom_dhcp_options[option_index].option_no = option_no;
                                    custom_dhcp_options[option_index].option_type = CUST_DHCP_OPTION_NUMBER; 
                                    custom_dhcp_options[option_index].option_len = 4; //length of 4 byte
                                    custom_dhcp_options[option_index].option_value_num = htonl(option_value_num); 
                                    //memcpy(custom_dhcp_options[option_index].option_value, option_value, sizeof(custom_dhcp_options[option_index].option_value));
                                    
                                } else if ((sscanf((char *)optarg, "%u,hex,%254s", (u_int32_t *) &option_no, option_value)) == 2) {
                                    if ((strlen(option_value) >= 255)) {
                                        fprintf(stdout, "dhcp custom option value hex length is more than 254\n");
                                        exit(2);
                                    }
                                    no_custom_dhcp_options = no_custom_dhcp_options + 1;
                                    option_index = no_custom_dhcp_options - 1;
                                    //fprintf(stdout, "option_value string %s\n", option_value);
                                    if ((strlen((const char *) option_value) % 2) == 1) {
                                        fprintf(stdout, "option hex value length must be even\n");
                                        exit(2);
                                    }
                                    int hex_length = (strlen((const char *) option_value)/2);

                                    custom_dhcp_options[option_index].option_no = option_no;
                                    custom_dhcp_options[option_index].option_type = CUST_DHCP_OPTION_HEX; 
                                    custom_dhcp_options[option_index].option_len = hex_length; 
                                    //memcpy(custom_dhcp_options[option_index].option_value, option_value, sizeof(custom_dhcp_options[option_index].option_value));
                                    int tmp, index = 0;
                                    for(tmp = 0; tmp < hex_length; tmp++) {
                                        sscanf(&option_value[index], "%2X", &custom_dhcp_options[option_index].option_value[tmp]);
                                        index = index + 2;
                                    }

                                    //print_buff(custom_dhcp_options[option_index].option_value, (hex_length/2));
                                } else if ((sscanf((char *)optarg, "%u,ip,%s", (u_int32_t *) &option_no, option_value)) == 2) {
                                    no_custom_dhcp_options = no_custom_dhcp_options + 1;
                                    option_index = no_custom_dhcp_options - 1;

                                    option_value_ip = inet_addr((const char *) option_value);
                                    if (option_value_ip == INADDR_NONE) { 
                                        fprintf(stdout, "Invalid IP address on option value\n");
                                        exit(2);
                                    }
                                    custom_dhcp_options[option_index].option_no = option_no;
                                    custom_dhcp_options[option_index].option_type = CUST_DHCP_OPTION_IP; 
                                    custom_dhcp_options[option_index].option_len = 4; //length of 4 byte
                                    custom_dhcp_options[option_index].option_value_ip = option_value_ip; 
                                    //memcpy(custom_dhcp_options[option_index].option_value, option_value, sizeof(custom_dhcp_options[option_index].option_value));

                                } else {
                                    fprintf(stdout, "custom option parse error. Use correct format\n");
                                    exit(2);
                                }
                                
                                /* - For debugging
                                fprintf(stdout, "Custom dhcp option - %s\n", optarg);
                                fprintf(stdout, "Custom dhcp option count - %d\n", no_custom_dhcp_options);
                                fprintf(stdout, "Option_no parsed - %d \n", custom_dhcp_options[option_index].option_no);
                                fprintf(stdout, "Option_format - %d \n", custom_dhcp_options[option_index].option_type);
                                fprintf(stdout, "Option_value_num - %u \n", custom_dhcp_options[option_index].option_value_num);
                                fprintf(stdout, "Option_value_ip - %u\n", custom_dhcp_options[option_index].option_value_ip);
                                if (custom_dhcp_options[option_index].option_type == CUST_DHCP_OPTION_HEX) {
                                    print_buff(custom_dhcp_options[option_index].option_value, ((strlen((const char *) option_value))/2));
                                } else {
                                    fprintf(stdout, "Option_value string - %s\n", custom_dhcp_options[option_index].option_value);
                                }
                                */
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
					exit(2);
				}
				timeout = atoi(optarg);
				break;

			case 'P':
				if(atoi(optarg) <=0 || atoi(optarg) > 65535) {
					fprintf(stdout, "Invalid portt value. Range 1 to 65535\n");
					exit(2);
				}
				port = atoi(optarg);
				break;

			case 'g':
				giaddr = optarg;
				break;

			case 'S':
				server_addr = optarg;
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

			case 'u':
				if (optarg) {
					struct in_addr out;

					if (!inet_aton(optarg, &out)) {
						fprintf(stdout, "Invalid unicast IP address.");
						exit(2);
					}
					unicast_ip_address = out.s_addr;
				}
				unicast_flag = 1;
				break;

			case 'a':
				nagios_flag = 1;
				break;

			case 'j':
				json_flag = 1;
				break;

			default:
				exit(2);
		}
		get_tmp++;
	}	

	if(!dhmac_flag) {
		print_help(argv[0]);
		exit(2);
	}

	if(json_flag) {
		fprintf(stdout, "[");
	}

	/* Opens the PF_PACKET socket */
	if(open_socket() < 0) {
		if (nagios_flag) {
			fprintf(stdout, "CRITICAL: Socket error.");
		} else if(json_flag) {
			if(!json_first) {
				fprintf(stdout, ",");
			} else {
				json_first = 0;
			}

			fprintf(stdout, "{\"msg\":\"Socket error.\","
					"\"result\":\"error\","
					"\"error-type\":\"socket\","
					"\"error-msg\":\"Socket error.\"}"
					"]");
		} else {
			fprintf(stdout, "Socket error\n");
		}

		exit(2);
	}

	/* Sets the promiscuous mode */
	set_promisc();

	if (unicast_flag && !unicast_ip_address) {
		unicast_ip_address = get_interface_address();
	}

	/* Sets a random DHCP xid */
	set_rand_dhcp_xid(); 

	/*
	 * If DHCP release flag is set, send DHCP release packet
	 * and exit. get_dhinfo parses the DHCP info from log file
	 * and unlinks it from the system
	 */
	if(dhcp_release_flag) {
		if(get_dhinfo() == ERR_FILE_OPEN) {
			if (nagios_flag) {
				fprintf(stdout, "CRITICAL: Error on opening DHCP info file.");
			} else if(json_flag) {
				if(!json_first) {
					fprintf(stdout, ",");
				} else {
					json_first = 0;
				}

				fprintf(stdout, "{\"msg\":\"Error on opening DHCP info file.\","
						"\"result\":\"error\","
						"\"error-type\":\"info-file\","
						"\"error-msg\":\"Error on opening DHCP info file.\"}"
						"]");
			} else {
				fprintf(stdout, "Error on opening DHCP info file\n");
				fprintf(stdout, "Release the DHCP IP after acquiring\n");
			}
			exit(2);
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
        build_option55();                       /* Option55 - parameter request list */
	if(option51_lease_time) {
		build_option51();               /* Option51 - DHCP lease time requested */
	}

	if(vci_flag == 1) {
		build_option60_vci(); 		/* Option60 - VCI  */
	}
        /* Build custom options */
        if(no_custom_dhcp_options) {
            build_custom_dhcp_options();
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
			if((time_now - time_last) >= timeout) {
				if (nagios_flag) {
					fprintf(stdout, "CRITICAL: Timeout reached: DISCOVER.");
				} else if(json_flag) {
					if(!json_first) {
						fprintf(stdout, ",");
					} else {
						json_first = 0;
					}

					fprintf(stdout, "{\"msg\":\"Timeout reached: DISCOVER.\","
                                                "\"result\":\"error\","
                                                "\"error-type\":\"timeout\","
						"\"error-subtype\":\"DISCOVER\""
                                                "\"error-msg\":\"Timeout reached: DISCOVER.\"}"
						"]");
				}

				close_socket();
				exit(2);
			}
		}
		if(dhcp_offer_state == DHCP_OFFR_RCVD) {
			if (!nagios_flag && !json_flag) {
				fprintf(stdout, "DHCP offer received\t - ");
			} else if(!nagios_flag) {
				if(!json_first) {
					fprintf(stdout, ",");
				} else {
					json_first = 0;
				}

				fprintf(stdout, "{\"msg\":\"DHCP offer received - %s\","
						"\"result\":\"success\","
						"\"result-type\":\"OFFER\","
						"\"result-value\":\"%s\""
						"}",
					get_ip_str(dhcph_g->dhcp_yip), get_ip_str(dhcph_g->dhcp_yip));
			}

			set_serv_id_opt50();
			if (!nagios_flag && !json_flag)
  				fprintf(stdout, "Offered IP : %s\n", get_ip_str(dhcph_g->dhcp_yip));
			if(!nagios_flag && verbose) { 
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
        build_option55();                               /* Option55 - parameter request list */
        /* Build custom options */
        if(no_custom_dhcp_options) {
                build_custom_dhcp_options();
        }
	build_optioneof();
	build_dhpacket(DHCP_MSGREQUEST); 		/* Builds specified packet */
	int dhcp_ack_state = 1;
	while(dhcp_ack_state != DHCP_ACK_RCVD) { 

		send_packet(DHCP_MSGREQUEST);
		dhcp_ack_state = recv_packet(DHCP_MSGACK); 

		if(timeout) {
			time_now = time(NULL);
			if((time_now - time_last) > timeout) {
				if (nagios_flag) {
					fprintf(stdout, "CRITICAL: Timeout reached: REQUEST.");
				} else if(json_flag) {
					if(!json_first) {
						fprintf(stdout, ",");
					} else {
						json_first = 0;
					}

					fprintf(stdout, "{\"msg\":\"Timeout reached: REQUEST.\","
                                                "\"result\":\"error\","
                                                "\"error-type\":\"timeout\","
                                                "\"error-subtype\":\"REQUEST\""
                                                "\"error-msg\":\"Timeout reached: REQUEST.\"}"
                                                "]");
				} else {
					fprintf(stdout, "Timeout reached. Exiting\n");
				}
				close_socket();
				exit(1);
			}
		}

		if(dhcp_ack_state == DHCP_ACK_RCVD) {
			if (nagios_flag) {
				fprintf(stdout, "OK: Acquired IP: %s", get_ip_str(dhcph_g->dhcp_yip));
			} else if(json_flag) {
				if(!json_first) {
					fprintf(stdout, ",");
				} else {
					json_first = 0;
				}

				fprintf(stdout, "{\"msg\":\"DHCP ack received - %s\","
                                                "\"result\":\"success\","
                                                "\"result-type\":\"ACK\","
                                                "\"result-value\":\"%s\""
						"}",
                                        get_ip_str(dhcph_g->dhcp_yip), get_ip_str(dhcph_g->dhcp_yip));
			} else {
				fprintf(stdout, "DHCP ack received\t - ");
				fprintf(stdout, "Acquired IP: %s\n", get_ip_str(dhcph_g->dhcp_yip));
			}

			/* Logs DHCP IP details to log file. This file is used for DHCP release */
			log_dhinfo(); 
			if(!nagios_flag && verbose) {
				print_dhinfo(DHCP_MSGACK);
			}
		} else if (dhcp_ack_state == DHCP_NAK_RCVD) {
			if (!nagios_flag && !json_flag) {
				fprintf(stdout, "DHCP nack received\t - ");
				fprintf(stdout, "Client MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", \
					dhmac[0], dhmac[1], dhmac[2], dhmac[3], dhmac[4], dhmac[5]); 
			} else if(json_flag) {
				if(!json_first) {
					fprintf(stdout, ",");
				} else {
					json_first = 0;
				}

				fprintf(stdout, "{\"msg\":\"DHCP nack received - %s\","
                                                "\"result\":\"info\","
                                                "\"result-type\":\"NACK\","
                                                "\"result-value\":\"%02x:%02x:%02x:%02x:%02x:%02x\""
						"}",
						dhmac[0], dhmac[1], dhmac[2], dhmac[3], dhmac[4], dhmac[5]); 
			}
		}
	}
	/* If IP listen flag is enabled, Listen on obtained for ARP, ICMP protocols  */
	if(!nagios_flag && ip_listen_flag) {
		if(!json_flag) {
			fprintf(stdout, "\nListening on %s for ARP and ICMP protocols\n", iface_name);
			fprintf(stdout, "IP address: %s, Listen timeout: %d seconds\n", get_ip_str(htonl(ip_address)), listen_timeout);
		} else {
			if(!json_first) {
				fprintf(stdout, ",");
			} else {
				json_first = 0;
			}

			fprintf(stdout, "{\"msg\":\"Listening on %s for ARP and ICMP protocols."
					"IP address: %s, Listen timeout: %d seconds\","
					"\"result\":\"info\","
					"\"result-type\":\"listen\","
					"\"result-ip\":\"%s\","
					"\"result-timeout\":\"%d\""
					"}",
					iface_name, get_ip_str(htonl(ip_address)), listen_timeout,
					get_ip_str(htonl(ip_address)), listen_timeout);
		}

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

		if(!json_flag) {
			fprintf(stdout, "Listen timout reached\n");
		} else {
			if(!json_first) {
				fprintf(stdout, ",");
			} else {
				json_first = 0;
			}

			fprintf(stdout, "{\"msg\":\"Listen timout reached.\","
					"\"result\":\"error\","
					"\"error-type\":\"timeout\","
					"\"error-subtype\":\"listen\""
					"\"error-msg\":\"Listen timout reached.\"}");
		}
	}
	/* Clear the promiscuous mode */
	clear_promisc();
	/* Close the socket */
	close_socket();

	if(json_flag) {
		fprintf(stdout, "]");
	}

	return 0;
}
