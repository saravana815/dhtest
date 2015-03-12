/*
 *  File -  dhcp-headers.h
 *  dhcp-headers.h - header structure for dhcp packets
 */

#ifndef HEADERS_H
#include<sys/types.h>
#include<netinet/in.h>
#define HEADERS_H

/*
 *  Functions used in functions.c
 */

int open_socket();		/* Opens PF_PACKET socket*/
int close_socket();		/* Close PF_PACKET socket */
int set_promisc();
int clear_promisc();
int send_packet(int pkt_type);	/* Sends DHCP packet socket*/
int recv_packet(int pkt_type);	/* Receives DHCP packet on socket*/

int reset_dhopt_size();		/* Resets the dhopt_size to zero */
int set_rand_dhcp_xid();	/* Sets a random DHCP xid */
int build_option53(int msg_type);	/* Option53: MSGTYPE. Builds option53*/
int build_option55();		/* Requested parameters list */
int build_option54();		/* Builds server identifier on DHCP request */
int build_option50();		/* Option50: Rqstd IP. Builds option50*/
int build_option51();		/* Option51: Rqstd lease time. Builds option51*/
int build_option60_vci();	/* Vendor class identifier */
int build_option12_hostname(); /* Hostname */
int build_option81_fqdn(); /* FQDN */
int build_custom_dhcp_options(); /* Custom DHCP options */
int build_optioneof();		/* End of option */

int build_dhpacket(int pkt_type);	/* Build DHCP disc, req packets  */
int build_packet(int pkt_type); /* Builds ARP and ICMP reply packets */
int print_buff(u_int8_t *buff, int size);/* Debug routine */
int print_dhoption(u_int8_t *buff, int size); /* Print dhcp option */
int map_all_layer_ptr(int pkt_type);	/* maps all layer pointer on DHCP packet */
int check_packet(int pkt_type);	/* Checks the packet for DHCP offer & ack */
int print_dhinfo(int pkt_type);	/* Prints DHCP offer & ack informations */
int log_dhinfo();		/* Logs DHCP IP info to log file */
int get_dhinfo();		/* Reads log file for mac, ip, serv_ip info */
char *get_ip_str(u_int32_t ip);  /* Convert in_addr to string */
u_int32_t get_interface_address(); /* Return the IP address of the interface. */

int set_serv_id_opt50();	/* Sets the server_ip and option50 ip */
/*
 * Libnet defines header sizes for every builder function exported.
 */

#define ETHER_H		0x10	/* Ethernet header: 14 bytes */
#define ETHER_ADDR_LEN  0x6	/* Ethernet address len: 6 bytes */	
#define IP_ADDR_LEN	0x4
#define VLAN_H		0x12	/* Ethernet header + vlan header*/	
#define IP_H		0x20	/* IP header: 20 bytes */	
#define UDP_H		0x8	/* UDP header: 8 bytes */		
#define ICMP_H		0x8
#define ICMP_PAYLOAD	0x3c	/* 60 bytes of ICMP payload */
#define DHCPV4_H	0xf0    /**< DHCP v4 header:     240 bytes */
#define ARP_H_LEN	0x08


/*
 *  ARP header
 *  Address Resolution Protocol
 *  Base header size: 8 bytes
 */
struct arp_hdr
{
	u_int16_t ar_hrd;         /* format of hardware address */
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
	u_int16_t ar_pro;         /* format of protocol address */
	u_int8_t  ar_hln;         /* length of hardware address */
	u_int8_t  ar_pln;         /* length of protocol addres */
	u_int16_t ar_op;          /* operation type */
#define ARPOP_REQUEST    1  /* req to resolve address */
#define ARPOP_REPLY      2  /* resp to previous request */
#define ARPOP_REVREQUEST 3  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8  /* req to identify peer */
#define ARPOP_INVREPLY   9  /* resp identifying peer */
	u_int8_t sender_mac[ETHER_ADDR_LEN];
	u_int8_t sender_ip[IP_ADDR_LEN];
	u_int8_t target_mac[ETHER_ADDR_LEN];
	u_int8_t target_ip[IP_ADDR_LEN];
};

/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */
struct ethernet_hdr
{
	u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
	u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
	u_int16_t ether_type;                 /* protocol */
};

/**
 * IEEE 802.1Q (Virtual Local Area Network) VLAN header, static header 
 * size: 18 bytes
 */
struct vlan_hdr
{
	u_int8_t vlan_dhost[ETHER_ADDR_LEN];  /**< destination ethernet address */
	u_int8_t vlan_shost[ETHER_ADDR_LEN];  /**< source ethernet address */
	u_int16_t vlan_tpi;                   /**< tag protocol ID */
	u_int16_t vlan_priority_c_vid;        /**< priority | VLAN ID */
#define VLAN_PRIMASK   0x0007    /**< priority mask */
#define VLAN_CFIMASK   0x0001    /**< CFI mask */
#define VLAN_VIDMASK   0x0fff    /**< vid mask */
	u_int16_t vlan_len;                   /**< length or type (802.3 / Eth 2) */
};  

/*
 * IP header included from netinet/ip.h
 */
#include<netinet/ip.h>

/*
 *  ICMP header
 *  Internet Control Message Protocol
 *  Base header size: 4 bytes
 */
struct icmp_hdr
{
	u_int8_t icmp_type;       			/* ICMP type */
#define     ICMP_ECHOREPLY                  0
#define     ICMP_ECHO                       8
	u_int8_t icmp_code;       			/* ICMP code */
	u_int16_t icmp_sum;   			/* ICMP Checksum */
	u_int16_t id; 				/* ICMP id */
	u_int16_t seq;				/* ICMP sequence number */
};

/*
 * UDP header included from netinet/udp.h
 */
#include<netinet/udp.h>


/*
 *  DHCP header
 *  Dynamic Host Configuration Protocol
 *  Static header size: f0 bytes
 */
struct dhcpv4_hdr
{
	u_int8_t dhcp_opcode;     /* opcode */
#define DHCP_REQUEST 0x1
#define DHCP_REPLY   0x2
	u_int8_t dhcp_htype;      /* hardware address type */
	u_int8_t dhcp_hlen;       /* hardware address length */
	u_int8_t dhcp_hopcount;   /* used by proxy servers */
	u_int32_t dhcp_xid;        /* transaction ID */
	u_int16_t dhcp_secs;      /* number of seconds since trying to bootstrap */
	u_int16_t dhcp_flags;     /* flags for DHCP, unused for BOOTP */
	u_int32_t dhcp_cip;        /* client's IP */
	u_int32_t dhcp_yip;        /* your IP */
	u_int32_t dhcp_sip;        /* server's IP */
	u_int32_t dhcp_gip;        /* gateway IP */
	u_int8_t dhcp_chaddr[16]; /* client hardware address */
	u_int8_t dhcp_sname[64];  /* server host name */
	u_int8_t dhcp_file[128];  /* boot file name */
	u_int32_t dhcp_magic;      /* BOOTP magic header */
#define DHCP_MAGIC                  0x63825363
#define BOOTP_MIN_LEN        0x12c
#define DHCP_PAD             0x00
#define DHCP_SUBNETMASK      0x01
#define DHCP_TIMEOFFSET      0x02
#define DHCP_ROUTER          0x03
#define DHCP_TIMESERVER      0x04
#define DHCP_NAMESERVER      0x05
#define DHCP_DNS             0x06
#define DHCP_LOGSERV         0x07
#define DHCP_COOKIESERV      0x08
#define DHCP_LPRSERV         0x09
#define DHCP_IMPSERV         0x0a
#define DHCP_RESSERV         0x0b
#define DHCP_HOSTNAME        0x0c
#define DHCP_BOOTFILESIZE    0x0d
#define DHCP_DUMPFILE        0x0e
#define DHCP_DOMAINNAME      0x0f
#define DHCP_SWAPSERV        0x10
#define DHCP_ROOTPATH        0x11
#define DHCP_EXTENPATH       0x12
#define DHCP_IPFORWARD       0x13
#define DHCP_SRCROUTE        0x14
#define DHCP_POLICYFILTER    0x15
#define DHCP_MAXASMSIZE      0x16
#define DHCP_IPTTL           0x17
#define DHCP_MTUTIMEOUT      0x18
#define DHCP_MTUTABLE        0x19
#define DHCP_MTUSIZE         0x1a
#define DHCP_LOCALSUBNETS    0x1b
#define DHCP_BROADCASTADDR   0x1c
#define DHCP_DOMASKDISCOV    0x1d
#define DHCP_MASKSUPPLY      0x1e
#define DHCP_DOROUTEDISC     0x1f
#define DHCP_ROUTERSOLICIT   0x20
#define DHCP_STATICROUTE     0x21
#define DHCP_TRAILERENCAP    0x22
#define DHCP_ARPTIMEOUT      0x23
#define DHCP_ETHERENCAP      0x24
#define DHCP_TCPTTL          0x25
#define DHCP_TCPKEEPALIVE    0x26
#define DHCP_TCPALIVEGARBAGE 0x27
#define DHCP_NISDOMAIN       0x28
#define DHCP_NISSERVERS      0x29
#define DHCP_NISTIMESERV     0x2a
#define DHCP_VENDSPECIFIC    0x2b
#define DHCP_NBNS            0x2c
#define DHCP_NBDD            0x2d
#define DHCP_NBTCPIP         0x2e
#define DHCP_NBTCPSCOPE      0x2f
#define DHCP_XFONT           0x30
#define DHCP_XDISPLAYMGR     0x31
#define DHCP_REQUESTEDIP     0x32
#define DHCP_LEASETIME       0x33
#define DHCP_OPTIONOVERLOAD  0x34
#define DHCP_MESSAGETYPE     0x35
#define DHCP_SERVIDENT       0x36
#define DHCP_PARAMREQUEST    0x37
#define DHCP_MESSAGE         0x38
#define DHCP_MAXMSGSIZE      0x39
#define DHCP_RENEWTIME       0x3a
#define DHCP_REBINDTIME      0x3b
#define DHCP_CLASSSID        0x3c
#define DHCP_CLIENTID        0x3d
#define DHCP_NISPLUSDOMAIN   0x40
#define DHCP_NISPLUSSERVERS  0x41
#define DHCP_MOBILEIPAGENT   0x44
#define DHCP_SMTPSERVER      0x45
#define DHCP_POP3SERVER      0x46
#define DHCP_NNTPSERVER      0x47
#define DHCP_WWWSERVER       0x48
#define DHCP_FINGERSERVER    0x49
#define DHCP_IRCSERVER       0x4a
#define DHCP_STSERVER        0x4b
#define DHCP_STDASERVER      0x4c
#define DHCP_FQDN            0x51
#define DHCP_END             0xff

#define DHCP_MSGDISCOVER     0x01
#define DHCP_MSGOFFER        0x02
#define DHCP_MSGREQUEST      0x03
#define DHCP_MSGDECLINE      0x04
#define DHCP_MSGACK          0x05
#define DHCP_MSGNACK         0x06
#define DHCP_MSGRELEASE      0x07
#define DHCP_MSGINFORM       0x08
};



/*
 *  Custom DHCP option struct
 */
struct custom_dhcp_option_hdr
{
	u_int8_t option_no;     
	u_int8_t option_type;  
	u_int8_t option_len;  
#define CUST_DHCP_OPTION_STRING    0
#define CUST_DHCP_OPTION_NUMBER    1
#define CUST_DHCP_OPTION_HEX       2
#define CUST_DHCP_OPTION_IP        3
        u_char option_value[256];
        u_int32_t option_value_num;
        u_int32_t option_value_ip;
};

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#endif
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN          0x8100  /* IEEE 802.1Q VLAN tagging */
#endif
#define ETHERTYPE_ARP		0x806

#define SOCKET_ERR 		-1
#define PACK_SEND_ERR 		-1
#define PACK_RECV_ERR 		-2

#define DHCP_OFFR_RCVD 		1
#define DHCP_DISC_RESEND 	2
#define UNKNOWN_PACKET 		3
#define DHCP_ACK_RCVD 		4
#define DHCP_REQ_RESEND 	5
#define DHCP_NAK_RCVD 		6
#define ERR_FILE_OPEN		7
#define ARP_ICMP_RCV		8
#define ARP_RCVD		9
#define ARP_MAP			10
#define ICMP_MAP		11
#define ICMP_RCVD		12
#define ARP_SEND		13
#define ICMP_SEND		14
#define LISTEN_TIMOUET	 	15


/*
 * FQDN options flags
 */
#define FQDN_N_FLAG   0x08
#define FQDN_E_FLAG   0x04
#define FQDN_O_FLAG   0x02
#define FQDN_S_FLAG   0x01a

/*
 * Minimum DHCP packet size
 */
#define MINIMUM_PACKET_SIZE 300

#endif  /* __HEADERS_H */

/* EOF */
