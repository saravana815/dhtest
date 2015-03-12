DHTEST README
-------------

1. Run 'make' command on shell to complile and build dhtest.

2. Run 'make clean' to remove dhtest

dhtest version 1.0 supports the following
-----------------------------------------

1. IP obtaining through DHCP

2. Release obtained IP with -r flag

3. VLAN

4. Broadcast flag support

5. DHCP option 50 - Requested IP

6. DHCP option 60 - Vendor Class Identifier

 
dhtest version 1.1 supports the following
-----------------------------------------

1. Binding obtained IP for a default timeout of 3600 seconds

2. Support of bind timout with -k flag on command line

3. Added DHCP option 51 - Requested lease time from server

dhtest version 1.2 supports the following
-----------------------------------------

1. Added DHCP option 12 - Hostname

2. Added DHCP option 81 - Fqdn

dhtest version 1.3 supports the following
----------------------------------------

1. Option to send in unicast mode.

2. Option to output for nagios.

3. Option to change port, patch by Alan Dekok.

Authour: Saravanakumar.G
Send your comments, enhancements and bugs to saravana815@gmail.com

custom option examples
----------------------

option 82

[root@CentOS dhtest-1.1]# ./dhtest -m 00:00:00:11:11:11 -c
82,hex,0108476967302f312f30021130303a30303a30303a31313a31313a3131 -V
DHCP discover sent       - Client MAC : 00:00:00:11:11:11
DHCP offer received      - Offered IP : 10.0.2.16

DHCP offer details
----------------------------------------------------------
DHCP offered IP from server - 10.0.2.16
Next server IP(Probably TFTP server) - 10.0.2.4
Option no - 53, option length - 1
  OPTION data (HEX)
    02 
  OPTION data (ASCII)
    
Subnet mask - 255.255.255.0
Router/gateway - 10.0.2.2
DNS server - 72.163.128.140
DNS server - 171.70.168.183
Option no - 15, option length - 9
  OPTION data (HEX)
    63 69 73 63 6F 2E 63 6F 6D 
  OPTION data (ASCII)
    cisco.com
Lease time - 1 Days 0 Hours 0 Minutes
DHCP server  - 10.0.2.2
----------------------------------------------------------

DHCP request sent        - Client MAC : 00:00:00:11:11:11
DHCP ack received        - Acquired IP: 10.0.2.16

DHCP ack details
----------------------------------------------------------
DHCP offered IP from server - 10.0.2.16
Next server IP(Probably TFTP server) - 10.0.2.4
Option no - 53, option length - 1
  OPTION data (HEX)
    05 
  OPTION data (ASCII)
    
Subnet mask - 255.255.255.0
Router/gateway - 10.0.2.2
DNS server - 72.163.128.140
DNS server - 171.70.168.183
Option no - 15, option length - 9
  OPTION data (HEX)
    63 69 73 63 6F 2E 63 6F 6D 
  OPTION data (ASCII)
    cisco.com
Lease time - 1 Days 0 Hours 0 Minutes
DHCP server  - 10.0.2.2
----------------------------------------------------------

option 50 requested ip

[root@CentOS dhtest-1.1]# ./dhtest -m 00:00:00:11:11:11 -c 50,ip,1.2.3.4 -V
DHCP discover sent       - Client MAC : 00:00:00:11:11:11
DHCP offer received      - Offered IP : 10.0.2.16

DHCP offer details
----------------------------------------------------------
DHCP offered IP from server - 10.0.2.16
Next server IP(Probably TFTP server) - 10.0.2.4
Option no - 53, option length - 1
  OPTION data (HEX)
    02 
  OPTION data (ASCII)
    
Subnet mask - 255.255.255.0
Router/gateway - 10.0.2.2
DNS server - 72.163.128.140
DNS server - 171.70.168.183
Option no - 15, option length - 9
  OPTION data (HEX)
    63 69 73 63 6F 2E 63 6F 6D 
  OPTION data (ASCII)
    cisco.com
Lease time - 1 Days 0 Hours 0 Minutes
DHCP server  - 10.0.2.2
----------------------------------------------------------

DHCP request sent        - Client MAC : 00:00:00:11:11:11
DHCP ack received        - Acquired IP: 10.0.2.16

DHCP ack details
----------------------------------------------------------
DHCP offered IP from server - 10.0.2.16
Next server IP(Probably TFTP server) - 10.0.2.4
Option no - 53, option length - 1
  OPTION data (HEX)
    05 
  OPTION data (ASCII)
    
Subnet mask - 255.255.255.0
Router/gateway - 10.0.2.2
DNS server - 72.163.128.140
DNS server - 171.70.168.183
Option no - 15, option length - 9
  OPTION data (HEX)
    63 69 73 63 6F 2E 63 6F 6D 
  OPTION data (ASCII)
    cisco.com
Lease time - 1 Days 0 Hours 0 Minutes
DHCP server  - 10.0.2.2
----------------------------------------------------------

option 60 - VCI

[root@CentOS dhtest-1.1]# ./dhtest -m 00:00:00:11:11:11 -c 60,str,"MSFT 5.0"
-V
DHCP discover sent       - Client MAC : 00:00:00:11:11:11
DHCP offer received      - Offered IP : 10.0.2.16

DHCP offer details
----------------------------------------------------------
DHCP offered IP from server - 10.0.2.16
Next server IP(Probably TFTP server) - 10.0.2.4
Option no - 53, option length - 1
  OPTION data (HEX)
    02 
  OPTION data (ASCII)
    
Subnet mask - 255.255.255.0
Router/gateway - 10.0.2.2
DNS server - 72.163.128.140
DNS server - 171.70.168.183
Option no - 15, option length - 9
  OPTION data (HEX)
    63 69 73 63 6F 2E 63 6F 6D 
  OPTION data (ASCII)
    cisco.com
Lease time - 1 Days 0 Hours 0 Minutes
DHCP server  - 10.0.2.2
----------------------------------------------------------

DHCP request sent        - Client MAC : 00:00:00:11:11:11
DHCP ack received        - Acquired IP: 10.0.2.16

DHCP ack details
----------------------------------------------------------
DHCP offered IP from server - 10.0.2.16
Next server IP(Probably TFTP server) - 10.0.2.4
Option no - 53, option length - 1
  OPTION data (HEX)
    05 
  OPTION data (ASCII)
    
Subnet mask - 255.255.255.0
Router/gateway - 10.0.2.2
DNS server - 72.163.128.140
DNS server - 171.70.168.183
Option no - 15, option length - 9
  OPTION data (HEX)
    63 69 73 63 6F 2E 63 6F 6D 
  OPTION data (ASCII)
    cisco.com
Lease time - 1 Days 0 Hours 0 Minutes
DHCP server  - 10.0.2.2
----------------------------------------------------------

multiple custom option - option 50, 60 and 82 

[root@CentOS dhtest-1.1]# ./dhtest -m 00:00:00:11:11:11 -c 50,ip,1.2.3.4 -c 60,str,"MSFT 5.0" -c 82,hex,0108476967302f312f30021130303a30303a30303a31313a31313a3131 -V 
DHCP discover sent       - Client MAC : 00:00:00:11:11:11
DHCP offer received      - Offered IP : 10.0.2.16

DHCP offer details
----------------------------------------------------------
DHCP offered IP from server - 10.0.2.16
Next server IP(Probably TFTP server) - 10.0.2.4
Option no - 53, option length - 1
  OPTION data (HEX)
    02 
  OPTION data (ASCII)
    
Subnet mask - 255.255.255.0
Router/gateway - 10.0.2.2
DNS server - 72.163.128.140
DNS server - 171.70.168.183
Option no - 15, option length - 9
  OPTION data (HEX)
    63 69 73 63 6F 2E 63 6F 6D 
  OPTION data (ASCII)
    cisco.com
Lease time - 1 Days 0 Hours 0 Minutes
DHCP server  - 10.0.2.2
----------------------------------------------------------

DHCP request sent        - Client MAC : 00:00:00:11:11:11
DHCP ack received        - Acquired IP: 10.0.2.16

DHCP ack details
----------------------------------------------------------
DHCP offered IP from server - 10.0.2.16
Next server IP(Probably TFTP server) - 10.0.2.4
Option no - 53, option length - 1
  OPTION data (HEX)
    05 
  OPTION data (ASCII)
    
Subnet mask - 255.255.255.0
Router/gateway - 10.0.2.2
DNS server - 72.163.128.140
DNS server - 171.70.168.183
Option no - 15, option length - 9
  OPTION data (HEX)
    63 69 73 63 6F 2E 63 6F 6D 
  OPTION data (ASCII)
    cisco.com
Lease time - 1 Days 0 Hours 0 Minutes
DHCP server  - 10.0.2.2
----------------------------------------------------------

[root@CentOS dhtest-1.1]# ./dhtest -m 00:00:00:11:11:11 -c 50,ip,1.2.3.4 -c 60,str,"MSFT 5.0" -c 82,hex,0108476967302f312f30021130303a30303a30303a31313a31313a3131 
DHCP discover sent       - Client MAC : 00:00:00:11:11:11
DHCP offer received      - Offered IP : 10.0.2.16
DHCP request sent        - Client MAC : 00:00:00:11:11:11
DHCP ack received        - Acquired IP: 10.0.2.16
