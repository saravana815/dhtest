
  dhtest readme
  *************
 
  About the tool
  --------------
  dhtest - linux dhcp client simulation tool. It can simulate hundreds of dhcp
  client from a linux machine. Linux root login is needed because the tool requires 
  layer2 raw socket for sending and receiving dhcp packets.
  
  Installation
  ------------

    * Download the latest source from github as zip. 
      Download link - https://github.com/saravana815/dhtest/archive/master.zip

        [sargandh@CentOS Desktop]$ unzip dhtest-master.zip 
        [sargandh@CentOS Desktop]$ cd dhtest-master
        [sargandh@CentOS dhtest-master]$ make
        gcc    -c -o dhtest.o dhtest.c
        gcc    -c -o functions.o functions.c
        gcc dhtest.o functions.o -o dhtest
        [sargandh@CentOS dhtest-master]$ ls -lh dhtest
        -rwxrwxr-x 1 sargandh sargandh 38K Mar 13 10:47 dhtest

  dhtest 1.5 - new 1.5 features supported
  -----------------------------------------
  
    * Add option to send DHCP DECLINE packets ('-D' flag)
    * Fix potential Segmentation Fault in get_dhinfo() function
    * Added dhcp option55 requested parameter list


  dhtest 1.4 - till 1.4 features supported
  -----------------------------------------
  
    * IP obtaining through DHCP
    * Release obtained IP with -r flag
    * VLAN
    * Broadcast flag support
    * DHCP option 50 - Requested IP
    * DHCP option 60 - Vendor Class Identifier
    * Binding obtained IP for a default timeout of 3600 seconds
    * Support of bind timeout with -k flag on command line
    * Added DHCP option 51 - Requested lease time from server
    * Added DHCP option 12 - Hostname
    * Added DHCP option 81 - Fqdn
    * Option to send in unicast mode.
    * Option to output for nagios.
    * Option to change port, patch by Alan Dekok.
    * Custom option support - Allows packing of any dhcp option in number/string/hex format

  License
  ---------
  Please see the LICENSE file.

  Tool usage examples
  -------------------
    * https://sargandh.wordpress.com/2012/02/23/linux-dhcp-client-simulation-tool/

    * custom option examples
        dhcp option 82 
        --------------
          [root@CentOS dhtest-1.1]# ./dhtest -m 00:00:00:11:11:11 
          -c 82,hex,0108476967302f312f30021130303a30303a30303a31313a31313a3131
                     | ||              |
                     | ||              |Subopt value - 'Gig0/1/0' 
                     | | **************        
                     | Subopt len 8
                   Opt82 subopt 1
                   Circuit id 

          [root@CentOS dhtest-1.1]# ./dhtest -m 00:00:00:11:11:11 
          -c 82,hex,0108476967302f312f30021130303a30303a30303a31313a31313a3131
                                         | ||              |
                                         | ||              |Subopt value - '00:00:00:11:11:11' 
                                         | | **************        
                                         | Subopt len 17
                                       Opt82 subopt 2
                                       Remote id 

        dhcp option 60 and 82 (multiple custom options) 
        -----------------------------------------------
          [root@CentOS dhtest-1.1]# ./dhtest -m 00:00:00:11:11:11 -c 60,str,"MSFT 5.0" 
          -c 82,hex,0108476967302f312f30021130303a30303a30303a31313a31313a3131 


     * dhcp option55 requested parameter list example


        root@ubuntu-16:~/dhtest# ./dhtest -m 00:00:00:11:11:11 -i enp0s3 -l 011C030F060A0B
        DHCP discover sent       - Client MAC : 00:00:00:11:11:11
        DHCP offer received      - Offered IP : 10.0.2.16
        DHCP request sent        - Client MAC : 00:00:00:11:11:11
        DHCP ack received        - Acquired IP: 10.0.2.16
        root@ubuntu-16:~/dhtest# 
     
        Tshark output     
        -------------
          Option: (55) Parameter Request List
              Length: 7
              Parameter Request List Item: (1) Subnet Mask
              Parameter Request List Item: (28) Broadcast Address
              Parameter Request List Item: (3) Router
              Parameter Request List Item: (15) Domain Name
              Parameter Request List Item: (6) Domain Name Server
              Parameter Request List Item: (10) Impress Server
              Parameter Request List Item: (11) Resource Location Server
