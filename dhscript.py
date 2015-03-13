#!/usr/bin/env python

import commands

#reset script log file
with open('dhscript_log.txt', 'w') as f:
    f.write('')
    f.close

#print_log(- prints the output to both stdout and file
def print_log(msg, cmd=None):
    if cmd != None:
        print msg, cmd
        msg_full = msg + cmd + "\n"
    else:
        print msg
        msg_full = msg + "\n"

    with open('dhscript_log.txt', 'a') as f:
        f.write(msg_full)
        f.close

#write_log - write the output to file
def write_log(msg):
    with open('dhscript_log.txt', 'a') as f:
        msg_full = msg + "\n"
        f.write(msg_full)
        f.close

def run_dhtest(mac, arg_list, search_output):
    cmd = "./dhtest -m " + mac + arg_list
    print_log("=============================================================")
    print_log("Running command ", cmd)
    out = commands.getoutput(cmd)
    write_log(out)
    if out.find(search_output) != -1:
        print_log("PASS: command ", cmd)
    else:
        print_log("FAIL: command ", cmd)
    print_log("============================================================")


# OPTION LIST
# ============
#  -r, --release                         # Releases obtained DHCP IP for corresponding MAC
#  -L, --option51-lease_time [ Lease_time ] # Option 51. Requested lease time in secondes
#  -I, --option50-ip     [ IP_address ]  # Option 50 IP address on DHCP discover
#  -o, --option60-vci    [ VCI_string ]  # Vendor Class Idendifier string
#  -h, --option12-hostname [ hostname_string ] # Client hostname string
#  -v, --vlan            [ vlan_id ]     # VLAN ID. Range(1 - 4094)
#  -t, --tos             [ TOS_value ]   # IP header TOS value
#  -i, --interface       [ interface ]   # Interface to use. Default eth0
#  -T, --timeout         [ cmd_timeout ] # Command returns within specified timout in seconds
#  -b, --bind-ip                         # Listens on the obtained IP. Supported protocols - ARP and ICMP
#  -k, --bind-timeout    [ timeout ]     # Listen timout in seconds. Default 3600 seconds
#  -f, --bcast_flag                      # Sets broadcast flag on DHCP discover and request
#  -d, --fqdn-domain-name   [ fqdn ]     # FQDN domain name to use
#  -n, --fqdn-server-not-update          # Sets FQDN server not update flag
#  -s, --fqdn-server-update-a            # Sets FQDN server update flag
#  -p, --padding                         # Add padding to packet to be at least 300 bytes
#  -P, --port            [ port ]        # Use port instead of 67
#  -g, --giaddr          [ giaddr ]      # Use giaddr instead of 0.0.0.0
#  -u, --unicast         [ ip ]          # Unicast request, IP is optional. If not specified, the interface address will be used. 
#  -a, --nagios                          # Nagios output format. 
#  -S, --server          [ address ]     # Use server address instead of 255.255.255.255
#  -V, --verbose                         # Prints DHCP offer and ack details

mac = "00:00:00:11:11:11"
run_dhtest(mac, '',  "DHCP ack received")
run_dhtest(mac, ' -V',  "DHCP ack received")
run_dhtest(mac, ' -r',  "DHCP release sent")
run_dhtest(mac, ' -L 1200', "DHCP ack received")
run_dhtest(mac, ' -I 10.0.2.16', "DHCP ack received")
run_dhtest(mac, ' -o MSFT 5.0', "DHCP ack received")
run_dhtest(mac, ' -h client_hostname', "DHCP ack received")
run_dhtest(mac, ' -t 10', "DHCP ack received")
run_dhtest(mac, ' -i eth0', "DHCP ack received")
run_dhtest(mac, ' -T 60', "DHCP ack received")
run_dhtest(mac, ' -b -k 10', "DHCP ack received")
run_dhtest(mac, ' -r', "DHCP release sent")
run_dhtest(mac, ' -f ', "DHCP ack received")
run_dhtest(mac, ' -d client.test.com ', "DHCP ack received")
run_dhtest(mac, ' -n', "DHCP ack received")
run_dhtest(mac, ' -s', "DHCP ack received")
run_dhtest(mac, ' -p', "DHCP ack received")
run_dhtest(mac, ' -g 10.0.2.1', "DHCP ack received")
run_dhtest(mac, ' -a', "Acquired IP")
run_dhtest(mac, ' -S 10.0.2.2 ', "DHCP ack received")
run_dhtest(mac, ' -c 60,str,"MSFT 5.0" -c 82,hex,0108476967302f312f30021130303a30303a30303a31313a31313a3131 ', "DHCP ack received")

