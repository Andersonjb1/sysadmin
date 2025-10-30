#!/bin/bash
#########################################
# restores firewall to allow only ssh,
# http, and https through
#########################################

ufw --force disable &> /dev/null
ufw --force reset &> /dev/null

echo " ** UFW reset **" 

ufw allow ssh &> /dev/null
ufw allow http &> /dev/null
ufw allow https &> /dev/null

ufw enable &> /dev/null
echo " ** UFW enabled **" 


find /etc/ufw -name '*.rules.*' -delete &> /dev/null

exit 0
