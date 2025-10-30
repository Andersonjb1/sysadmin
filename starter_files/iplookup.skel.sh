#!/bin/bash
########################################################################
#	iplookup.skel.sh
#	  Author:	      
#	  Date:		      2021-08-06
# 	Last revised:	2024-05-05
#	  Description:	Improved IP lookup script
#		- Removes repetitive lookups to ipinfo.io
#		- Uses regex and awk to filter out hits <100, instead of doing 
#     a sequential check (if/else)
#		- Keeps found IP information in memory, instead of writing 
#     temp files
#		- Outputs info on demand, instead of making the user sit through
#     it all
#		- Improved regex for matching valid IP addresses
#   - NEW: option to add CIDR blocks instead of IPs
#   - NEW: option to reset the firewall
#
#	  NOTE: Only works with /var/log/auth.log
########################################################################

############### ERROR CHECKING ######################
#have to sudo to access log files


#check for proper usage (correct # of arguments - 0)


#check that input file exists


############# DONE ERROR CHECKING ##################
#colors
RESET="\e[0m"   #for color text output


#IP patterns
QUAD=""
IP=""

#misc variables
i=0   #counter for attempts
uniqIps=0 #counter for unique IP addresses

printf "Working... "

#scrape IPs from input file, sort, get unique
#(with counts), trim off anything with <100
#hits, sort by # of hits. in /var/log/auth.log, 
#the IP address is recorded three times for each offense.
#filtering on "rhost=$IP" trims off the other two entries
# ** develop pipeline from the command prompt! **
regs=$()

echo "Done!"
sleep 1s
echo

############  FUNCTIONS  ############
#display menu
function show_menu () {
  # Show Menu function
  return 0
}

#pause output
function pause () {
  # Pause function
  return 0
}

#before adding a CIDR block, it'd be nice
#to make sure that an IP address within 
#that block isn't already in UFW and 
#delete it, if so
function delete_ip () {
  echo "Delete singleton IP from UFW"

  #find the UFW rule # associated with the IP
  #address
  rule_no=$()

  #if there is a rule associated with the provided
  #IP address, delete it 
  if [[ $rule_no ]]
  then
    
    return 0   #return success
  fi

  return 1  #return fail
}

#display the unique IP addresses on demand
function display_unique_ips () {
  echo "Display IPs and counts"
  
  return 0
}

#print detailed info on the offenders
function print_info () {
  echo "Print detailed information about IP address"

  return 0
}

#add the IPs to the firewall. if 'y', have to check
#and make sure that the IP isn't already in the firewall
function add_ips_to_ufw () {
  echo "Add singleton IP addresses to UFW"
  
  return 0
  pause
}

#modify the offenders to the CIDR notation for each
#e.g., 192.168.1.0/24. Strips the last octet of
#each offender's IP address and adds "0/24". this
#will block up to 256 addresses within the range 
#(often attacks come in from multiple hosts
#within a given range)
function bracket_ips () {
  echo "Modify IPs to CIDR (x.x.x.0/24)"
  echo "Delete IP from UFW"
  echo "Insert CIDR to UFW"

  pause
  return 0
}

#show all firewall rules (run thru less)
function show_firewall () {
  echo "List UFW rules"
}

#if the firewall becomes too conjested,
#reset it to allow only ssh, http, and 
#https. Then, current offenders can be added
function reset_firewall () {
  echo "Reset firewall"  

  pause
  return 0
}

#################################
############  START  ############
#################################

#add variables to store current state of UFW
#and hold first three octets of each
ufwstatus=$()
currentIps=$()
  
#count both total attempts and uniq IP addresses
while read num ip
do
  (( i += num ))
  (( uniqIps++ ))
done <<< $regs

#display totals
# Display count totals
pause 

# main loop
# while true; do
#  
# done

echo
echo "Done! Bye now"
echo

exit 0
