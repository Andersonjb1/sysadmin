#!/bin/bash
########################################################################
#	iplookup.sh
#	  Author:	      Blaine Anderson
#	  Date:		      2025-10-06
# 	Last revised:	2025-10-18
#	  Description:	
#       - Updated to meet the requirements for MS1
#         - Error Checking
#         - Initial Processing
########################################################################

#colors
RESET="\e[0m"
CYAN="\e[36m"
MAGENTA="\e[31m"
YELLOW="\e[38;5;228m"
PURPLE="\e[38;5;141m"
RED="\e[38;5;196m"
GREEN="\e[38;5;43m"
BLUE="\e[38;5;26m"
LTPURP="\e[38;5;219m"
ORANGE="\e[38;5;216m"

############### ERROR CHECKING ######################
#have to sudo to access log files
if [[ $EUID -ne 0 ]]; then
  echo -e $RED"You are using a non-privileged account!"$RESET >&2
  exit 1
fi

#check for proper usage (require exactly one argument)
if [[ $# -ne 1 ]]; then
  echo -e $RED"Proper usage: sudo ./iplookup.sh [path-to-file]"$RESET >&2
  exit 2
fi

#check that input file exists and is readable
INPUT_FILE="$1"

if [[ ! -e "$INPUT_FILE" ]]; then
  echo -e $RED"Input file '$INPUT_FILE' does not exist."$RESET >&2
  exit 3
fi

############# DONE ERROR CHECKING ##################


#IP patterns
QUAD="(25[0-5])|(2[0-4][0-9])|(1[0-9]{2})|([1-9]?[0-9])"
IP="\b($QUAD)\.($QUAD)\.($QUAD)\.($QUAD)\b"

printf "Working... "

#scrape IPs from input file, sort, get unique
#(with counts), trim off anything with <100
#hits, sort by # of hits. in /var/log/auth.log, 
#the IP address is recorded three times for each offense.
#filtering on "rhost=$IP" trims off the other two entries
# ** develop pipeline from the command prompt! **
regs=$(grep -oP "rhost=\K$IP" "$INPUT_FILE" | sort -g | uniq -c | awk '$1 >= 100' | sort -nr)

#misc variables
i=$(echo "$regs" | awk '{sum += $1} END {print sum+0}')   #counter for attempts
uniqIps=$(echo "$regs" | sort -u | wc -l) #counter for unique IP addresses

echo -e $LTPURP"\n\nThere were "$i" attempts\nFrom "$uniqIps" unique IP addresses\n"$RESET

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
