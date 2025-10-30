#!/bin/bash
########################################################################
#	iplookup.sh
#	  Author:	      Blaine Anderson
#	  Date:		      2025-10-06
# 	Last revised:	2025-10-29
#	  Description:	
#       - Updated to meet the requirements for MS1 (2025-10-18)
#         - Error Checking
#         - Initial Processing
#       - Added updates to meet the requirements for MS2 (2025-10-22)
#         - show_menu()
#         - pause()
#         - main loop with case statements
#	      - Implemented requirements for MS3 (2025-10-29)
#	        - display_unique_ips()
#           - to get the colors to work in awk I had to use \033 instead of \e
#         - print_info()
#           - Displays heading, IP address, detailed info, # of attempts,
#               and allows the user to quit
#
#
########################################################################

#colors
RESET="\033[0m"
CYAN="\033[36m"
MAGENTA="\033[31m"
YELLOW="\033[38;5;228m"
PURPLE="\033[38;5;141m"
RED="\033[38;5;196m"
GREEN="\033[38;5;43m"
BLUE="\033[38;5;26m"
LTPURP="\033[38;5;219m"
ORANGE="\033[38;5;216m"

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

clear
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

echo -e $LTPURP"\n\nThere were "$i" attempts\nFrom "$uniqIps" unique IP addresses"$RESET

sleep 1s
echo

############  FUNCTIONS  ############
#display menu
function show_menu () {
  echo -e $CYAN"============================================"
  echo -e "=================== Menu ==================="
  echo -e "============================================"
  echo -e $RESET" ┌────────────────────────────────────────┐"
  echo -e " │${YELLOW}  1.${RESET} Get unique IP addresses            │"
  echo -e " │${YELLOW}  2.${RESET} Show detailed information          │"
  echo -e " │${YELLOW}  3.${RESET} Add new offenders to UFW           │"
  echo -e " │${YELLOW}  4.${RESET} Bracket IP subnet/add to UFW       │"
  echo -e " │${YELLOW}  5.${RESET} Show firewall rules ('q' to quit)  │"
  echo -e " │${YELLOW}  6.${RESET} Reset the firewall                 │"
  echo -e " │${YELLOW}  7.${RESET} Quit                               │"
  echo -e " └────────────────────────────────────────┘"
  echo -e $CYAN"============================================"
  echo -e $RESET
  return 0
}

#pause output
function pause () {
  echo -e $RED"\n...Press Enter to continue..."
  read -r -n1 < /dev/tty 
  echo -e $RESET
  clear
  return 0
}

#before adding a CIDR block, it'd be nice
#to make sure that an IP address within 
#that block isn't already in UFW and 
#delete it, if so
function delete_ip () {
  clear
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
    
  clear

  # awk is saying if the line number is even use GREEN otherwise use LTPURP
  #   and reset at the end. 
  # $2 - the ips from regs
  # $1 - the number of attemps from regs
  uniq_ips=$(echo "$regs" | awk -v c1="$GREEN" -v c2="$LTPURP" -v reset="$RESET" '
        NR % 2 {color=c1}
        !(NR % 2) {color=c2}
        {printf "%s%s%s\n", color,"> " $2 " (" $1 " attempts)", reset}')
 
  echo -e $RED"Naughty IP addresses:"
  echo -e "====================================="$RESET
  echo -e "$uniq_ips" 
  echo -e $RED"====================================="$RESET
  
  return 0
}

#print detailed info on the offenders
function print_info () {
  clear

  TOKEN="ed89a5347cc7cc"

  # Added this counter for fun
  # Thought it might be good to see where you are in the list of IPs
  TOTAL_IPS=$(echo "$regs" | wc -l)
  CURRENT_IP=1

  # Loops through all ips using regs, fetches ip info data,
  #   then prints everything out to the terminal one ip at a time
  while read -r ip attempts; do

    # Display counter
    echo -e $PURPLE"[$CURRENT_IP | $TOTAL_IPS]"$RESET


    echo -e "${RED}IP Information for $ip${RESET}"
    
    # Fetch IP info
    info=$(curl -s "https://ipinfo.io/$ip?token=$TOKEN")

    # Print out the info
    echo -e "\n" $BLUE"$info"$RESET $RED"($attempts attempts)"$RESET

    # Didn't use pause() here in order to implement the ability to quit
    echo -e $YELLOW
    read -r -n1 -p $'\n> Press any key to continue (q to quit): ' key < /dev/tty
    echo -e $RESET
    clear

    #------------V---V (took this from your hint in class)
    if [[ "$key" =~ [qQ] ]]; then
      break 
      clear
    fi

    # Increment the IP counter
    ((CURRENT_IP++))

  done < <(
    echo "$regs" | awk '{print $2, $1}'
  )

  clear

  return 0
}

#add the IPs to the firewall. if 'y', have to check
#and make sure that the IP isn't already in the firewall
function add_ips_to_ufw () {
  clear
  echo "Add singleton IP addresses to UFW"
  
  return 0
}

#modify the offenders to the CIDR notation for each
#e.g., 192.168.1.0/24. Strips the last octet of
#each offender's IP address and adds "0/24". this
#will block up to 256 addresses within the range 
#(often attacks come in from multiple hosts
#within a given range)
function bracket_ips () {
  clear
  echo "Modify IPs to CIDR (x.x.x.0/24)"
  echo "Delete IP from UFW"
  echo "Insert CIDR to UFW"

  return 0
}

#show all firewall rules (run thru less)
function show_firewall () {
  clear
  echo "List UFW rules"
}

#if the firewall becomes too conjested,
#reset it to allow only ssh, http, and 
#https. Then, current offenders can be added
function reset_firewall () {
  clear
  echo "Reset firewall"  

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
while [[ $finished -eq 0 ]]; do
  show_menu
  echo -e $CYAN"Choose an option [1-7]: "
  read -n1 choice
  echo -e $RESET
  case "$choice" in
    1)
      display_unique_ips
      pause
      ;;
    2)
      print_info
      ;;
    3)
      add_ips_to_ufw
      pause
      ;;
    4)
      bracket_ips
      pause
      ;;
    5)
      show_firewall
      pause
      ;;
    6)
      reset_firewall
      pause
      ;;
    7)
      clear
      echo -e $GREEN"Exiting..."$RESET
      finished=1
      ;;
    *)
      clear
      echo -e $RED"Invalid selection. Please choose 1-7."$RESET
      ;;
  esac
done

echo -e "\nDone! Bye now\n"

exit 0
