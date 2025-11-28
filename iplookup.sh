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
#       - Updated for MS4 (2025-11-3)
#           - add_ips_to_ufw()
#             - Check UFW for IPs, Insert IP into UFW, Indicate success,
#               Skip IP if present in CIDR, Indicate failure if IP already present
#           - reset_firewall()
#           - show_firewall()
#       - MS5 (2025-11-28) 
#           - bracket_ips()
#             - Convert IPs to CIDRs, Check UFW for IP (Delete if present),
#               Check for CIDR (Skip if present), Insert CIDR into UFW (if not present)
#
#
#
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
i=$(echo "$regs" | awk '{sum += $1} END {print sum+0}') #counter for attempts
uniqIps=$(echo "$regs" | sort -u | wc -l)               #counter for unique IP addresses

echo -e $LTPURP"\n\nThere were "$i" attempts\nFrom "$uniqIps" unique IP addresses"$RESET

sleep 1s
echo

############  FUNCTIONS  ############
#display menu
function show_menu() {
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
function pause() {
	echo -e $RED"\n...Press Enter to continue..."
	read -r -n1 </dev/tty
	echo -e $RESET
	clear
	return 0
}

#before adding a CIDR block, it'd be nice
#to make sure that an IP address within
#that block isn't already in UFW and
#delete it, if so
function delete_ip() {
	#find the UFW rule # associated with the IP
	#address
	# expects IP as first argument
	local ip="$1"

	if [[ -z "$ip" ]]; then
		echo -e $RED"No IP provided to delete_ip()"$RESET
		return 1
	fi

	# refresh status
	ufwstatus=$(ufw status)

	# delete all matching singleton rules by number (re-evaluate numbers after each delete)
	while true; do
		rule_no=$(ufw status numbered | grep -F "$ip" | sed -n 's/^\[\s*\([0-9]\+\)\].*/\1/p')
		[[ -z "$rule_no" ]] && break

		if ufw --force delete "$rule_no" &>/dev/null; then
			echo -e $GREEN"Deleted rule #$rule_no for $ip"$RESET
		else
			echo -e $RED"Failed to delete rule #$rule_no for $ip"$RESET
			return 1
		fi

		# refresh ufwstatus after deletion
		ufwstatus=$(ufw status)
	done

	return 0
}

#display the unique IP addresses on demand
function display_unique_ips() {

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
function print_info() {
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
		read -r -n1 -p $'\n> Press any key to continue (q to quit): ' key </dev/tty
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
#
# - Check UFW for IPs, Insert IP into UFW, Indicate success,
#   Skip IP if present in CIDR, Indicate failure if IP already present
function add_ips_to_ufw() {
	clear
	echo "Add singleton IP addresses to UFW"

	# confirm action
	echo -e $YELLOW
	read -r -n1 -p $'\n> Add offender IPs to UFW? (y/n): ' key </dev/tty
	echo -e $RESET
	if [[ "$key" =~ [nN] ]]; then
		echo "Aborting, returning to menu..."
		sleep 1
		clear
		return 0
	fi

	# refresh ufw status
	ufwstatus=$(ufw status)

	if [[ "$ufwstatus" == *"Status: inactive"* ]]; then
		echo -e $RED"UFW is inactive. Enable it before adding rules."$RESET
		pause
		return 1
	fi

	# loop through ips
	while read -r ip attempts; do
		# ignore empty lines
		[[ -z "$ip" ]] && continue

		cidr="${ip%.*}.0/24"

		# refresh status for each iteration to see newly added rules
		ufwstatus=$(ufw status)

		# if CIDR already present, skip adding ip
		if grep -qwF "$cidr" <<<"$ufwstatus"; then
			echo -e $ORANGE"Skipping $ip — covered by existing CIDR $cidr"$RESET
			continue
		fi

		# if the exact IP is already present, indicate failure/skip
		if grep -qwF "$ip" <<<"$ufwstatus"; then
			echo -e $RED"IP $ip already present in UFW (skipping)."$RESET
			continue
		fi

		# add deny rule for the single IP
		if ufw insert 1 deny from "$ip" to any &>/dev/null; then
			echo -e $GREEN"Added $ip to UFW successfully."$RESET
			# update local ufwstatus so subsequent checks see the new rule
			ufwstatus=$(ufw status)
		else
			echo -e $RED"Failed to add $ip to UFW."$RESET
		fi

	done < <(echo "$regs" | awk '{print $2, $1}')

	pause
	return 0
}

#modify the offenders to the CIDR notation for each
#e.g., 192.168.1.0/24. Strips the last octet of
#each offender's IP address and adds "0/24". this
#will block up to 256 addresses within the range
#(often attacks come in from multiple hosts
#within a given range)
function bracket_ips() {
	clear

	# confirm action
	echo -e $YELLOW
	read -r -n1 -p $'\n> Convert offender IPs to /24 and add to UFW? (y/n): ' key </dev/tty
	echo -e $RESET
	if [[ "$key" =~ [nN] ]]; then
		echo "Aborting, returning to menu..."
		sleep 1
		clear
		return 0
	fi

	# refresh ufw status
	ufwstatus=$(ufw status)
	if [[ "$ufwstatus" == *"Status: inactive"* ]]; then
		echo -e $RED"UFW is inactive. Enable it before bracketing."$RESET
		pause
		return 1
	fi

	# iterate through offenders
	while read -r ip attempts; do
		# ignore empty lines
		[[ -z "$ip" ]] && continue

		cidr="${ip%.*}.0/24"

		# refresh status each iteration
		ufwstatus=$(ufw status)

		# if CIDR already present, skip
		if grep -qwF "$cidr" <<<"$ufwstatus"; then
			echo -e $ORANGE"Skipping $ip — CIDR $cidr already present in UFW"$RESET
			continue
		fi

		# if exact singleton IP present, delete it first so CIDR can be added
		if grep -qwF "$ip" <<<"$ufwstatus"; then
			echo -e $YELLOW"Found singleton IP $ip in UFW — deleting before adding $cidr"$RESET
			# delegate deletion to delete_ip() which will remove all singleton rules
			if delete_ip "$ip"; then
				# refresh status after successful deletion
				ufwstatus=$(ufw status)
			else
				echo -e $RED"Failed to remove singleton IP $ip — skipping CIDR add"$RESET
				# skip this IP since we couldn't remove the singleton rule
				continue
			fi
		fi

		# re-check if CIDR got added by another iteration/process
		ufwstatus=$(ufw status)
		if grep -qwF "$cidr" <<<"$ufwstatus"; then
			echo -e $ORANGE"After cleanup, CIDR $cidr already present — skipping $ip"$RESET
			continue
		fi

		# insert CIDR as a deny rule at top
		if ufw insert 1 deny from "$cidr" to any &>/dev/null; then
			echo -e $GREEN"Added CIDR $cidr to UFW (covers $ip)."$RESET
			# refresh ufwstatus so subsequent checks see the new rule
			ufwstatus=$(ufw status)
		else
			echo -e $RED"Failed to add CIDR $cidr to UFW for $ip."$RESET
		fi

	done < <(echo "$regs" | awk '{print $2, $1}')

	pause
	return 0
}

#show all firewall rules (run thru less)
function show_firewall() {
	clear

	if [[ "$ufwstatus" == *"Status: inactive"* ]]; then
		echo -e $YELLOW
		echo "Firewall is not active..."
		echo -e $RESET
		pause
		return 0
	fi

	# refresh status each iteration
	ufwstatus=$(ufw status numbered)
	echo "$ufwstatus" | less
	return 0
}

#if the firewall becomes too conjested,
#reset it to allow only ssh, http, and
#https. Then, current offenders can be added
function reset_firewall() {
	clear

	#########################################
	# restores firewall to allow only ssh,
	# http, and https through
	#########################################

	echo -e $RED
	read -r -n1 -p $'\n> Are you sure you want to reset the firewall? (y/n): ' key </dev/tty
	echo -e $RESET

	if [[ "$key" =~ [nN] ]]; then
		echo -e $RED
		echo "Returning to Main Menu..."
		echo -e $RESET

		sleep 1.5
		clear
		return 0
	fi

	ufw --force disable &>/dev/null
	ufw --force reset &>/dev/null

	echo " ** UFW reset **"

	ufw allow ssh &>/dev/null
	ufw allow http &>/dev/null
	ufw allow https &>/dev/null

	ufw --force enable &>/dev/null
	echo " ** UFW enabled **"

	find /etc/ufw -name '*.rules.*' -delete &>/dev/null

	pause

	return 0
}

#################################
############  START  ############
#################################

#add variables to store current state of UFW
#and hold first three octets of each
ufwstatus=$(ufw status numbered)
currentIps=$()

#count both total attempts and uniq IP addresses
while read num ip; do
	((i += num))
	((uniqIps++))
done <<<$regs

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
		#pause
		;;
	4)
		bracket_ips
		#pause
		;;
	5)
		show_firewall
		clear
		;;
	6)
		reset_firewall
		#pause
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
