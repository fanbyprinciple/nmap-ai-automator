#!/bin/sh
#by @21y4d, modified with Gemini AI insights

# Define ANSI color variables
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'
origIFS="${IFS}"

# Start timer
elapsedStart="$(date '+%H:%M:%S' | awk -F: '{print $1 * 3600 + $2 * 60 + $3}')"
REMOTE=false

# Parse flags
while [ $# -gt 0 ]; do
        key="$1"

        case "${key}" in
        -H | --host)
                HOST="$2"
                shift
                shift
                ;;
        -t | --type)
                TYPE="$2"
                shift
                shift
                ;;
        -d | --dns)
                DNS="$2"
                shift
                shift
                ;;
        -o | --output)
                OUTPUTDIR="$2"
                shift
                shift
                ;;
        -s | --static-nmap)
                NMAPPATH="$2"
                shift
                shift
                ;;
        -r | --remote)
                REMOTE=true
                shift
                ;;
        *)
                POSITIONAL="${POSITIONAL} $1"
                shift
                ;;
        esac
done
set -- ${POSITIONAL}

# Legacy flags support, if run without -H/-t
if [ -z "${HOST}" ]; then
        HOST="$1"
fi

if [ -z "${TYPE}" ]; then
        TYPE="$2"
fi

# Legacy types support, if quick/basic used
if expr "${TYPE}" : '^\([Qq]uick\)$' >/dev/null; then
        TYPE="Port"
elif expr "${TYPE}" : '^\([Bb]asic\)$' >/dev/null; then
        TYPE="Script"
fi

# Set DNS or default to system DNS
if [ -n "${DNS}" ]; then
        DNSSERVER="${DNS}"
        DNSSTRING="--dns-server=${DNSSERVER}"
else
        DNSSERVER="$(grep 'nameserver' /etc/resolv.conf | grep -v '#' | head -n 1 | awk {'print $NF'})"
        DNSSTRING="--system-dns"
fi

# Set output dir or default to host-based dir
if [ -z "${OUTPUTDIR}" ]; then
        OUTPUTDIR="${HOST}"
fi

# Set path to nmap binary or default to nmap in $PATH, or resort to --remote mode
if [ -z "${NMAPPATH}" ] && type nmap >/dev/null 2>&1; then
        NMAPPATH="$(type nmap | awk {'print $NF'})"
elif [ -n "${NMAPPATH}" ]; then
        NMAPPATH="$(cd "$(dirname ${NMAPPATH})" && pwd -P)/$(basename ${NMAPPATH})"
        # Ensure static binary is executable and is nmap
        if [ ! -x $NMAPPATH ]; then
                printf "${RED}\nFile is not executable! Attempting chmod +x...${NC}\n"
                chmod +x $NMAPPATH 2>/dev/null || (printf "${RED}Could not chmod. Running in Remote mode...${NC}\n\n" && REMOTE=true)
        elif [ $($NMAPPATH -h | head -c4) != "Nmap" ]; then
                printf "${RED}\nStatic binary does not appear to be Nmap! Running in Remote mode...${NC}\n\n" && REMOTE=true
        fi
        printf "${GREEN}\nUsing static nmap binary at ${NMAPPATH}${NC}\n"
else
        printf "${RED}\nNmap is not installed and -s is not used. Running in Remote mode...${NC}\n\n" && REMOTE=true
fi

# Print usage menu and exit. Used when issues are encountered
usage() {
        echo
        printf "${RED}Usage: $(basename $0) -H/--host ${NC}<TARGET-IP>${RED} -t/--type ${NC}<TYPE>${RED}\n"
        printf "${YELLOW}Optional: [-r/--remote ${NC}<REMOTE MODE>${YELLOW}] [-d/--dns ${NC}<DNS SERVER>${YELLOW}] [-o/--output ${NC}<OUTPUT DIRECTORY>${YELLOW}] [-s/--static-nmap ${NC}<STATIC NMAP PATH>${YELLOW}]\n\n"
        printf "Scan Types:\n"
        printf "${YELLOW}\tNetwork : ${NC}Shows all live hosts in the host's network ${YELLOW}(~15 seconds)\n"
        printf "${YELLOW}\tPort    : ${NC}Shows all open ports ${YELLOW}(~15 seconds)\n"
        printf "${YELLOW}\tScript  : ${NC}Runs a script scan on found ports ${YELLOW}(~5 minutes)\n"
        printf "${YELLOW}\tFull    : ${NC}Runs a full range port scan, then runs a script scan on new ports ${YELLOW}(~5-10 minutes)\n"
        printf "${YELLOW}\tUDP     : ${NC}Runs a UDP scan \"requires sudo\" ${YELLOW}(~5 minutes)\n"
        printf "${YELLOW}\tVulns   : ${NC}Runs CVE scan and nmap Vulns scan on all found ports ${YELLOW}(~5-15 minutes)\n"
        printf "${YELLOW}\tRecon   : ${NC}Suggests recon commands, then prompts to automatically run them\n"
        printf "${YELLOW}\tAnalyze : ${NC}Sends scan data to Gemini AI for vulnerability remediation insights\n"
        printf "${YELLOW}\tAll     : ${NC}Runs all the scans including AI analysis ${YELLOW}(~20-30 minutes)\n"
        printf "${NC}\n"
        exit 1
}

# Print initial header and set initial variables before scans start
header() {
        echo

        # Print scan type
        if expr "${TYPE}" : '^\([Aa]ll\)$' >/dev/null; then
                printf "${YELLOW}Running all scans on ${NC}${HOST}"
        else
                printf "${YELLOW}Running a ${TYPE} scan on ${NC}${HOST}"
        fi

        if expr "${HOST}" : '^\(\([[:alnum:]-]\{1,63\}\.\)*[[:alpha:]]\{2,6\}\)$' >/dev/null; then
                urlIP="$(host -4 -W 1 ${HOST} ${DNSSERVER} 2>/dev/null | grep ${HOST} | head -n 1 | awk {'print $NF'})"
                if [ -n "${urlIP}" ]; then
                        printf "${YELLOW} with IP ${NC}${urlIP}\n\n"
                else
                        printf ".. ${RED}Could not resolve IP of ${NC}${HOST}\n\n"
                fi
        else
                printf "\n"
        fi

        if $REMOTE; then
                printf "${YELLOW}Running in Remote mode! Some scans will be limited.\n"
        fi

        # Set $subnet variable
        if expr "${HOST}" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null; then
                subnet="$(echo "${HOST}" | cut -d "." -f 1,2,3).0"
        fi

        # Set $nmapType variable based on ping
        kernel="$(uname -s)"
        checkPing="$(checkPing "${urlIP:-$HOST}")"
        nmapType="$(echo "${checkPing}" | head -n 1)"

        # Set if host is pingable 'for ping scans'
        if expr "${nmapType}" : ".*-Pn$" >/dev/null; then
                pingable=false
                printf "${NC}\n"
                printf "${YELLOW}No ping detected.. Will not use ping scans!\n"
                printf "${NC}\n"
        else
                pingable=true
        fi

        # OS Detection
        ttl="$(echo "${checkPing}" | tail -n 1)"
        if [ "${ttl}" != "nmap -Pn" ]; then
                osType="$(checkOS "${ttl}")"
                printf "${NC}\n"
                printf "${GREEN}Host is likely running ${osType}\n"
        fi

        echo
        echo
}

assignPorts() {
        if [ -f "nmap/Port_$1.nmap" ]; then
                commonPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/Port_$1.nmap" | sed 's/.$//')"
        fi

        if [ -f "nmap/Full_$1.nmap" ]; then
                if [ -f "nmap/Port_$1.nmap" ]; then
                        allPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/Port_$1.nmap" "nmap/Full_$1.nmap" | sed 's/.$//')"
                else
                        allPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/Full_$1.nmap" | sed 's/.$//')"
                fi
        fi

        if [ -f "nmap/UDP_$1.nmap" ]; then
                udpPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/UDP_$1.nmap" | sed 's/.$//')"
                if [ "${udpPorts}" = "Al" ]; then
                        udpPorts=""
                fi
        fi
}

checkPing() {
        if [ $kernel = "Linux" ]; then TW="W"; else TW="t"; fi
        pingTest="$(ping -c 1 -${TW} 1 "$1" 2>/dev/null | grep ttl)"
        if [ -z "${pingTest}" ]; then
                echo "${NMAPPATH} -Pn"
        else
                echo "${NMAPPATH}"
                if expr "$1" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null; then
                        ttl="$(echo "${pingTest}" | cut -d " " -f 6 | cut -d "=" -f 2)"
                else
                        ttl="$(echo "${pingTest}" | cut -d " " -f 7 | cut -d "=" -f 2)"
                fi
                echo "${ttl}"
        fi
}

checkOS() {
        case "$1" in
        25[456]) echo "OpenBSD/Cisco/Oracle" ;;
        12[78]) echo "Windows" ;;
        6[34]) echo "Linux" ;;
        *) echo "Unknown OS!" ;;
        esac
}

cmpPorts() {
        extraPorts="$(echo ",${allPorts}," | sed 's/,\('"$(echo "${commonPorts}" | sed 's/,/,\\|/g')"',\)\+/,/g; s/^,\|,$//g')"
}

progressBar() {
        [ -z "${2##*[!0-9]*}" ] && return 1
        [ "$(stty size | cut -d ' ' -f 2)" -le 120 ] && width=50 || width=100
        fill="$(printf "%-$((width == 100 ? $2 : ($2 / 2)))s" "#" | tr ' ' '#')"
        empty="$(printf "%-$((width - (width == 100 ? $2 : ($2 / 2))))s" " ")"
        printf "In progress: $1 Scan ($3 elapsed - $4 remaining)   \n"
        printf "[${fill}>${empty}] $2%% done   \n"
        printf "\e[2A"
}

nmapProgressBar() {
        refreshRate="${2:-1}"
        outputFile="$(echo $1 | sed -e 's/.*-oN \(.*\).nmap.*/\1/').nmap"
        tmpOutputFile="${outputFile}.tmp"

        if [ ! -e "${outputFile}" ]; then
                $1 --stats-every "${refreshRate}s" >"${tmpOutputFile}" 2>&1 &
        fi

        while { [ ! -e "${outputFile}" ] || ! grep -q "Nmap done at" "${outputFile}"; } && { [ ! -e "${tmpOutputFile}" ] || ! grep -i -q "quitting" "${tmpOutputFile}"; }; do
                scanType="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -ne '/elapsed/{s/.*undergoing \(.*\) Scan.*/\1/p}')"
                percent="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -ne '/% done/{s/.*About \(.*\)\..*% done.*/\1/p}')"
                elapsed="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -ne '/elapsed/{s/Stats: \(.*\) elapsed.*/\1/p}')"
                remaining="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -ne '/remaining/{s/.* (\(.*\) remaining.*/\1/p}')"
                progressBar "${scanType:-No}" "${percent:-0}" "${elapsed:-0:00:00}" "${remaining:-0:00:00}"
                sleep "${refreshRate}"
        done
        printf "\033[0K\r\n\033[0K\r\n"

        if [ -e "${outputFile}" ]; then
                sed -n '/PORT.*STATE.*SERVICE/,/^# Nmap/H;${x;s/^\n\|\n[^\n]*\n# Nmap.*//gp}' "${outputFile}" | awk '!/^SF(:|-).*$/' | grep -v 'service unrecognized despite'
        else
                cat "${tmpOutputFile}"
        fi
        rm -f "${tmpOutputFile}"
}

networkScan() {
        printf "${GREEN}---------------------Starting Network Scan---------------------\n"
        printf "${NC}\n"
        origHOST="${HOST}"
        HOST="${urlIP:-$HOST}"
        if [ $kernel = "Linux" ]; then TW="W"; else TW="t"; fi
        if ! $REMOTE; then
                nmapProgressBar "${nmapType} -T4 --max-retries 1 --max-scan-delay 20 -n -sn -oN nmap/Network_${HOST}.nmap ${subnet}/24"
                printf "${YELLOW}Found the following live hosts:${NC}\n\n"
                cat nmap/Network_${HOST}.nmap | grep -v '#' | grep "$(echo $subnet | sed 's/..$//')" | awk {'print $5'}
        elif $pingable; then
                echo >"nmap/Network_${HOST}.nmap"
                for ip in $(seq 0 254); do
                        (ping -c 1 -${TW} 1 "$(echo $subnet | sed 's/..$//').$ip" 2>/dev/null | grep 'stat' -A1 | xargs | grep -v ', 0.*received' | awk {'print $2'} >>"nmap/Network_${HOST}.nmap") &
                done
                wait
                sed -i '/^$/d' "nmap/Network_${HOST}.nmap"
                sort -t . -k 3,3n -k 4,4n "nmap/Network_${HOST}.nmap"
        else
                printf "${YELLOW}No ping detected.. TCP Network Scan is not implemented yet in Remote mode.\n${NC}"
        fi
        HOST="${origHOST}"
        echo; echo; echo
}

portScan() {
        printf "${GREEN}---------------------Starting Port Scan-----------------------\n"
        printf "${NC}\n"
        if ! $REMOTE; then
                nmapProgressBar "${nmapType} -T4 --max-retries 1 --max-scan-delay 20 --open -oN nmap/Port_${HOST}.nmap ${HOST} ${DNSSTRING}"
                assignPorts "${HOST}"
        else
                printf "${YELLOW}Port Scan is not implemented yet in Remote mode.\n${NC}"
        fi
        echo; echo; echo
}

scriptScan() {
        printf "${GREEN}---------------------Starting Script Scan-----------------------\n"
        printf "${NC}\n"
        if ! $REMOTE; then
                if [ -z "${commonPorts}" ]; then
                        printf "${YELLOW}No ports in port scan.. Skipping!\n"
                else
                        nmapProgressBar "${nmapType} -sCV -p${commonPorts} --open -oN nmap/Script_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                fi
                if [ -f "nmap/Script_${HOST}.nmap" ] && grep -q "Service Info: OS:" "nmap/Script_${HOST}.nmap"; then
                        serviceOS="$(sed -n '/Service Info/{s/.* \([^;]*\);.*/\1/p;q}' "nmap/Script_${HOST}.nmap")"
                        if [ "${osType}" != "${serviceOS}" ]; then
                                osType="${serviceOS}"
                                printf "${NC}\n"
                                printf "${GREEN}OS Detection modified to: ${osType}\n"
                        fi
                fi
        else
                printf "${YELLOW}Script Scan is not supported in Remote mode.\n${NC}"
        fi
        echo; echo; echo
}

fullScan() {
        printf "${GREEN}---------------------Starting Full Scan------------------------\n"
        printf "${NC}\n"
        if ! $REMOTE; then
                nmapProgressBar "${nmapType} -p- --max-retries 1 --max-rate 500 --max-scan-delay 20 -T4 -v --open -oN nmap/Full_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
                assignPorts "${HOST}"
                if [ -z "${commonPorts}" ]; then
                        echo; printf "${YELLOW}Making a script scan on all ports\n"
                        nmapProgressBar "${nmapType} -sCV -p${allPorts} --open -oN nmap/Full_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                        assignPorts "${HOST}"
                else
                        cmpPorts
                        if [ -z "${extraPorts}" ]; then
                                echo; allPorts=""; printf "${YELLOW}No new ports\n"
                        else
                                echo; printf "${YELLOW}Making a script scan on extra ports: $(echo "${extraPorts}" | sed 's/,/, /g')\n"
                                nmapProgressBar "${nmapType} -sCV -p${extraPorts} --open -oN nmap/Full_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                                assignPorts "${HOST}"
                        fi
                fi
        else
                printf "${YELLOW}Full Scan is not implemented yet in Remote mode.\n${NC}"
        fi
        echo; echo; echo
}

UDPScan() {
        printf "${GREEN}----------------------Starting UDP Scan------------------------\n"
        printf "${NC}\n"
        if ! $REMOTE; then
                if [ "${USER}" != 'root' ]; then
                        echo "UDP needs to be run as root, running with sudo..."
                        sudo -v
                        echo
                fi
                nmapProgressBar "sudo ${nmapType} -sU --max-retries 1 --open --open -oN nmap/UDP_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
                assignPorts "${HOST}"
                if [ -n "${udpPorts}" ]; then
                        echo; printf "${YELLOW}Making a script scan on UDP ports: $(echo "${udpPorts}" | sed 's/,/, /g')\n"
                        if [ -f /usr/share/nmap/scripts/vulners.nse ]; then
                                sudo -v
                                nmapProgressBar "sudo ${nmapType} -sCVU --script vulners --script-args mincvss=7.0 -p${udpPorts} --open -oN nmap/UDP_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                        else
                                sudo -v
                                nmapProgressBar "sudo ${nmapType} -sCVU -p${udpPorts} --open -oN nmap/UDP_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                        fi
                else
                        echo; printf "${YELLOW}No UDP ports are open\n"
                fi
        else
                printf "${YELLOW}UDP Scan is not implemented yet in Remote mode.\n${NC}"
        fi
        echo; echo; echo
}

vulnsScan() {
        printf "${GREEN}---------------------Starting Vulns Scan-----------------------\n"
        printf "${NC}\n"
        if ! $REMOTE; then
                if [ -z "${allPorts}" ]; then
                        portType="common"; ports="${commonPorts}"
                else
                        portType="all"; ports="${allPorts}"
                fi
                if [ ! -f /usr/share/nmap/scripts/vulners.nse ]; then
                        printf "${RED}Please install 'vulners.nse' nmap script. Skipping CVE scan!\n"
                else
                        printf "${YELLOW}Running CVE scan on ${portType} ports\n"
                        nmapProgressBar "${nmapType} -sV --script vulners --script-args mincvss=7.0 -p${ports} --open -oN nmap/CVEs_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
                fi
                echo; printf "${YELLOW}Running Vuln scan on ${portType} ports\n"
                nmapProgressBar "${nmapType} -sV --script vuln -p${ports} --open -oN nmap/Vulns_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
        else
                printf "${YELLOW}Vulns Scan is not supported in Remote mode.\n${NC}"
        fi
        echo; echo; echo
}

# --- NEW: Gemini AI Analysis Function ---
geminiAnalyze() {
    printf "${GREEN}---------------------Starting Gemini AI Analysis----------------\n"
    printf "${NC}\n"

    # API Key Check
    if [ -z "$GEMINI_API_KEY" ]; then
        printf "${RED}Error: GEMINI_API_KEY is not set in your environment.${NC}\n"
        printf "${YELLOW}Please run: export GEMINI_API_KEY='your_api_key'${NC}\n\n"
        return
    fi

    # Dependency Check
    if ! type jq >/dev/null 2>&1; then
        printf "${RED}Error: 'jq' is required for JSON processing. Install with: sudo apt install jq${NC}\n"
        return
    fi

    # Aggregate existing scan data
    local scan_results=""
    for file in "nmap/Script_${HOST}.nmap" "nmap/Vulns_${HOST}.nmap" "nmap/CVEs_${HOST}.nmap"; do
        if [ -f "$file" ]; then
            scan_results="${scan_results}\n--- Data from $file ---\n$(cat "$file")"
        fi
    done

    if [ -z "$scan_results" ]; then
        printf "${RED}No scan data found for analysis. Run 'Script' or 'Vulns' scan first.${NC}\n"
        return
    fi

    printf "${YELLOW}Preparing prompt and calling Gemini API...${NC}\n"

    local prompt="You are a Cybersecurity Specialist. I have scanned the host ${HOST}. 
    Based on the following Nmap results, identify the most critical security vulnerabilities and misconfigurations.
    For each issue:
    1. Explain the risk.
    2. Provide specific remediation steps (e.g., specific configuration changes or update commands).
    3. Suggest how an attacker might exploit this if left unpatched.
    
    Scan Data:
    ${scan_results}"

    # Query Gemini API via curl and jq
    local response=$(curl -s -X POST "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_API_KEY}" \
        -H "Content-Type: application/json" \
        -d "$(jq -n --arg p "$prompt" '{contents: [{parts: [{text: $p}]}]}')")

    # Extract text content
    local analysis=$(echo "$response" | jq -r '.candidates[0].content.parts[0].text // "Error: Unable to parse Gemini response."')

    # Save and output
    echo "$analysis" > "nmap/AI_Analysis_${HOST}.md"
    printf "${GREEN}Analysis complete! Saved to: nmap/AI_Analysis_${HOST}.md${NC}\n"
    echo "==============================================================="
    echo "$analysis"
    echo "==============================================================="
}

# Original Recon Logic
recon() {
        IFS="
"
        reconRecommend "${HOST}" | tee "nmap/Recon_${HOST}.nmap"
        allRecon="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap" | cut -d " " -f 1 | sort | uniq)"
        for tool in ${allRecon}; do
                if ! type "${tool}" >/dev/null 2>&1; then
                        missingTools="$(echo ${missingTools} ${tool} | awk '{$1=$1};1')"
                fi
        done
        if [ -n "${missingTools}" ]; then
                printf "${RED}Missing tools: ${NC}${missingTools}\n"
                availableRecon="$(echo "${allRecon}" | tr " " "\n" | awk -vORS=', ' '!/'"$(echo "${missingTools}" | tr " " "|")"'/' | sed 's/..$//')"
        else
                availableRecon="$(echo "${allRecon}" | tr "\n" " " | sed 's/\ /,\ /g' | sed 's/..$//')"
        fi
        secs=30; count=0
        if [ -n "${availableRecon}" ]; then
                while [ "${reconCommand}" != "!" ]; do
                        printf "${YELLOW}\nWhich commands would you like to run?${NC}\nAll (Default), ${availableRecon}, Skip <!>\n\n"
                        while [ ${count} -lt ${secs} ]; do
                                tlimit=$((secs - count)); printf "\033[2K\rRunning Default in (${tlimit})s: "
                                reconCommand="$(sh -c '{ { sleep 1; kill -sINT $$; } & }; exec head -n 1')"
                                count=$((count + 1)); [ -n "${reconCommand}" ] && break
                        done
                        if expr "${reconCommand}" : '^\([Aa]ll\)$' >/dev/null || [ -z "${reconCommand}" ]; then
                                runRecon "${HOST}" "All"; reconCommand="!"
                        elif expr " ${availableRecon}," : ".* ${reconCommand}," >/dev/null; then
                                runRecon "${HOST}" "${reconCommand}"; reconCommand="!"
                        elif [ "${reconCommand}" = "Skip" ] || [ "${reconCommand}" = "!" ]; then
                                reconCommand="!"; echo; echo; echo
                        else
                                printf "${RED}Incorrect choice!\n"
                        fi
                done
        else
                printf "${YELLOW}No Recon Recommendations found...\n"
        fi
        IFS="${origIFS}"
}

reconRecommend() {
        printf "${GREEN}---------------------Recon Recommendations---------------------\n"
        printf "${NC}\n"; IFS="
"
        if [ -f "nmap/Full_Extra_${HOST}.nmap" ]; then
                ports="${allPorts}"; file="$(cat "nmap/Script_${HOST}.nmap" "nmap/Full_Extra_${HOST}.nmap" | grep "open" | grep -v "#" | sort | uniq)"
        elif [ -f "nmap/Script_${HOST}.nmap" ]; then
                ports="${commonPorts}"; file="$(grep "open" "nmap/Script_${HOST}.nmap" | grep -v "#")"
        fi
        if echo "${file}" | grep -q "25/tcp"; then
                printf "${YELLOW}SMTP Recon:\n"; echo "smtp-user-enum -U /usr/share/wordlists/metasploit/unix_users.txt -t \"${HOST}\" | tee \"recon/smtp_user_enum_${HOST}.txt\""; echo
        fi
        if echo "${file}" | grep -q "53/tcp" && [ -n "${DNSSERVER}" ]; then
                printf "${YELLOW}DNS Recon:\n"; echo "host -l \"${HOST}\" \"${DNSSERVER}\" | tee \"recon/hostname_${HOST}.txt\""; echo
        fi
        if echo "${file}" | grep -i -q http; then
                printf "${YELLOW}Web Servers Recon:\n"
                for line in ${file}; do
                        if echo "${line}" | grep -i -q http; then
                                port="$(echo "${line}" | cut -d "/" -f 1)"
                                if echo "${line}" | grep -q ssl/http; then
                                        urlType='https://'; echo "sslscan \"${HOST}\" | tee \"recon/sslscan_${HOST}_${port}.txt\""
                                else
                                        urlType='http://'; echo "nikto -host \"${urlType}${HOST}:${port}\" | tee \"recon/nikto_${HOST}_${port}.txt\""
                                fi
                                echo
                        fi
                done
        fi
        IFS="${origIFS}"; echo; echo; echo
}

runRecon() {
        printf "${GREEN}---------------------Running Recon Commands--------------------\n"
        mkdir -p recon/; IFS="
"
        if [ "$2" = "All" ]; then reconCommands="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap")"
        else reconCommands="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap" | grep "$2")"; fi
        for line in ${reconCommands}; do
                currentScan="$(echo "${line}" | cut -d ' ' -f 1)"; fileName="$(echo "${line}" | awk -F "recon/" '{print $2}')"
                if [ -n "${fileName}" ] && [ ! -f recon/"${fileName}" ]; then
                        printf "${YELLOW}Starting ${currentScan} scan\n"; eval "${line}"
                fi
        done
        IFS="${origIFS}"; echo; echo; echo
}

footer() {
        printf "${GREEN}---------------------Finished all scans------------------------\n"
        elapsedEnd="$(date '+%H:%M:%S' | awk -F: '{print $1 * 3600 + $2 * 60 + $3}')"
        elapsedSeconds=$((elapsedEnd - elapsedStart))
        printf "${YELLOW}Completed in ${elapsedSeconds} seconds\n${NC}\n"
}

main() {
        assignPorts "${HOST}"
        header
        case "${TYPE}" in
        [Nn]etwork) networkScan "${HOST}" ;;
        [Pp]ort) portScan "${HOST}" ;;
        [Ss]cript) [ ! -f "nmap/Port_${HOST}.nmap" ] && portScan "${HOST}"; scriptScan "${HOST}" ;;
        [Ff]ull) fullScan "${HOST}" ;;
        [Uu]dp) UDPScan "${HOST}" ;;
        [Vv]ulns) [ ! -f "nmap/Port_${HOST}.nmap" ] && portScan "${HOST}"; vulnsScan "${HOST}" ;;
        [Rr]econ) [ ! -f "nmap/Port_${HOST}.nmap" ] && portScan "${HOST}"; scriptScan "${HOST}"; recon "${HOST}" ;;
        [Aa]nalyze) [ ! -f "nmap/Script_${HOST}.nmap" ] && scriptScan "${HOST}"; geminiAnalyze "${HOST}" ;;
        [Aa]ll)
                portScan "${HOST}"
                scriptScan "${HOST}"
                fullScan "${HOST}"
                UDPScan "${HOST}"
                vulnsScan "${HOST}"
                recon "${HOST}"
                geminiAnalyze "${HOST}"
                ;;
        esac
        footer
}

if [ -z "${TYPE}" ] || [ -z "${HOST}" ]; then usage; fi
if ! expr "${HOST}" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null && ! expr "${HOST}" : '^\(\([[:alnum:]-]\{1,63\}\.\)*[[:alpha:]]\{2,6\}\)$' >/dev/null; then
        printf "${RED}\nInvalid IP or URL!\n"; usage
fi

if ! case "${TYPE}" in [Nn]etwork | [Pp]ort | [Ss]cript | [Ff]ull | UDP | udp | [Vv]ulns | [Rr]econ | [Aa]nalyze | [Aa]ll) false ;; esac then
        mkdir -p "${OUTPUTDIR}" && cd "${OUTPUTDIR}" && mkdir -p nmap/ || usage
        main | tee "nmapAutomator_${HOST}_${TYPE}.txt"
else
        printf "${RED}\nInvalid Type!\n"; usage
fi