#!/bin/bash

# bettermap.sh scanner Dewalt - rev WhoKnows : Codename PRE-UDP
#
# Know yourself and know your foe and you need not fear the outcome of 100 battles
# Know yourself but not know your foe for every victory gained you shall suffer a defeat
# Know neither yourself, nor your foe you will succumb in every battle.
# - Sun Tzu The Art Of War - Translation: Enumeration is key
#

# major idea change, have it run thru all machine ips get the service type and port number
# then do the scanning...

# DEFINE GLOBALS
  # unicorn puke / status indicators
  greenplus='\e[1;33m[++]\e[0m'
  greenminus='\e[1;33m[--]\e[0m'
  redplus='\e[1;31m[++]\e[0m'
  redminus='\e[1;31m[--]\e[0m'
  redexclaim='\e[1;31m[!!]\e[0m'
  redstar='\e[1;31m[**]\e[0m'
  blinkexclaim='\e[1;31m[\e[5;31m!!\e[0m\e[1;31m]\e[0m'
  fourblinkexclaim='\e[1;31m[\e[5;31m!!!!\e[0m\e[1;31m]\e[0m'
  sleeptimer="$2"

# DEFINE GLOBAL FILES AND VAR TO ACCESS THEM
  # temporary files used by the script defined here
  tcp_sorted='/tmp/tcp_sorted'
  udp_sorted='/tmp/udp_sorted'
  skipped='/tmp/skipped.list'
  nmap_found='/tmp/nmap_found'
  found_port='/tmp/ports.tmp'
  found_service='/tmp/service.tmp'

# sanitycheck="1" or "0"
  # - add if statments for sanity checks

# MAX SLEEP TIMER / INCREMENT = TOTAL REATTEMPTS
  # 300 seconds / 60 seconds = 5 re-attempts with incremental delay, 60, 120, 180, 240 and 300
  # 120 seconds / 30 seconds = 4 re-attempts with incremental delay, 30, 60, 90 and 120
  # increment sleep in seconds between each scan reattempt
  snooze_increment=30
  # maxmium sleep time in seconds to sleep on failed scans / fail2ban detection
  maxsleep=120

# HARD SET GLOBAL VALUES
  check_for_pn_switch=0
  date=$(date +%x)
  time=$(date +%X)

# LOGGING
  #  Uncomment next 2 lines to enable logging of script run
    LOG_FILE='/tmp/superscan.log'
  # overwrite log on each run
    exec > >(tee ${LOG_FILE}) 2>&1
  # append log on each run
    # exec > >(tee -a ${LOG_FILE}) 2>&1

# CHECK FOR EUID = 0
if [ $EUID -ne 0 ]
  then
    echo -e "\n  $redexclaim Script must be run with sudo or as root \n"
    exit
  else
    echo -e "\n  $greenplus BetterMap - Case studies show its the smarter way to Nmap!"
  fi

service_scan() {
  echo -e "\n  $greenplus Service Scanning : $getip"
  echo -e "       Ports : $ports "
  [[ ! -d $getip ]] && mkdir -p $getip
  # UNCOMMENT FOR SANITY CHECK
  # echo "nmap $pingprobe -p$ports -sV -T4 $getip > "$getip/$getip.service_scan" "

  ### PRE UDP BUILD OUT
  # for udp a scantype="-sU" is needed here and detection of which scantype is passed
  # if [ $protocol = "tcp" ]
  #   then
  #    scantype=""  # defaults to tcp does not need to be set here
  # nmap $pingprobe $scantype -$ports -sV -T4 $getip > "$getip/$getip.service_scan"

  # COMMENT OUT FOR SANITY CHECK

  # add if statment $protcol = "udp"
  # if [ $protcol = "udp" ]
  # then
  # scantype="-sU"
  #   nmap $scantype $pingprobe -p$ports -sV -T4 $getip > "$getip/$getip.udp_service.scan"
  #
  nmap $pingprobe -p$ports -sC -O -A -sV --version-all -T4 $getip > "$getip/$getip.tcp.service_scan"
  for each_ip in $getip; do
    if [[ $ports = "" ]]
     then
       echo -e "\n  $redexclaim $each_ip - no ports detected"
       echo "$each_ip" >> $skipped
    else
      ### PRE UDP BUILD OUT
      # build out for udp inclusion file needs to be $each_ip.tcp_service_scan
      # need to check the existing service scan and make sure udp isnt already being
      # detected before implementing a new scantype for udp specifcially

      # add if statement for $protocl = "udp"
      # if [ $protocol = "udp" ]
      #  then
      #  cat $each_ip/$each_ip.udp_service_scan | grep -i '^[0-9]*/udp' | awk '{print$1}' | sed s:"\/tcp":"":g  > $found_port
      #  cat $each_ip/$each_ip.udp_service_scan | grep -i '^[0-9]*/udp' | awk '{print$3}' | sed s:"\/tcp":"":g | sed s:"\?":"":g > $found_service


      cat $each_ip/$each_ip.tcp.service_scan | grep -i '^[0-9]*/tcp' | awk '{print$1}' | sed s:"\/tcp":"":g  > $found_port
      cat $each_ip/$each_ip.tcp.service_scan | grep -i '^[0-9]*/tcp' | awk '{print$3}' | sed s:"\/tcp":"":g | sed s:"\?":"":g > $found_service

      paste $found_port $found_service | while IFS="$(printf '\t')" read -r f1 f2
       do
         each_port=$(printf '%s\n' "$f1")
         each_service=$(printf '%s\n' "$f2" | sed s:"\?":"":g)
         if [[ "$sleeptimer" == "" || "$sleeptimer" == "0" ]]
          then
            echo -e "\n  $redexclaim No Sleep timer detected, may trigger fail2ban "
            deepscan $each_ip $each_port $each_service
          else
            echo -e "\n  $redplus Sleep detected - sleeping $sleeptimer seconds...\n"
            sleep $sleeptimer
            deepscan $each_ip $each_port $each_service
            ### PRE UDP BUILD OUT
            # $protocol would need to be defined here and passed
         fi
       done
    fi
  done
### PRE UDP BUILD OUT
# fi

### PRE UDP BUILD OUT
#   if [ $protocol = "udp" ]
#    then
#     scantype="-sU"
#     nmap $pingprobe $scantype -$ports -sV -T4 $getip > "$getip/$getip.udp_service_scan"
#   for each_ip in $getip; do
#      if [[ $ports = "" ]]
#       then
#        echo -e "\n  $redexclaim $each_ip - no ports detected"
#        echo "$each_ip" >> $skipped
#       else
#        cat $each_ip/$each_ip.service_scan | grep -i "open" | awk '{print$1}' | sed s:"\/tcp":"":g  > $found_port
#        cat $each_ip/$each_ip.service_scan | grep -i "open" | awk '{print$3}' | sed s:"\/tcp":"":g | sed s:"\?":"":g > $found_service
#
#        paste $found_port $found_service | while IFS="$(printf '\t')" read -r f1 f2
#         do
#           each_port=$(printf '%s\n' "$f1")
#           each_service=$(printf '%s\n' "$f2" | sed s:"\?":"":g)
#             if [[ "$sleeptimer" == "" || "$sleeptimer" == "0" ]]
#              then
#               echo -e "\n  $redexclaim No Sleep timer detected, may trigger fail2ban "
#               deepscan $each_ip $each_port $each_service $scantype
#             else
#               echo -e "\n  $redplus Sleep detected - sleeping $sleeptimer seconds...\n"
#               sleep $sleeptimer
#               deepscan $each_ip $each_port $each_service $scantype $protocol
#            # $protocol would need to be defined here and passed
#         fi
#       done
#    fi
#  done
# fi
  }

deepscan () {
  mkdir -p "$each_ip"/"$each_port"
  nmap_script=""
  check_for_fail=0
  found=0
  logging="$each_ip/$each_port/$each_port"
  scan_options="-sV --version-all -sC -O -A -T4"
  ### PRE UDP BUILD OUT
  # udp build out for tcp scans scantype=""
  #if [ $protocol = "tcp" ]
    #then
  case $each_service in
    # DEFINE SPECIFIC TCP SERVICES HERE
    # common ports 21 / 20 ftp-data
    "ftp" ) found=1; nmap_script="vuln,ftp-anon,ftp-proftpd-backdoor,ftp-vsftpd-backdoor";;

    # common ports 22
    "ssh" ) found=1; nmap_script="vuln,ssh-auth-methods,ssh-hostkey,ssh-publickey-acceptance,ssh2-enum-algos,sshv1";;

    # common ports 25
    "smtp" ) found=1; nmap_script="vuln,smtp-enum-users,smtp-ntlm-info,smtp-open-relay,smtp-strangeport";;

    # common ports 53
    "domain" ) found=1; nmap_script="vuln,dns-zone-transfer,dns-srv-enum,dns-brute";;

    # common ports 80, 8080
    "http"|"http-alt" ) found=1; nmap_script="vuln,http-title,http-config-backup,http-wordpress-enum,http-shellshock";;

    # common ports 110
    "pop3" ) found=1; nmap_script="vuln,pop3-capabilities,pop3-ntlm-info";;

    # common ports 111
    "rpcbind" ) found=1; nmap_script="vuln,nfs-showmount,nfs-statfs,nfs-ls,rpcinfo,rpc-grind";;

    # common ports 135 - msrpc
    "msrpc" ) found=1; nmap_script="vuln,msrpc-enum,rpcinfo,rpc-grind";;

    # common ports 137 and 138 nothing usually intresting - commented out
    # "netbios-sn"|"netbios-dgm"  ) found=1; nmap_script="vuln,smb-os-discovery,smb-enum-domains,smb-enum-groups,smb-enum-users,smb-enum-shares";;
    # common ports 139 and 445 usually something intresting if it is there
    "netbios-ssn"|"microsoft-ds" ) found=1; nmap_script="vuln,smb-os-discovery,smb-enum-domains,smb-enum-groups,smb-enum-users,smb-enum-shares";;

    # common ports 143 - imap
    "imap"|"imap3" ) found=1; nmap_script="vuln,imap-capabilities,imap-ntlm-info";;

    # SNMP port 161 tcp/udp also add $protocol flag for tcp or udp
    # -- work in progress -- need to add a detection flag for udp or just force a udp scan 1 time
    # all scripts : snmp-brute snmp-hh3c-logins snmp-info snmp-interfaces
    # snmp-ios-config snmp-netstat snmp-processes snmp-sysdescr snmp-win32-services
    # snmp-win32-shares snmp-win32-software snmp-win32-users
    # "snmp"|"smux" ) found=1; scan_options="-sU" nmap_script="snmp-brute snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"
    # snmp-info,snmp-interfaces,snmp-ios-config,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users";;
    # other snmp types :
    # "snmptrap"|"synotic-relay"|"snmp-tcp-port"|"oce-snmp-trap" \
    #"squid-snmp"|"websphere-snmp"|"snmpssh"|"patrol-snmp"|"snmptls"|"snmpdtls" \
    #"snmptls-trap"|"snmpdtls-trap"|"suncacao-snmp"

    # common ports 389/636 - ldap
    "ldap"|"ldaps" ) found=1; nmap_script="vuln,ldap-novell-getpass,ldap-rootdse,ldap-search";;

    # common ports 443 - https
    "ssl/http" ) found=1; nmap_script="vuln,https-redirect,ip-https-discover";;

    # common ports 1521 - oracle database
    "oracle"|"oracle-tns" ) found=1; nmap_script="vuln,oracle-tns-version,oracle-enum-users,oracle-sid-brute";;

    # common ports 3306 - mysql,mysql-cluster,mysql-cm-agent,mysql-im,mysql-proxy,mysqlx
    "mysql"  ) found=1; nmap_script="vuln,mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables";;

    # common ports 3389 - microsoft rdp
    "ssl/ms-wbt-server"|"ms-wbt-server" ) found=1; nmap_script="vuln,rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020";;

    # common ports 4569 tcp/udp
    # "asterisk" ) found=1; nmap_script="vuln,iax-version"

    # common ports 27900? - microsoft sql
    "ms-sql-s" ) found=1; nmap_script="vuln,ms-sql-info,ms-sql-config,ms-sql-dac,ms-sql-dump-hashes,ms-sql-empty-password,ms-sql-hasdbaccess,ms-sql-ntlm-info,ms-sql-query,ms-sql-tables,ms-sql-xp-cmdshell";;

    # common ports vnc-http, vnc 5800, 5900
    "vnc-http"|"vnc" ) found=1; nmap_script="vuln,vnc-info,vnc-title,realvnc-auth-bypass";;
  esac

### PRE UDP BUILD OUT
  #BUILDOUT FOR UDP INCLUSION
  # if [ $protocol = "udp" ]
  # then
  #  case in $each_service
  #    "snmp"|"smux" ) echo "perform udp snmp operations here"
  # SNMP port 161 tcp/udp also add $protocol flag for tcp or udp
  # -- work in progress -- need to add a detection flag for udp or just force a udp scan 1 time
  # all scripts : snmp-brute snmp-hh3c-logins snmp-info snmp-interfaces
  # snmp-ios-config snmp-netstat snmp-processes snmp-sysdescr snmp-win32-services
  # snmp-win32-shares snmp-win32-software snmp-win32-users
  # "snmp"|"smux" ) found=1; scan_options="-sU" nmap_script="snmp-brute snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"
  # snmp-info,snmp-interfaces,snmp-ios-config,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users";;
  # other snmp types :
  # "snmptrap"|"synotic-relay"|"snmp-tcp-port"|"oce-snmp-trap" \
  #"squid-snmp"|"websphere-snmp"|"snmpssh"|"patrol-snmp"|"snmptls"|"snmpdtls" \
  #"snmptls-trap"|"snmpdtls-trap"|"suncacao-snmp"
  #  esac

  # catch-all if service is not found set nmap_script to vuln
  [[ $found = 0 ]] && nmap_script="vuln"

  # MAIN FUNCTION OF DEEP_SCAN
  current_date=$(date +%x)
  current_time=$(date +%X)
  echo -e "\n  $greenplus Performing Deep Scan : $getip Port: $each_port"
  echo -e "\n----------------------------------------------------------------------------"
  echo -e "  + Target IP         : $each_ip                   $current_date $current_time"
  echo -e "  + Found Ports       : $ports"
  echo -e "  + Deep Scannning    : $each_port"
  echo -e "  + Service Detected  : $each_service"
  echo -e "  + Nmap Scripts      : $nmap_script"
  echo -e "  + Scan Logfile      : $each_ip/$each_port/$each_port(.nmap .gnmap .xml)"
  echo -e "----------------------------------------------------------------------------"

  # UNCOMMENT FOR SANITY CHECK
  # echo -e "  TURN ME OFF! Running: nmap $pingprobe $scan_options -p$each_port --script $nmap_script $each_ip -oA $logging \n"
  # COMMENT OUT FOR SANITY CHECK
  # echo -e "max timeout is $max_timeout"
  echo -e "\n  [++] Background scan of $each_ip on $each_port - Notification sent to screen when complete"
  nmap $pingprobe $scan_options -p$each_port --script $nmap_script $each_ip -oA $logging >/dev/null 2>&1 && echo -e "\n  [++] Scan complete of $each_ip on port $each_port see $logging" &

  # check for failed scan and rerun scan
  # while check_for_fail = 1 increment snooze_button by a value of $snooze_increment each loop and sleep for that value
  # This could be its own function
  check_for_fail=$(cat $logging.nmap | grep -c "1 IP address (0 hosts up)")
  snooze_button=0
   while [ $check_for_fail = 1 ]
    do
      snooze_button=$((snooze_button+$snooze_increment))
      echo -e "\n  $redexclaim Fail2Ban Detected or Scan Failed... Sleeping for : $snooze_button"
      sleep $snooze_button
      # echo " SANITY CHECK ON WHILE LOOP : "
      # echo "nmap $pingprobe $scan_options -p$each_port --script $nmap_script $each_ip -oA $logging"
      echo -e "\n  $greenplus Attempting rescan on $each_ip port $each_port "
      nmap $pingprobe $scan_options -p$each_port --script $nmap_script $each_ip -oA $logging 
       if [ $snooze_button = $maxsleep ]
         then
          check_for_fail=0
          echo -e "\n  $redminus Maximum attempts reached - Aborting scan of : $each_ip on $each_port"
       else
         check_for_fail=$(cat $logging.nmap | grep -c "1 IP address (0 hosts up)")
       fi
    done

  echo -e "\n  $greenplus Scan Completed $each_ip on port $each_port"

  # add case based enumeration here / problem adding it here would result in multiple enum4linux runs
  # multiple http/https runs
  # case $each_service in
  # "ftp" ) found=1; nmap_script="vuln,ftp-anon,ftp-proftpd-backdoor,ftp-vsftpd-backdoor";;
  # for i in $(find ./ -name 139 -o -name 445 -o -name 636 | cut -d "/" -f2); do echo $i | sort -u ;done > smb-servers.txt
  # "msrpc"|"rpcbind"|"ldap"|"netbios-ssn"|"microsoft-ds" ) found=1; nmap_script="vuln,smb-os-discovery,smb-enum-domains,smb-enum-groups,smb-enum-users,smb-enum-shares";;
  # esac

  # reset vars to blank or 0 after each run of the loop
  check_for_fail=0
  nmap_script=""
  logging=""
  scan_options=""
  found=0
  }


# --- MAIN ---
  # house keeping before start of script
  [[ -f $tcp_sorted ]] && rm -f $tcp_sorted
  [[ -f $nmap_found ]] && rm -f $nmap_found
  [[ -f $found_port ]] && rm -f $found_port
  [[ -f $found_service ]] && rm -f $found_service
  [[ -f $skipped ]] && rm -f $skipped

  # check if $1 is blank, if so display help
  # add a if EUID = 0 check for root, most of these scripts are going to require root privs
  if [[ "$1" == "" ]]
   then
    echo -e "\n  scriptname (whateverfile.sh)"
    echo -e "\n  Single Ip"
    echo -e "  usage : ./bettermap.sh ip.address.goes.here sleeptimeinseconds\n"
    echo -e "\n  CIDR"
    echo -e "  usage : ./bettermap.sh ip.address.goes.here/cidr sleeptimeinseconds\n"
    echo -e "\n  Ip Range"
    echo -e "  usage ; ./bettermap.sh ip.address.goes.here-range sleeptimeinseconds\n"
    echo -e "\n  IP List"
    echo -e "  usage : ./bettermap.sh filename.txt sleeptimeinseconds\n"
    echo -e "\n  IP List" 
    echo -e "  usage : ./bettermap.sh filename.list sleeptimeinseconds\n"
    exit
   else
    # GETIP FUNCTION (this could be a function by itself)
    # get_work()
    echo -e "\n  $greenplus Gathering all info on $1 "

    # Get IP's that respond
    case "$1" in
    *.*.*.*/*) echo -e "\n /CIDR Detected \n"; nmap -sn $1 | grep -i "report for" | cut -d " " -f5 > $nmap_found;;
    *.*.*.*-*) echo -e "\n IP Range Detected \n"; nmap -sn $1 | grep -i "report for" | cut -d " " -f5 > $nmap_found;;
      *.*.*.*) echo -e "\n Single IP Detected"; nmap -sn $1 | grep -i "report for" | cut -d " " -f5 > $nmap_found;;
        *.txt) echo -e "\n File Detected $1"; nmap -iL $1 -sn | grep -i "report for" | cut -d " " -f5 > $nmap_found;;
       *.list) echo -e "\n List Detected $1"; nmap -iL $1 -sn | grep -i "report for" | cut -d " " -f5 > $nmap_found;;
    esac

#    nmap -sn $1 | grep -i "report for" | cut -d " " -f5 > $nmap_found
    gofind=$(cat $nmap_found)

    # garbage can remove
    detected_machines=$(cat $nmap_found | wc -l)
    echo -e "\n  $greenplus Detected Addresses : $detected_machines"

    if [ $detected_machines = 0 ]
    then
      echo -e "\n  $redexclaim Whoa! there is something seriously wrong here, I have no IP List"
      exit
    else
      echo > /dev/null
    fi

    # GETPORTS FUNCTION FOR-LOOP (this could be a function by itself)
    # get_ports()
    for each_found in $gofind; do
      # on screen display
      echo -e "\n  $greenplus Found : $each_found ... [ detecting ports ] "

      # build portlist per ip
      tcp_current_find=$(nmap -p- --host-timeout 201 --max-retries 0 --min-rate=1000 -T4 $each_found | grep '^[0-9]*/tcp' | cut -d "/" -f1 | tr "\n" "," | sed s/.$//)
      udp_current_find=$(nmap -sU --top-ports 20 -v $each_found | grep '^[0-9]*/udp' | cut -d "/" -f1 | tr "\n" "," | sed s/.$//)

      # - will produce same result as tcp_current_find, although this is UDP were talking about here snmp and smux is about all
      # - we really want out of this at this time. grep for only those specific services? case in case?

      # check to see if there are no ports , if current_find = ""
      # sleep 60 , then retry with -Pn
      # otherwise proceed as normal
      if [[ $tcp_current_find = "" ]]
       then
        echo -e "       $redexclaim No ports found on $each_found... skipping "
        echo -e "       $redplus Reattempting $each_ip with -Pn after 60 second delay"
        sleep 60
        tcp_current_find_retry=$(nmap -Pn -p- --host-timeout 201 --max-retries 0 --min-rate=1000 -T4 $each_found | grep '^[0-9]*/tcp' | cut -d "/" -f1 | tr "\n" "," | sed s/.$//g)
         if [[ $tcp_current_find_retry = "" ]]
          then
           echo -e "\n      $redexclaim Retry attempt failed.. giving up on $each_ip"
           echo "$each_found" >> $skipped
         else
           echo -e "\n       $greenplus Retry succeeded!"
           echo -e "       Ports: $tcp_current_find_retry"
           # add :P after to note this ip needs -Pn in the future
           echo "$each_found:$tcp_current_find_retry:P" >> $tcp_sorted
         fi
      else
        echo -e "       Ports : $tcp_current_find"
        echo "$each_found:$tcp_current_find" >> $tcp_sorted
      fi
    done

    # build out another function here for udp_current_find set variable protocol="udp" and pass $protocol to function

    # copy the sorted list somewhere for safe keeping
    cat $tcp_sorted > ip-and-portlist.list

    # MAIN LOOP FUNCTION
    iplist=$(cat $tcp_sorted | cut -d ":" -f1)

    for getip in $iplist; do
      # [[ ! -f $getip/$getip.udp_service.scan ]] && mkdir $getip; $udp_current_find > $getip/$getip.udp_service.scan
      check_for_pn_switch=$(cat $tcp_sorted | grep $getip | grep -c P)
      if [[ $check_for_pn_switch = 1 ]]
        then
          # check_for_pn_switch = 1
          ports=$(cat $tcp_sorted | grep --max-count=1 "$getip" | cut -d ":" -f2)
          pingprobe="-Pn"
          # UNCOMMENT FOR SANITY CHECK
          # echo -e "SANITY CHECK: service_scan $getip $ports $sleeptimer $pingprobe"
          # COMMENT OUT FOR SANITY CHECK
          service_scan $getip $ports $sleeptimer $pingprobe
          pingprobe=""
          check_for_pn_switch=0
        else
          # check_for_pn_switch = 0
          ports=$(cat $tcp_sorted | grep --max-count=1 "$getip"| cut -d ":" -f2)
          pingprobe=""
          # UNCOMMENT FOR SANITY CHECK
          # echo "SANITY CHECK: service_scan $getip $ports $sleeptimer $pingprobe"
          # COMMENT OUT FOR SANITY CHECK
          service_scan $getip $ports $sleeptimer $pingprobe
          check_for_pn_switch=0
      fi
      check_for_pn_switch=0
    done

    # Honestly for the little we are going to be doing with UDP, this hardly seems to be worh the effort
    #  build out udp function here to pass to service scan $getip $ports $sleeptimer $protocol

    # END OF SCRIPT HOUSE KEEPING
    # [[ -f $skipped ]] && echo -e "\n  $redexclaim Addresses that were skipped..."; cat $skipped; cp -f $skipped skipped.list; || echo > /dev/null
    [[ -f $tcp_sorted ]] && rm -f $tcp_sorted
    [[ -f $nmap_found ]] && rm -f $nmap_found
    [[ -f $found_port ]] && rm -f $found_port
    [[ -f $found_service ]] && rm -f $found_service
    [[ -f $skipped ]] && rm -f $skipped
  fi
