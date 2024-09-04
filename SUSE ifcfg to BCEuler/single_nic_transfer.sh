#!/bin/bash
if [[ $1 == "" ]] || [[ $1 == "--help" ]] || [[ $1 == "-h" ]]; then printf "Usage(Use eth0 as example):\n./manual eth0\n"; exit 1; fi

MAC=$(ip link show $1 | awk '/ether/ {print$2}' | tr 'a-z' 'A-Z')
IP=$(ip -4 addr show $1 | grep inet | awk '{print$2}' | awk -F/ '{print$1}')
PFX=$(ip -4 addr show $1 | grep inet | awk '{print$2}' | awk -F/ '{print$2}')
GW=$(ip route | grep default | awk '{print$3}')
ID=$(uuidgen)

printf "HWADDR=$MAC\nTYPE=Ethernet\nPROXY_METHOD=none\nBROWSER_ONLY=no\nBOOTPROTO=none\nIPADDR=$IP\nPREFIX=$PFX\nGATEWAY=$GW\nDEFROUTE=yes\nIPV4_FAILURE_FATAL=no\nIPV4_DNS_PRIORITY=100\nIPV6INIT=no\nNAME=$1\nUUID=$ID\nDEVICE=$1\nONBOOT=yes\n" | tee /root/ifcfg-"$1" &>/dev/null

done
