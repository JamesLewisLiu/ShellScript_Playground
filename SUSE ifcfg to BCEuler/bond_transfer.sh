#!/bin/bash
if [[ -d /proc/net/bonding ]];then
        echo "Found nic bond,processing..."
        for BOND in $(find /proc/net/bonding -type f)
        do
                MASTER=$(awk -F/ '{print$NF}' <<< $BOND)
                MASTERIP=$(ip -4 addr show $MASTER | grep inet | head -n1 | awk '{print$2}' | awk -F/ '{print$1}')
                MASTERPFX=$(ip -4 addr show $MASTER | grep inet | head -n1 | awk '{print$2}' | awk -F/ '{print$2}')
                MASTERGW=$(ip route | grep default | awk '{print$3}')
                MASTERUUID=$(uuidgen)
                echo "Converting ifcfg of $MASTER..."
                for SLAVE in $(cat $BOND | grep "Slave Interface" | awk '{print$NF}')
                do
					printf "TYPE=Ethernet\nNAME=$MASTER"_slave_"$SLAVE\nUUID=$(uuidgen)\nONBOOT=yes\nMASTER=$MASTER\nSLAVE=yes\nMASTER_UUID=$MASTERUUID\n"|tee /root/ifcfg-"$MASTER"_slave_"$SLAVE" &>/dev/null
				done
                if [[ $(ip r|grep $MASTER|grep default &>/dev/null;echo $?) -eq 0 ]];then 
					if [[ $(cat $BOND|grep 'Bonding Mode:') == 'Bonding Mode: IEEE 802.3ad Dynamic link aggregation' ]];then 
						printf "BONDING_OPTS=\"mode=802.3ad downdelay=0 miimon=100 updelay=0\"\nTYPE=Bond\nBONDING_MASTER=yes\nHWADDR=\nPROXY_METHOD=none\nBROWSER_ONLY=no\nBOOTPROTO=none\nIPADDR=$MASTERIP\nPREFIX=$MASTERPFX\nGATEWAY=$MASTERGW\nDEFROUTE=yes\nIPV4_FAILURE_FATAL=no\nIPV6_DISABLED=yes\nIPV6INIT=no\nNAME=$MASTER\nUUID=$MASTERUUID\nDEVICE=$MASTER\nONBOOT=yes\n" | tee /root/ifcfg-"$MASTER" &>/dev/null;
					elif [[ $(cat $BOND|grep 'Bonding Mode:') == 'Bonding Mode: fault-tolerance (active-backup)' ]];then 
						printf "BONDING_OPTS=\"mode=active-backup downdelay=0 miimon=100 updelay=0\"\nTYPE=Bond\nBONDING_MASTER=yes\nHWADDR=\nPROXY_METHOD=none\nBROWSER_ONLY=no\nBOOTPROTO=none\nIPADDR=$MASTERIP\nPREFIX=$MASTERPFX\nGATEWAY=$MASTERGW\nDEFROUTE=yes\nIPV4_FAILURE_FATAL=no\nIPV6_DISABLED=yes\nIPV6INIT=no\nNAME=$MASTER\nUUID=$MASTERUUID\nDEVICE=$MASTER\nONBOOT=yes\n" | tee /root/ifcfg-"$MASTER" &>/dev/null;
					fi
				else 
					if [[ $(cat $BOND|grep 'Bonding Mode:') == 'Bonding Mode: IEEE 802.3ad Dynamic link aggregation' ]];then 
					printf "BONDING_OPTS=\"mode=802.3ad downdelay=0 miimon=100 updelay=0\"\nTYPE=Bond\nBONDING_MASTER=yes\nHWADDR=\nPROXY_METHOD=none\nBROWSER_ONLY=no\nBOOTPROTO=none\nIPADDR=$MASTERIP\nPREFIX=$MASTERPFX\nGATEWAY=\nDEFROUTE=no\nIPV4_FAILURE_FATAL=no\nIPV6_DISABLED=yes\nIPV6INIT=no\nNAME=$MASTER\nUUID=$MASTERUUID\nDEVICE=$MASTER\nONBOOT=yes\n" | tee /root/ifcfg-"$MASTER" &>/dev/null;
					elif [[ $(cat $BOND|grep 'Bonding Mode:') == 'Bonding Mode: fault-tolerance (active-backup)' ]];then 
					printf "BONDING_OPTS=\"mode=active-backup downdelay=0 miimon=100 updelay=0\"\nTYPE=Bond\nBONDING_MASTER=yes\nHWADDR=\nPROXY_METHOD=none\nBROWSER_ONLY=no\nBOOTPROTO=none\nIPADDR=$MASTERIP\nPREFIX=$MASTERPFX\nGATEWAY=\nDEFROUTE=no\nIPV4_FAILURE_FATAL=no\nIPV6_DISABLED=yes\nIPV6INIT=no\nNAME=$MASTER\nUUID=$MASTERUUID\nDEVICE=$MASTER\nONBOOT=yes\n" | tee /root/ifcfg-"$MASTER" &>/dev/null;
					fi
				fi
				unset MASTER;unset MASTERIP;unset MASTERPFX;unset MASTERGW;unset MASTERUUID;
        done
else
        echo "Cannot find any nic bond,exiting..."
        exit 1
fi