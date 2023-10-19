#!/bin/bash
DATE=$(date +%F-%T)
OLD_IFS=$IFS
#IFS=$'\n'

_check_string_if_exist(){
    grep -v -- '#' $1|grep -- $2 &>/dev/null;echo $?
}
#example _get_space_value $FILE 'string'
_get_space_value(){
    grep -v -- '#' $1|grep -- $2|awk '{print$2}'
}

cp -p /etc/login.defs /etc/login.defs-bak-$DATE;
if [[ $(_check_string_if_exist /etc/login.defs 'PASS_MAX_DAYS') -eq 1 ]];then sed -i '$aPASS_MAX_DAYS\t 90' /etc/login.defs;else if [[ $(_get_space_value /etc/login.defs 'PASS_MAX_DAYS') != "90" ]];then sed -i '/^PASS_MAX_DAYS/s/^/#/g;/^#PASS_MAX_DAYS/aPASS_MAX_DAYS\t 90' /etc/login.defs;fi;fi

if [[ $(_check_string_if_exist /etc/login.defs 'PASS_MIN_DAYS') -eq 1 ]];then sed -i '$aPASS_MIN_DAYS\t 1' /etc/login.defs;else if [[ $(_get_space_value /etc/login.defs 'PASS_MIN_DAYS') != "1" ]];then sed -i '/^PASS_MIN_DAYS/s/^/#/g;/^#PASS_MIN_DAYS/aPASS_MIN_DAYS\t 1' /etc/login.defs;fi;fi

if [[ $(_check_string_if_exist /etc/login.defs 'PASS_MIN_LEN') -eq 1 ]];then sed -i '$aPASS_MIN_LEN\t 8' /etc/login.defs;else if [[ $(_get_space_value /etc/login.defs 'PASS_MIN_LEN') != "8" ]];then sed -i '/^PASS_MIN_LEN/s/^/#/g;/^#PASS_MIN_LEN/aPASS_MIN_LEN\t 8' /etc/login.defs;fi;fi

if [[ $(_check_string_if_exist /etc/login.defs 'LASTLOG_ENAB') -eq 1 ]];then sed -i '$aLASTLOG_ENAB\t yes' /etc/login.defs;else if [[ $(_get_space_value /etc/login.defs 'LASTLOG_ENAB') != "yes" ]];then sed -i '/^LASTLOG_ENAB/s/^/#/g;/^#LASTLOG_ENAB/aLASTLOG_ENAB\t yes' /etc/login.defs;fi;fi

if [[ $(_check_string_if_exist /etc/login.defs 'FAILLOG_ENAB') -eq 1 ]];then sed -i '$aFAILLOG_ENAB\t yes' /etc/login.defs;else if [[ $(_get_space_value /etc/login.defs 'FAILLOG_ENAB') != "yes" ]];then sed -i '/^FAILLOG_ENAB/s/^/#/g;/^#FAILLOG_ENAB/aFAILLOG_ENAB\t yes' /etc/login.defs;fi;fi

#_get_space_value /etc/login.defs 'PASS_MAX_DAYS'
#_get_space_value /etc/login.defs 'PASS_MIN_DAYS'
#_get_space_value /etc/login.defs 'PASS_MIN_LEN'
#_get_space_value /etc/login.defs 'LASTLOG_ENAB'
#_get_space_value /etc/login.defs 'FAILLOG_ENAB'