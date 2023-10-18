#!/bin/bash
DATE=$(date +%F-%T)
OLD_IFS=$IFS
#IFS=$'\n'
#备份并修改/etc/login.defs相关参数

#example GET_EQUAL_VALUE $FTPCONF 'ftpd_banner'
_get_equal_value(){
    grep -v -- '#' $1|grep -- $2|awk -F\= '{gsub(/ = /,"=");print$2}'
}

cp -p /etc/login.defs /etc/login.defs-bak-$DATE;
if [[ $(_get_equal_value /etc/login.defs 'PASS_MAX_DAYS') != "90" ]];then sed -i '/^PASS_MAX_DAYS/s/^/#/g;/^#PASS_MAX_DAYS/aPASS_MAX_DAYS = 90' /etc/login.defs;fi
if [[ $(_get_equal_value /etc/login.defs 'PASS_MIN_DAYS') != "1" ]];then sed -i '/^PASS_MIN_DAYS/s/^/#/g;/^#PASS_MIN_DAYS/aPASS_MIN_DAYS = 1' /etc/login.defs;fi
if [[ $(_get_equal_value /etc/login.defs 'PASS_MIN_LEN') != "8" ]];then sed -i '/^PASS_MIN_LEN/s/^/#/g;/^#PASS_MIN_LEN/aPASS_MIN_LEN = 8' /etc/login.defs;fi
if [[ $(_get_equal_value /etc/login.defs 'LASTLOG_ENAB') != "yes" ]];then sed -i '/^LASTLOG_ENAB/s/^/#/g;/^#LASTLOG_ENAB/aLASTLOG_ENAB = yes' /etc/login.defs;fi
if [[ $(_get_equal_value /etc/login.defs 'FAILLOG_ENAB') != "yes" ]];then sed -i '/^FAILLOG_ENAB/s/^/#/g;/^#FAILLOG_ENAB/aFAILLOG_ENAB = yes' /etc/login.defs;fi

#sed -i '/PASS_MAX_DAYS/s/99999/90/;/PASS_MIN_DAYS/s/0/1/;/PASS_MIN_LEN/s/5/8/;$aLASTLOG_ENAB\tyes\nFAILLOG_ENAB\tyes\n' /etc/login.defs
