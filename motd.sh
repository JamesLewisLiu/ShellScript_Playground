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

#系统Banner相关
IFS=$'\n'
if [[ -e /etc/motd ]];then if [[ $(_check_string_if_exist /etc/motd 'Authorized users only. All activity may be monitored and reported.') -eq 1 ]];then printf "Authorized users only. All activity may be monitored and reported.\n"|tee /etc/motd &>/dev/null;echo '/etc/motd is empty,modified.';else echo '/etc/motd is good,skip';fi;else printf "Authorized users only. All activity may be monitored and reported.\n"|tee /etc/motd &>/dev/null;echo '/etc/motd is not exist,created.';fi;
if [[ $(_check_string_if_exist /etc/ssh/sshd_config 'Banner /etc/motd') -eq 1 ]];then cp /etc/ssh/sshd_config /etc/ssh/sshd_config-$DATE;sed -i '/^#Banner/aBanner /etc/motd' /etc/ssh/sshd_config;else if [[ $(_get_space_value /etc/ssh/sshd_config 'Banner') != "/etc/motd" ]];then sed -i '/^Banner/d;/^#Banner/aBanner /etc/motd' /etc/ssh/sshd_config;fi;fi
IFS=$OLD_IFS

systemctl disable --now update-motd
