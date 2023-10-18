#!/bin/bash


_check_string_if_exist(){
    grep -v -- '#' $1|grep -- $2 &>/dev/null;echo $?
}


PROFILE="/etc/profile /etc/csh.login /etc/csh.cshrc /etc/bashrc /root/.bashrc /root/.cshrc"
for a in $PROFILE;do if [[ -e $a ]];then IFS=$'\n';if [[ $(_check_string_if_exist /etc/profile '^umask 027') -eq 1 ]];then cp -p $a $a-bak-umask-$DATE;sed -i '/^umask/s/^/#/g;/002/s/#//;/022/s/#//;/027/s/#//;$aumask 027' $a;IFS=$OLD_IFS;fi;fi;done
