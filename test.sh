#!/bin/bash
OLD_IFS=$IFS
DATE=$(date +%s)
#
#Use for testing only
#Function Area
#$1 is needed checking file,$2 is searching string,example CHECK_STRING_IF_EXIST $FTPCONF 'ftpd_banner'
_check_string_if_exist(){
    grep -v -- '#' $1|grep -- $2 &>/dev/null;echo $?
}
#example GET_EQUAL_VALUE $FTPCONF 'ftpd_banner'
_get_equal_value(){
    grep -v -- '#' $1|grep -- $2|awk -F\= '{gsub(/ = /,"=");print$2}'
}
#example _get_space_value $FILE 'string'
_get_space_value(){
    grep -v -- '#' $1|grep -- $2|awk '{print$2}'
}

#SED
SED_ADD_LL(){
    sed -i "\$a$1" $2
}

if [[ -e /etc/logrotate.d/syslog ]];then printf '/var/log/syslog\n{\n    maxage 365\n    rotate 30\n    notifempty\n    copytruncate\n    missingok\n    size +4096k\n    sharedscriptsendscript\n}\n'|tee /etc/logrotate.d/syslog &>/dev/null ;else printf '/var/log/syslog\n{\n    maxage 365\n    rotate 30\n    notifempty\n    copytruncate\n    missingok\n    size +4096k\n    sharedscriptsendscript\n}\n'|tee /etc/logrotate.d/syslog &>/dev/null;fi


