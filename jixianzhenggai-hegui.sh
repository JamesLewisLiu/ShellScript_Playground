#!/bin/bash
DATE=$(date +%F-%T)
OLD_IFS=$IFS
#IFS=$'\n'

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

VSFTP(){
#banner
if [[ $(_get_equal_value $FTPCONF 'ftpd_banner') != "\"Authorized users only. All activity may be monitored and reported.\"" ]];then sed -i '/^ftpd_banner/d;/^#ftpd_banner/aftpd_banner="Authorized users only. All activity may be monitored and reported."' $FTPCONF;fi
if [[ $(_check_string_if_exist $FTPCONF 'ftpd_banner') -eq 1 ]];then sed -i '/^#ftpd_banner/aftpd_banner="Authorized users only. All activity may be monitored and reported."' $FTPCONF;fi
#anonymous_enable=NO
if [[ $(_check_string_if_exist $FTPCONF 'anonymous_enable') -eq 1 ]];then sed -i '$aanonymous_enable=NO' $FTPCONF;fi
if [[ $(_get_equal_value $FTPCONF 'anonymous_enable'|tr 'a-z' 'A-Z') != "NO" ]];then sed -i '/^anonymous_enable/s/YES/NO/g;/^anonymous_enable/s/yes/NO/g;' $FTPCONF;fi
#userlist_enable=YES
if [[ $(_check_string_if_exist $FTPCONF 'userlist_enable') -eq 1 ]];then sed -i '$auserlist_enable=YES' $FTPCONF;fi
if [[ $(_get_equal_value $FTPCONF 'userlist_enable'|tr 'a-z' 'A-Z') != "YES" ]];then sed -i '/^userlist_enable/s/NO/YES/g;/^userlist_enable/s/no/YES/g;' $FTPCONF;fi
#userlist define
if [ ! -f /etc/vsftpd/user_list ];then printf "# vsftpd userlist\n# If userlist_deny=NO, only allow users in this file\n# If userlist_deny=YES (default), never allow users in this file, and\n# do not even prompt for a password.\n# Note that the default vsftpd pam config also checks /etc/vsftpd/ftpusers\n# for users that are denied.\nroot\nbin\ndaemon\nadm\nlp\nsync\nshutdown\nhalt\nmail\nnews\nuucp\noperator\ngames\nnobody\n" | tee /etc/vsftpd/user_list &>/dev/null;fi
if [ ! -f /etc/vsftpd/ftpusers ];then printf "# Users that are not allowed to login via ftp\nroot\nbin\ndaemon\nadm\nlp\nsync\nshutdown\nhalt\nmail\nnews\nuucp\noperator\ngames\nnobody\n" | tee /etc/vsftpd/ftpusers &>/dev/null;fi
#userlist_file=/etc/vsftpd/user_list
if [[ $(_check_string_if_exist $FTPCONF 'userlist_file') -eq 1 ]];then sed -i '/^userlist_enable/auserlist_file=/etc/vsftpd/user_list' $FTPCONF;fi
if [[ $(_get_equal_value $FTPCONF 'userlist_file') != "/etc/vsftpd/user_list" ]];then sed -i '/^userlist_file=/d;/^userlist_enable/auserlist_file=/etc/vsftpd/user_list' $FTPCONF;fi
#chroot_local_user=YES
if [[ $(_check_string_if_exist $FTPCONF 'chroot_local_user') -eq 1 ]];then sed -i '/^chroot_local_user/s/^/#/g;/chroot_local_user=/achroot_local_user=YES' $FTPCONF;fi
if [[ $(_get_equal_value $FTPCONF 'chroot_local_user'|tr 'a-z' 'A-Z') != "YES" ]];then sed -i '/^chroot_local_user/s/NO/YES/g;/^chroot_local_user/s/no/YES/g;' $FTPCONF;fi
#ls_recurse_enable=YES
if [[ $(_check_string_if_exist $FTPCONF 'ls_recurse_enable') -eq 1 ]];then sed -i '/^ls_recurse_enable/s/^/#/g;/ls_recurse_enable=/als_recurse_enable=YES' $FTPCONF;fi
if [[ $(_get_equal_value $FTPCONF 'ls_recurse_enable'|tr 'a-z' 'A-Z') != "YES" ]];then sed -i '/^ls_recurse_enable/s/NO/YES/g;/^ls_recurse_enable/s/no/YES/g;' $FTPCONF;fi
#local_umask=022
if [[ $(_check_string_if_exist $FTPCONF 'local_umask') -eq 1 ]];then sed -i '/^#local_umask=/alocal_umask=022' $FTPCONF;fi
if [[ $(_get_equal_value $FTPCONF 'local_umask') != "022" ]];then sed -i 's/^local_umask=.*/local_umask=022/g' $FTPCONF;fi
#anon_umask=022
if [[ $(_check_string_if_exist $FTPCONF 'anon_umask') -eq 1 ]];then sed -i '/^local_umask=/aanon_umask=022' $FTPCONF;fi
if [[ $(_get_equal_value $FTPCONF 'anon_umask') != "022" ]];then sed -i 's/^anon_umask=.*/anon_umask=022/g' $FTPCONF;fi
}

#Execute Area
#检测是否存在/var/log/cron，若无则创建
if [[ -e /var/log/cron ]];then chmod 775 /var/log/cron;else touch /var/log/cron;chmod 775 /var/log/cron;fi
#检测是否存在/etc/syslog-ng，若无则创建
if [[ ! -e /etc/syslog-ng ]];then mkdir /etc/syslog-ng;echo '/etc/syslog-ng does not exist,created.';else echo '/etc/syslog-ng exist,skipped.';fi
if [[ ! -e /etc/syslog-ng/syslog-ng.conf ]];then touch /etc/syslog-ng/syslog-ng.conf;echo '/etc/syslog-ng/syslog-ng.conf does not exist,created.';else echo '/etc/syslog-ng/syslog-ng.conf exist,skipped.';fi
if [[ ! -e /etc/syslog.conf ]];then touch /etc/syslog.conf;echo '/etc/syslog.conf does not exist,created.';else echo '/etc/syslog.conf exist,skipped.';fi
if [[ ! -e /etc/rsyslog.conf ]];then touch /etc/rsyslog.conf;echo '/etc/rsyslog.conf does not exist,created.';else echo '/etc/rsyslog.conf exist,skipped.';fi
#检测/etc/syslog-ng/syslog-ng.conf、/etc/syslog.conf和/etc/rsyslog.conf中是否存在'192.168.0.1'，若无则追加。
if [[ $(_check_string_if_exist /etc/syslog-ng/syslog-ng.conf '192.168.0.1') -eq 1 ]];then printf "*.*\t@192.168.0.1\n"|tee -a /etc/syslog-ng/syslog-ng.conf &>/dev/null;fi
if [[ $(_check_string_if_exist /etc/syslog.conf '192.168.0.1') -eq 1 ]];then printf "*.*\t@192.168.0.1\n"|tee -a /etc/syslog.conf &>/dev/null;fi
if [[ $(_check_string_if_exist /etc/rsyslog.conf '192.168.0.1') -eq 1 ]];then cp /etc/rsyslog.conf /etc/rsyslog.conf-$DATE;sed -i '$a*.*\t@192.168.0.1\n' /etc/rsyslog.conf;fi
#检测/etc/syslog-ng/syslog-ng.conf、/etc/syslog.conf和/etc/rsyslog.conf中是否存在'authpriv.info'，若无则追加。
if [[ $(_check_string_if_exist /etc/syslog-ng/syslog-ng.conf 'authpriv.info') -eq 1 ]];then printf "authpriv.info\t/var/log/authlog\n"|tee -a /etc/syslog-ng/syslog-ng.conf &>/dev/null;fi
if [[ $(_check_string_if_exist /etc/syslog.conf 'authpriv.info') -eq 1 ]];then printf "authpriv.info\t/var/log/authlog\n"|tee -a /etc/syslog.conf &>/dev/null;fi
if [[ $(_check_string_if_exist /etc/rsyslog.conf 'authpriv.info') -eq 1 ]];then sed -i '$aauthpriv.info\t/var/log/authlog\n' /etc/rsyslog.conf;fi
#检测/etc/syslog-ng/syslog-ng.conf、/etc/syslog.conf和/etc/rsyslog.conf中是否存在'/var/log/cron'，若无则追加。
if [[ $(_check_string_if_exist /etc/syslog-ng/syslog-ng.conf '/var/log/cron') -eq 1 ]];then printf "cron.*\t/var/log/cron\n"|tee -a /etc/syslog-ng/syslog-ng.conf &>/dev/null;fi
if [[ $(_check_string_if_exist /etc/syslog.conf '/var/log/cron') -eq 1 ]];then printf "cron.*\t/var/log/cron\n"|tee -a /etc/syslog.conf &>/dev/null;fi
if [[ $(_check_string_if_exist /etc/rsyslog.conf '/var/log/cron') -eq 1 ]];then sed -i '$acron.*\t/var/log/cron\n' /etc/rsyslog.conf;fi
#检测/etc/syslog-ng/syslog-ng.conf中是否存在'相关参数'，若无则追加。
if [[ -e /etc/syslog-ng/syslog-ng.conf ]];then cp /etc/syslog-ng/syslog-ng.conf /etc/syslog-ng/syslog-ng.conf-bak-$DATE;else printf '$adestination logserver { udp("10.10.10.10" port(514)); };log { source(src); destination(logserver); };\n' | tee /etc/syslog-ng/syslog-ng.conf &>/dev/null;fi
if [[ $(_check_string_if_exist /etc/syslog-ng/syslog-ng.conf 'destination') -eq 1 ]];then sed -i '$adestination logserver { udp("10.10.10.10" port(514)); };log { source(src); destination(logserver); };' /etc/syslog-ng/syslog-ng.conf;fi

#创建/etc/hosts.allow、/etc/hosts.deny，并添加条目
printf "all:0.0.0.0:allow\nsshd:0.0.0.0:allow\nall:10.0.0.0:allow\nsshd:10.0.0.0:allow\n"|tee /etc/hosts.allow &>/dev/null;
printf "all:all:deny\n"|tee /etc/hosts.deny &>/dev/null;

#直接备份，注释原有的umask并追加新的umask 027进环境配置文件。
PROFILE="/etc/profile /etc/csh.login /etc/csh.cshrc /etc/bashrc /root/.bashrc /root/.cshrc"
for a in $PROFILE;do if [[ -e $a ]];then IFS=$'\n';if [[ $(_check_string_if_exist /etc/profile '^umask 027') -eq 1 ]];then cp -p $a $a-bak-umask-$DATE;sed -i '/^umask/s/^/#/g;/002/s/#//;/022/s/#//;/027/s/#//;$aumask 027' $a;IFS=$OLD_IFS;fi;fi;done

IFS=$'\n'
#/etc/profile
if [[ $(_check_string_if_exist /etc/profile 'TMOUT=180') -eq 1 ]];then SED_ADD_LL 'TMOUT=180' /etc/profile;fi
if [[ $(_check_string_if_exist /etc/profile 'export TMOUT') -eq 1 ]];then sed -i '/TMOUT=180/aexport TMOUT' /etc/profile;fi
if [[ $(_check_string_if_exist /etc/profile 'autologout=30') -eq 1 ]];then SED_ADD_LL 'set autologout=30' /etc/profile;fi
if [[ $(_check_string_if_exist /etc/profile '^umask 027') -eq 1 ]];then SED_ADD_LL 'umask 027' /etc/profile;fi
#csh.cshrc
if [ -f /etc/csh.cshrc ];then if [[ $(_check_string_if_exist /etc/csh.cshrc 'TMOUT=180') -eq 1 ]];then SED_ADD_LL 'TMOUT=180' /etc/csh.cshrc;fi;if [[ $(_check_string_if_exist /etc/csh.cshrc 'export TMOUT') -eq 1 ]];then sed -i '/TMOUT=180/aexport TMOUT' /etc/csh.cshrc;fi;if [[ $(_check_string_if_exist /etc/csh.cshrc 'autologout=30') -eq 1 ]];then SED_ADD_LL 'set autologout=30' /etc/csh.cshrc;fi;fi;
IFS=$OLD_IFS

#备份并修改/etc/login.defs相关参数
cp -p /etc/login.defs /etc/login.defs-bak-$DATE;
if [[ $(_check_string_if_exist /etc/login.defs 'PASS_MAX_DAYS') -eq 1 ]];then sed -i '$aPASS_MAX_DAYS\t 90' /etc/login.defs;else if [[ $(_get_space_value /etc/login.defs 'PASS_MAX_DAYS') != "90" ]];then sed -i '/^PASS_MAX_DAYS/s/^/#/g;/^#PASS_MAX_DAYS/aPASS_MAX_DAYS\t 90' /etc/login.defs;fi;fi
if [[ $(_check_string_if_exist /etc/login.defs 'PASS_MIN_DAYS') -eq 1 ]];then sed -i '$aPASS_MIN_DAYS\t 1' /etc/login.defs;else if [[ $(_get_space_value /etc/login.defs 'PASS_MIN_DAYS') != "1" ]];then sed -i '/^PASS_MIN_DAYS/s/^/#/g;/^#PASS_MIN_DAYS/aPASS_MIN_DAYS\t 1' /etc/login.defs;fi;fi
if [[ $(_check_string_if_exist /etc/login.defs 'PASS_MIN_LEN') -eq 1 ]];then sed -i '$aPASS_MIN_LEN\t 8' /etc/login.defs;else if [[ $(_get_space_value /etc/login.defs 'PASS_MIN_LEN') != "8" ]];then sed -i '/^PASS_MIN_LEN/s/^/#/g;/^#PASS_MIN_LEN/aPASS_MIN_LEN\t 8' /etc/login.defs;fi;fi
if [[ $(_check_string_if_exist /etc/login.defs 'LASTLOG_ENAB') -eq 1 ]];then sed -i '$aLASTLOG_ENAB\t yes' /etc/login.defs;else if [[ $(_get_space_value /etc/login.defs 'LASTLOG_ENAB') != "yes" ]];then sed -i '/^LASTLOG_ENAB/s/^/#/g;/^#LASTLOG_ENAB/aLASTLOG_ENAB\t yes' /etc/login.defs;fi;fi
if [[ $(_check_string_if_exist /etc/login.defs 'FAILLOG_ENAB') -eq 1 ]];then sed -i '$aFAILLOG_ENAB\t yes' /etc/login.defs;else if [[ $(_get_space_value /etc/login.defs 'FAILLOG_ENAB') != "yes" ]];then sed -i '/^FAILLOG_ENAB/s/^/#/g;/^#FAILLOG_ENAB/aFAILLOG_ENAB\t yes' /etc/login.defs;fi;fi

#系统Banner相关
if [[ -e /etc/motd ]];then if [[ $(_check_string_if_exist /etc/motd 'Authorized users only. All activity may be monitored and reported.') -eq 1 ]];then printf "Authorized users only. All activity may be monitored and reported.\n"|tee /etc/motd &>/dev/null;echo '/etc/motd is empty,modified.';else echo '/etc/motd is good,skip';fi;else echo '/etc/motd is not exist,skipped.';fi

if [[ $(_check_string_if_exist /etc/ssh/sshd_config 'Banner') -eq 1 ]];then cp /etc/ssh/sshd_config /etc/ssh/sshd_config-$DATE;sed -i '/#Banner/aBanner /etc/motd' /etc/ssh/sshd_config;fi
find / -maxdepth 3 -name hosts.equiv|xargs -I {} mv {} {}-bak-$DATE
if [[ -e /etc/issue ]];then mv /etc/issue /etc/issue-bak-$DATE;fi
if [[ -e /etc/issue.net ]];then mv /etc/issue.net /etc/issue-net-bak-$DATE;fi

#内核参数相关
#bak
cp -p /etc/sysctl.conf /etc/sysctl.conf-bak-$DATE;
#Add if not exist
if [[ $(_check_string_if_exist /etc/sysctl.conf 'net.ipv4.conf.all.accept_redirects') -eq 1 ]];then SED_ADD_LL 'net.ipv4.conf.all.accept_redirects = 0' /etc/sysctl.conf;fi
if [[ $(_check_string_if_exist /etc/sysctl.conf 'net.ipv4.conf.all.rp_filter') -eq 1 ]];then SED_ADD_LL 'net.ipv4.conf.all.rp_filter = 0' /etc/sysctl.conf;fi
if [[ $(_check_string_if_exist /etc/sysctl.conf 'net.ipv4.conf.default.rp_filter') -eq 1 ]];then SED_ADD_LL 'net.ipv4.conf.default.rp_filter = 0' /etc/sysctl.conf;fi
#Mod if value is not fulfilled
if [[ $(_get_equal_value /etc/sysctl.conf 'net.ipv4.conf.all.accept_redirects') != "0" ]];then sed -i '/^net.ipv4.conf.all.accept_redirects/s/^/#/g;/^#net.ipv4.conf.all.accept_redirects/anet.ipv4.conf.all.accept_redirects = 0' /etc/sysctl.conf;fi
if [[ $(_get_equal_value /etc/sysctl.conf 'net.ipv4.conf.all.rp_filter') != "0" ]];then sed -i '/^net.ipv4.conf.all.rp_filter/s/^/#/g;/^#net.ipv4.conf.all.rp_filter/anet.ipv4.conf.all.rp_filter = 0' /etc/sysctl.conf;fi
if [[ $(_get_equal_value /etc/sysctl.conf 'net.ipv4.conf.default.rp_filter') != "0" ]];then sed -i '/^net.ipv4.conf.default.rp_filter/s/^/#/g;/^#net.ipv4.conf.default.rp_filter/anet.ipv4.conf.default.rp_filter = 0' /etc/sysctl.conf;fi

sysctl -p;

#系统文件权限相关
for a in $(find /etc/passwd /etc/shadow /etc/group);do cp -p $a $a-bak-$DATE;done
chmod 0644 /etc/passwd;chmod 0400 /etc/shadow;chmod 0644 /etc/group

cp -p /etc/pam.d/su /etc/pam.d/su-bak-$DATE;sed -i '/auth\t\tsufficient\tpam_rootok.so/aauth\t\trequired\tpam_wheel.so group=wheel\nauth\t\trequired\tpam_wheel.so use_uid' /etc/pam.d/su;

IFS=$'\n'
cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth-bak-$DATE;
if [[ $(_check_string_if_exist /etc/pam.d/system-auth 'dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minclass=3 minlen=8 enforce_for_root') -eq 1 ]];then sed -i '/password    requisite/apassword    requisite     pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minclass=3 minlen=8 enforce_for_root' /etc/pam.d/system-auth;fi
IFS=$OLD_IFS

if [[ $(_check_string_if_exist /etc/pam.d/system-auth 'remember=5') -eq 1 ]];then sed -i '/password    sufficient    pam_unix.so/s/$/ remember=5/' /etc/pam.d/system-auth;fi

if [[ -e /etc/logrotate.d/syslog ]];then cp -p /etc/logrotate.d/syslog /etc/logrotate.d/syslog-bak-$DATE;sed -i '/missingok/a\    size 10M' /etc/logrotate.d/syslog;fi

printf 'console\nvc/1\nvc/2\nvc/3\nvc/4\nvc/5\nvc/6\nvc/7\nvc/8\nvc/9\nvc/10\nvc/11\ntty1\ntty2\ntty3\ntty4\ntty5\ntty6\ntty7\ntty8\ntty9\ntty10\ntty11\nttyS0\nttysclp0\nsclp_line0\n3270/tty1\nhvc0\nhvc1\nhvc2\nhvc3\nhvc4\nhvc5\nhvc6\nhvc7\nhvsi0\nhvsi1\nhvsi2\nxvc0\n'|tee /etc/securetty &>/dev/null;chmod 0600 /etc/securetty

#Add and Remove packages
#yum -y remove $(rpm -qa |egrep "\btcpdump\b|\bgdb\b|\bstrace\b|\bdexdump\b|^\bcpp\b|\bgcc\b|\bwireshark\b|\bethereal\b|\bgcc3\b|\bgcc3-c++\b|\b gcc3-g77\b|\bgcc3-java\b|\bgcc3-objc\b|\bgcc-c++\b|\bgcc-chill\b|\bgcc-g77\b|\bgcc-java\b|\bgcc-objc\b|\bbin86\b|\bdev86\b|\bnasm\b")
#yum -y install tar unzip zip zstd binutils net-tools;

#关闭SSH的root直连
#cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config-bak-$DATE;sed -i '/PermitRootLogin/s/yes/no/' /etc/ssh/sshd_config;systemctl restart sshd;

if [[ $(_check_string_if_exist /etc/ssh/sshd_config 'PermitTunnel') -eq 1 ]];then sed -i '/#PermitTunnel/aPermitTunnel no' /etc/ssh/sshd_config;fi
#添加SSHD安全算法
if [[ $(_check_string_if_exist /etc/ssh/sshd_config 'Ciphers') -eq 1 ]];then sed -i '/#RekeyLimit default none/aCiphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1\nMACs umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\n' /etc/ssh/sshd_config;fi

#关闭snmp服务，以合规
systemctl disable --now snmpd

#卸载ftp，避嫌
#yum -y remove $(rpm -qa|grep ftp)

#vsftp相关
if [ -f /etc/vsftpd.conf ];then FTPCONF="/etc/vsftpd.conf";VSFTP;elif [ -f /etc/vsftpd/vsftpd.conf ];then FTPCONF="/etc/vsftpd/vsftpd.conf";VSFTP;fi
#else exit;fi;

#Self delete after execution
#rm -- "$0"