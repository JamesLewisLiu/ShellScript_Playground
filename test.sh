#!/bin/bash
#Use for testing only
#Function
_hyphen_grep(){
	grep -- $1 $2
}

_audit_check(){
	_hyphen_grep $1 /etc/audit/rules.d/audit.rules
}

#AUDIT START
OLD_IFS=$IFS
IFS=$'\n'

_hyphen_grep "-w /etc/sudoers -p wa -k sudo_audit" /etc/audit/rules.d/audit.rules
sleep 15

AUDIT="
-w /etc/sudoers -p wa -k sudo_audit
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k audit_rules_networkconfig_modification
-w /etc/issue -p wa -k audit_rules_networkconfig_modification
-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification
-w /etc/hosts -p wa -k audit_rules_networkconfig_modification
-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification
-w /etc/group -p wa -k audit_rules_usergroup_modification
-w /etc/passwd -p wa -k audit_rules_usergroup_modification
-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
-w /etc/shadow -p wa -k audit_rules_usergroup_modification
-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-w /usr/sbin/insmod -p x -k modules
-w /usr/sbin/rmmod -p x -k modules
-w /usr/sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k audit_time_rules
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k audit_time_rules
-w /etc/localtime -p wa -k audit_time_rules
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k export
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
"
for a in $AUDIT;do _audit_check $a;done
_hyphen_grep '-w /etc/sudoers -p wa -k sudo_audit' /etc/audit/rules.d/audit.rules
IFS=$OLD_IFS
#AUDIT END

