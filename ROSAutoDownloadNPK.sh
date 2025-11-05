# #!/bin/bash
# RSS=$(curl -s https://download.mikrotik.com/routeros/latest-stable-and-long-term.rss | xml sel -t -v rss/channel/item/title -n )
# longterm=$(echo "$RSS" | grep long-term | awk '{print$2}')
# stable=$(echo "$RSS" | grep stable | awk '{print$2}')
# VER=$stable
# ARCH='mmips'
# DST='sata1-part1'
# UPDATE='NO'

# echo $(date) '当前 RouterOS 最新版本为： '$VER' ，准备检查本地已有版本'
# for a in $(curl -s -u admin:123456 http://10.9.0.10/rest/file | jq -r .[]."name" | grep mmips | awk -F- '{print$2}' | sort -V);do if [[ "$a" != "$VER" ]];then UPDATE='YES';else UPDATE='NO';echo $(date) '本地已有最新版本，跳过下载';fi;done

# if [[ "$UPDATE" == "YES" ]];then echo $(date) '本地没有最新版本，准备下载';ssh -t admin@10.9.0.10 "/tool/fetch https://download.mikrotik.com/routeros/$VER/routeros-$VER-$ARCH.npk dst-path=$DST;quit;";fi

# for a in $(curl -s -u admin:123456 http://10.9.0.10/rest/file | jq -r .[]."name" | grep mmips | awk -F- '{print$2}' | sort -V);do if [[ "$a" == "$VER" ]];then echo $(date) '最新版本下载已完成';fi;done

# #Delete, not tested yet.
# #for a in $(curl -s -u admin:123456 http://10.9.0.10/rest/file | jq -r .[]."name" | grep mmips | awk -F- '{print$3}' | sort -V);do if [[ "$a" != "$VER" ]];then ssh -t admin@10.9.0.10 "/file/remove /$DST/routeros-$a-$ARCH.npk dst-path=$DST;quit;";fi;done
#!/bin/bash
RSS=$(curl -s https://download.mikrotik.com/routeros/latest-stable-and-long-term.rss | xml sel -t -v rss/channel/item/title -n )
longterm=$(echo "$RSS" | grep long-term | awk '{print$2}')
stable=$(echo "$RSS" | grep stable | awk '{print$2}')
VER=$stable
ARCH='mmips'
DST='sata1-part1'
UPDATE='YES'

echo $(date) 'Found latest RouterOS version: '$VER' ,checking local stored npk...';
for a in $(curl -s -u admin:123456 http://172.17.0.1/rest/file | jq -r .[]."name" | grep mmips | awk -F- '{print$2}' | sort -V);do if [[ "$a" != "$VER" ]];then UPDATE='YES';else UPDATE='NO';echo $(date) 'Found latest npk,skip downloading...';fi;done

if [[ "$UPDATE" == "YES" ]];then echo $(date) 'Not found latest version npk,downloading...';sshpass -p 123456 ssh -t admin@172.17.0.1 "/tool/fetch https://download.mikrotik.com/routeros/$VER/routeros-$VER-$ARCH.npk dst-path=$DST;quit;";fi

for a in $(curl -s -u admin:123456 http://172.17.0.1/rest/file | jq -r .[]."name" | grep mmips | awk -F- '{print$2}' | sort -V);do if [[ "$a" == "$VER" ]];then echo $(date) 'Latest version npk download finished.';fi;done


#Delete, not tested yet.
#for a in $(curl -s -u admin:123456 http://172.17.0.1/rest/file | jq -r .[]."name" | grep mmips | awk -F- '{print$2}' | sort -V);do if [[ "$a" != "$VER" ]];then sshpass -p 123456 ssh -t admin@$IP "/file/remove /$DST/routeros-$a-$ARCH.npk dst-path=$DST;quit;";fi;done
