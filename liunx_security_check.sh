#!/bin/bash

###########################################################################
# Check Abnormal User
###########################################################################

#if [ $# -eq 2 ];then
#    if [ -d $1 ] && [ -d $2 ];then
#        WEBCHK=1 
#        WEBDIR=$1
#        LOGDIR=$2
#    else
#        echo "Web dir $1 or $2 error, exit."
#        exit -1
#    fi 
#else
#    WEBCHK=0
#fi
if [ -f /etc/redhat-release ]; then
#	yum -y update
	yum -y install epel-release
	yum -y groupinstall 'Development Tools'
	yum install -y wget git rkhunter unhide clamav
else
	apt-get -y update
	apt-get -y install wget git build-essential rkhunter unhide clamav
fi

echo -e "\033[33m#### 0x1. Check system source use \033[0m"
echo -e "\033[33m|--> Check OS Version \033[0m"
cat /etc/redhat-release
echo -e "\033[33m|--> Check system cpu load \033[0m"
uptime
echo -e "\033[33m|--> Check system mem use \033[0m"
free -g
echo -e "\033[33m|--> Check system network rate use \033[0m"
sar -n DEV 3 1  | grep -vE '^$'
echo -e "\033[33m|--> Check system tool \033[0m"
ls -al `which stat` 
stat `which ps top netstat sshd lsof find`>/tmp/checksystool.log
echo "/tmp/checksystool.log"

echo -e "\033[33m#### 0x2. Check abnormal user \033[0m"
echo -e "\033[33m|--> Check passwd stat info, GID=0 or use bash \033[0m"
stat /etc/passwd | grep -vE 'ile|Inode'
echo -e "\033[33m|--> Check GID=0 or use bash user \033[0m"
grep -E '/bash|:0+:' /etc/passwd | grep -vE 'root|mysql|rpm|mysql|shutdown|halt|sync'
echo -e "\033[33m|--> Check shadow stat info and no password user \033[0m"
stat /etc/shadow | grep -vE 'ile|Inode'
echo -e "\033[33m|--> Check no password user \033[0m"
awk -F: 'length($2)==0 {print $1}' /etc/shadow
echo ""

echo -e "\033[33m#### 0x3. Check service and task info \033[0m"
echo -e "\033[33m|--> Check start chkconfig service \033[0m"
chkconfig --list |grep -E '2:on|3:on' | awk '{printf"%s ",$1}'
systemctl list-unit-files |grep -E '2:on|3:on' | awk '{printf"%s ",$1}'
sysv-rc-conf --list
echo ""
echo -e "\033[33m|--> Check start rc.local \033[0m"
grep -vE '^$|^#' /etc/rc.local
echo -e "\033[33m|--> Check start crontab \033[0m"
crontab -l
ls -la /var/spool/cron/ >> /tmp/checkcrontab.log
ls -la /etc/cron* >> /tmp/checkcrontab.log
echo ""
echo -e "\033[33m|--> Check remote service \033[0m"
cat /etc/inetd.conf | grep -v "^#"
echo -e "\033[33m#### 0x4. Check process info \033[0m"
echo -e "\033[33m|--> Check ps result \033[0m"
ps axu | grep -v ]$
#echo -e "\033[33m|--> Check hidden process \033[0m"
#ps -ef | awk '{print $2}' | sort -n | uniq >1
#ls /proc | sort -n |uniq >2
#diff 1 2 | awk '{printf"%s ",$0}'
echo ""

echo -e "\033[33m#### 0x5. Check network info \033[0m"
echo -e "\033[33m|--> Check network hosts configure \033[0m"
cat /etc/hosts | grep -v 'localhost'
echo -e "\033[33m|--> Check network dns configure \033[0m"
cat /etc/resolv.conf | grep 'nameserver'
echo -e "\033[33m|--> Check network ip configure \033[0m"
/sbin/ip a|grep 'inet '| awk '{print $2}' | awk -F'/' '{printf"%s ",$1}'
echo ""
echo -e "\033[33m|--> Check network interface promisc mode \033[0m"
ifconfig | grep 'PROMISC'
echo -e "\033[33m|--> Check network interface forward mode \033[0m"
cat /proc/sys/net/ipv4/ip_forward 
echo -e "\033[33m|--> Check rpc info\033[0m"
rpcinfo -p
echo -e "\033[33m|--> Check network service info\033[0m"
netstat -nap | grep LISTEN
echo -e "\033[33m|--> Check process <-> port info\033[0m"
lsof -i > /tmp/checklsof
#cat /tmp/checklsof
echo ""

echo -e "\033[33m#### 0x6. Check file and module info \033[0m"
echo -e "\033[33m|--> Check file which link number equare 0 \033[0m"
lsof +L1
echo -e "\033[33m|--> Check file which change 3 days before now and executable \033[0m"
find / -path "/proc" -prune -o -type f -executable -mtime -3 -print > /tmp/checkfilechange
echo -e "\033[33m|--> Check module which installed \033[0m"
lsmod | awk '{printf"%s ",$1}'
echo ""
echo ""

echo -e "\033[33m#### 0x7. Check ssh and bash \033[0m"
echo -e "\033[33m|--> Check ssh key login host\033[0m"
if [ -e /root/.ssh/authorized_keys ]; then
    awk '{printf"%s ",$3}' /root/.ssh/authorized_keys
fi
echo -e "\033[33m|--> Check ssh password login user\033[0m"
lastlog | grep -vE 'Never'
echo -e "\033[33m|--> Check ssh now login\033[0m"
w
echo -e "\033[33m|--> Check ssh login success history\033[0m"
last -n 30
echo -e "\033[33m|--> Check ssh login fail history\033[0m"
grep -ri "ail" /var/log/secure* | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'| sort -n | uniq | awk '{printf"%s ",$1}'
last -f  /var/log/btmp -20
echo ""
echo -e "\033[33m|--> Check bash history size\033[0m"
echo $HISTSIZE
echo -e "\033[33m|--> Check some secure operation \033[0m"
history | grep -E 'wget|whoami'
echo -e "\033[33m|--> Check bash history \033[0m"
history 100 | awk '{for(i=2;i<=NF;i++)printf"%s ",$i;printf" <-- "}'
echo ""

echo -e "\033[33m#### 0x8. Check web log \033[0m"
echo -e "\033[33m|--> Check webshell \033[0m"
find / -type f -name '*.php' | xargs egrep '(phpspy|c99sh|include|milw0rm|eval\(gunerpress|eval\(base64_decode|spider_bc|@$)' | awk -F : '{print $1}' >> /tmp/checkweb.log
find / -type f -name "*.jsp" |xargs egrep 'exec|getRuntime()' >> /tmp/checkweb.log
find / -type f -name "*.asp*" |xargs egrep 'eval|execute|Request|VBScript'>> /tmp/checkweb.log
#grep -i 'select%20|sqlmap|script|phpinfo()|upload|cat' $LOGDIR/*log  | grep 500 | grep -i \.php >> /tmp/checkweb.log
find / -type f -name '*struts*'>> /tmp/checkweb.log
#cat /tmp/checkweb.log 
echo ""

echo -e "\033[33m#### 0x9. Check rootkit \033[0m"
echo -e "\033[33m|--> Check sysfile\033[0m"
rkhunter -c --sk > /tmp/rkhunter.log
grep 'Warning' /tmp/rkhunter.log
echo ""
echo -e "\033[33m|--> Check hiden progress\033[0m"
nohup unhide sys >>/tmp/unhide.log
nohup unhide brute >>/tmp/unhide.log
nohup unhide proc >>/tmp/unhide.log
nohup unhide procall >>/tmp/unhide.log
nohup unhide procfs >>/tmp/unhide.log
nohup unhide quick >>/tmp/unhide.log
nohup unhide reverse >>/tmp/unhide.log
nohup unhide-tcp >>/tmp/unhide.log
#cat /tmp/unhide.log

echo 'check backdoors'
find / -name “.rhosts” -print 
find / -name “.forward” -print 
echo 'check syslogs'
ls -la -h /var/log/messages
ls -la -h /var/log/maillog
ls -la /var/log/mail/

#echo -e "\033[33m|--> Check av\033[0m"
#freshclam  >/dev/null 2>&1 
#clamscan -r --bell -i / > /tmp/checkclamav.log 2>&1
#tail -10  /tmp/checkclamav.log

echo '/tmp/checkcrontab.log /tmp/checkfilechange /tmp/checklsof /tmp/unhide.log /tmp/checksystool.log /tmp/rkhunter.log /tmp/checkweb.log'
