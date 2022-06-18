#!/bin/ksh
# AIX Data Request Commands NG
# v1583419298 gnotske
#
# Instructions:
#    a. Please create a temporary directory called /tmp/corpaudit_<Hostname>
#    b. cd to /tmp/corpaudit_<Hostname>
#    c. Run the following commands as a privileged user:  (Please change the command if the location of the log is not standard)
#    d. Follow any additional directions in the Data Request
#    e. tar and zip the /tmp/corpaudit_<Hostname> directory and post into audit team room
#
export LANG=C ;
# sysID
/usr/bin/date +"%s" > epoch.txt ;
/usr/bin/hostname >sysinfo.txt ;
/usr/bin/uname -srv >>sysinfo.txt ;
/usr/bin/oslevel >>sysinfo.txt ;
/usr/bin/uname -L >>sysinfo.txt ;
/usr/bin/uptime >>sysinfo.txt ;
/usr/sbin/ifconfig -a >>sysinfo.txt ;
/usr/sbin/dumpfs /dev/hd4 | /usr/bin/head > rootfs_age.txt ;

# Disk, Mounts, Exports
/usr/sbin/mount >mountedfs.txt ;
/usr/bin/cat /etc/auto_master >auto_master.txt ;
/usr/sbin/lsvg -o | lsvg -il >lsvg.txt ;
/usr/bin/df -k >df-k.txt ;
/usr/bin/cat /etc/exports >exportedfs.txt 2>&1 ;
/usr/bin/showmount -e localhost >>exportedfs.txt 2>&1 ;
/usr/bin/cat /etc/xtab >>exportedfs.txt 2>&1 ;

# Security Config Files
/usr/bin/cat /etc/shells >shells.txt ;
/usr/bin/cat /etc/hosts >hosts.txt ;
/usr/bin/cat /etc/environment >env.txt ;
/usr/bin/cat /etc/passwd >passwd.txt ;
/usr/bin/cat /etc/group >group.txt ;
/usr/bin/cat /etc/security/group >sec_group.txt ;
/usr/bin/cat /etc/security/passwd >sec_passwd.txt ;
/usr/bin/cat /etc/security/user >sec_user.txt ;
/usr/sbin/lsuser -c ALL >lsuser-c.txt ;
/usr/sbin/lsuser -R LDAP -a gecos ALL >lsuser-ldap.txt  2>&1 ;
/usr/sbin/lsgroup -c ALL >lsgroup-c.txt ;
/usr/bin/cat /etc/security/login.cfg >sec_login.txt ;
/usr/bin/cat /etc/pam.conf >pam_conf.txt ;
/usr/bin/cat /etc/ftpusers >ftpusers.txt ;
/usr/bin/usrck -n ALL 2>usrck.txt ;
/usr/sbin/grpck -n ALL 2>grpck.txt ;
/usr/sbin/audit query >audit-subsystem.txt 2>&1

# Privilege Access
/usr/bin/cat /etc/sudoers >sudoers.txt ;
for sf in $(/usr/bin/ls -1 /etc/sudoers.d) ; do 
  /usr/bin/echo "== included file: ${sf} ==========" ; 
  /usr/bin/cat /etc/sudoers.d/${sf} ; 
done >>sudoers.txt ;
/usr/bin/cat /etc/sudo.env > sudo_env.txt ;

# Processes/Services
/usr/bin/ps -deaf >ps-deaf.txt ;
/usr/bin/netstat -a |grep -i LIST >netstat.txt ;
/usr/sbin/lsitab -a >lsitab-a.txt ;
/usr/bin/cat /etc/inetd.conf >inetd.txt;
/usr/bin/cat /etc/inittab >inittab.txt ;
/usr/bin/lssrc -a >lssrc-a.txt;
/usr/bin/lssrc -ls inetd >lssrc-inetd.txt ;

# Remote Access
/usr/bin/cat /etc/ssh/sshd_config >sshd_config.txt ;
/usr/bin/ls -l /etc/hosts.equiv >hosts_equiv.txt ;
/usr/bin/cat /etc/hosts.equiv >>hosts_equiv.txt ;
/usr/bin/cat /etc/motd >motd.txt ; 

# Logging / Logs
/usr/bin/cat /etc/syslog.conf >syslog_conf.txt ;
/usr/bin/cat /var/*/sudo.log >sudolog.txt ;
/usr/bin/last >last.txt ;
/usr/bin/cat /etc/security/lastlog >lastlog.txt ;
/usr/bin/cat /var/adm/sulog >sulog.txt ;
/bin/cat /var/adm/auth.log >authlog.txt ;
/usr/sbin/acct/fwtmp < /var/adm/wtmp > wtmpdump.txt ; 

# Package/Patch ###################
/usr/bin/which bash >shellshock.txt
env x='() { :;}; echo bash vulnerable' bash -c 'echo bash ok' >>shellshock.txt ;
/usr/sbin/instfix -iv >instfix-iv.txt ;
/usr/bin/lslpp -ahc >lslpp-ahc.txt ;
/usr/bin/lppchk -v >lppchk-v.txt 2>&1 ;
/usr/bin/lslpp -l >lslpp-l.txt ;
/usr/bin/lslpp -Lc >lslpp2lssecfixes.txt ;
/usr/bin/lslpp -qch | /usr/bin/awk -F: '{printf "%-14s %-40s %-15s\n",$7,$2,$3}' | \
  /usr/bin/sort | /usr/bin/uniq | \
  /usr/bin/sed 's/70/-70/' | /usr/bin/sort -t '/' -k 3,3nr -k 1,1nr -k 2,2nr | \
  /usr/bin/sed 's/-70/70/' >lslpp-installorder.txt ;
# If exists rpm
rpm -qa --queryformat '%{INSTALLTIME}~%{NAME}~%{VERSION}-%{RELEASE}\n' >rpm2lssecfix.txt ;

/usr/bin/echo $PATH | /usr/bin/awk -F: '{for (i=1;i<=NF;i++){print $i}}' >path.txt ;
/usr/bin/echo $PATH | /usr/bin/awk -F: '{for (i=1;i<=NF;i++){print $i}}' | \
  /usr/bin/xargs -i /usr/bin/ls -lrt {} >path-lst.txt ;

/usr/bin/cat /etc/profile >profile.txt ;
for pe1 in / /root /home /etc /opt /usr /var/log /etc/security /etc/ssh \
    /var/spool/cron/crontabs /var/adm /etc/profile.d ; do
    if [ "X${pe1}" != "X/" ]; then
        pe2=$(echo ${pe1} | /usr/bin/tr '/' '_' | /usr/bin/sed -e 's/^_//') ;
    else pe2='fsroot-perms.txt' ;
    fi;
    /usr/bin/ls -lac ${pe1} >${pe2}-perms.txt 2>&1 ;
    /usr/bin/istat ${pe1} >>${pe2}-perms.txt 2>&1 ;
done;

# User Crawler
uidmin=$(/usr/bin/awk '{print $1}' /etc/security/.ids) ;
if [[ -z ${uidmin} ]] ; then
    uidmin=50
fi
/usr/bin/echo "UID_MIN=${uidmin}" >pwchages.txt ;
while read lg; do
    lid=$(/usr/bin/echo ${lg} | /usr/bin/awk -F: '{print $3}') ;
    if [[ $lid -ge $uidmin || $lid -eq 0 ]]; then
        ln=$(/usr/bin/echo ${lg} | /usr/bin/awk -F: '{print $1}') ;
        /usr/bin/echo "== PWCHGS ${ln} =========================" >>pwchages.txt ;
        /usr/bin/lssec -f /etc/security/passwd -s ${ln} -a lastupdate >>pwchages.txt ;
        /usr/bin/echo "== PRIVS ${ln} =========================" >>sudoable.txt ;
        sudo -lU ${ln} >>sudoable.txt ;
        /usr/bin/echo "== SSH ${ln} =========================" >>keys.txt ;
        hd=$(/usr/bin/echo ${lg} | /usr/bin/awk -F: '{print $6}') ;
        /usr/bin/ls -la ${hd}/.ssh >>keys.txt 2>&1 ;
        /usr/bin/echo "== SSHKPUB ${ln} =========================" >>keys.txt ;
        /usr/bin/cat ${hd}/.ssh/authorized_keys >>keys.txt 2>&1 ;
        /usr/bin/cat ${hd}/.ssh/authorized_keys2 >>keys.txt 2>&1 ;
        /usr/bin/echo "== SSHK ${ln} =========================" >>keys.txt ;
        /usr/bin/cat ${hd}/.ssh/id_* >>keys.txt 2>&1 ;
        for sinit in .profile .bashrc .bash_profile .login .kshrc .cshrc .tcshrc ; do
            /usr/bin/echo "== PROFILE ${ln} ${hd}/${sinit} ============" >>sinit_${ln}.txt ;
            /usr/bin/ls -l ${hd}/$sinit 2>/dev/null >>sinit_${ln}.txt ;
            /usr/bin/cat ${hd}/$sinit 2>/dev/null >>sinit_${ln}.txt ;
        done;
        /usr/bin/echo "== HOMEFILES ${ln} =========================" >homedir_${ln}.txt ;
        /usr/bin/ls -lac ${hd} >>homedir_${ln}.txt ;
        if [ -f /var/spool/cron/crontabs/${ln} ] ; then
            /usr/bin/echo "== CRONTABS ${ln} =========================" >crontab_${ln}.txt ;
            /usr/bin/ls -lc /var/spool/cron/crontabs/${ln} >>crontab_${ln}.txt ;
            /usr/bin/cat /var/spool/cron/crontabs/${ln} >>crontab_${ln}.txt ;
        fi
        for uf1 in $(/usr/bin/crontab -l ${ln} | /usr/bin/awk '{print $6}' | \
            /usr/bin/grep "^/" | /usr/bin/sort | /usr/bin/uniq) ; do 
            /usr/bin/echo "== CRONTARGETPERM ${ln};${hd} =========================" ;
            /usr/bin/ls -ld ${uf1} ;
            /usr/bin/echo "== CRONTARGETCONTENTS ${ln};${uf1} =========================" ;
            /usr/bin/strings ${uf1} ;
        done 2>/dev/null >>cron_targetfiles.txt ; 
        if [ -f ${hd}/.netrc ] ; then
            /usr/bin/ls -l ${hd}/.netrc >>rperms_${ln}.txt ;
            /usr/bin/istat ${hd}/.netrc >>rperms_${ln}.txt ;
        fi ;
        if [ -f ${hd}/.rhosts ] ; then
            /usr/bin/cat ${hd}/.rhosts >>rperms_${ln}.txt ;
            /usr/bin/ls -l ${hd}/.rhosts >>rperms_${ln}.txt ;
            /usr/bin/istat ${hd}/.rhosts >>rperms_${ln}.txt ;
        fi ;
    fi ;
done < /etc/passwd ;
/usr/bin/shasum -a 256 ./*.txt > sha256.sum