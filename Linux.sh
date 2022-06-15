#!/bin/ksh

export LANG=C ;
# sysID
/bin/date +"%s" > epoch.txt ;
/bin/hostname >sysinfo.txt ;
/bin/uname -sr >>sysinfo.txt ;
/bin/cat /etc/*release >>sysinfo.txt ;
/usr/bin/uptime >>sysinfo.txt ;
/usr/sbin/dmidecode | /usr/bin/grep -A9 '^System Information' >>sysinfo.txt 2>&1 ;
/sbin/ifconfig >>sysinfo.txt ;
# RHEL 6 and later
/sbin/ip addr >>sysinfo.txt ;
/sbin/ip route >>sysinfo.txt ;

# Disks, Mounts, Exports
/bin/mount >mountedfs.txt ;
/bin/cat /etc/exports >exportedfs.txt 2>&1 ;
/sbin/showmount -e localhost >>exportedfs.txt 2>&1 ;
/bin/cat /etc/auto.master >auto_master.txt ;
/bin/df -k >df-k.txt ;
/sbin/fdisk -l >disk-partitions.txt 2>&1 ;
/sbin/vgs >lsvg.txt ;
/sbin/lvs >>lsvg.txt ;
/sbin/pvs >>lsvg.txt ;

# Security Config Files
/bin/cat /etc/shells >shells.txt ;
/bin/cat /etc/hosts >hosts.txt ;
/bin/cat /etc/login.defs >login_defs.txt ;
/bin/cat /etc/ldap.conf /etc/openldap/ldap.conf >ldap.conf.txt 2>&1 ;
/bin/cat /etc/sssd/sssd.conf >sssd.txt 2>&1;
/bin/cat /etc/nsswitch.conf >nsswitch_conf.txt;
/bin/cat /etc/krb5/krb5.conf >krb5_conf.txt 2>&1;
/bin/cat /usr/local/etc/krb5.conf >>krb5_conf.txt 2>&1;
/bin/cat /etc/pam.d/*auth >pamd-auth.txt ;
/bin/cat /etc/pam.d/*passwd >pamd-passwd.txt ;
/bin/cat /etc/pam.d/*login >pamd-login.txt ;
/bin/cat /etc/securetty >securetty.txt ;
/bin/cat /etc/ftpusers >ftpusers.txt 2>&1 ;
/bin/cat /etc/security/access.conf >access.conf.txt ;
/bin/cat /etc/security/pwquality.conf >pwquality.conf.txt 2>&1;
/bin/cat /etc/passwd >passwd.txt ;
/bin/cat /etc/shadow >shadow.txt ;
/bin/cat /etc/group >group.txt ;
/bin/cat /etc/sysconfig/authconfig  >sysconfig-authconfig.txt 2>&1;  #RHEL Only
/usr/bin/getent passwd >ge-passwd.txt ;
/usr/bin/getent group >ge-group.txt ;
/usr/sbin/pwck -r >usrck.txt 2>&1 ;
/sbin/auditd -l >audit-subsystem.txt 2>&1 ;
/sbin/iptables --list >iptables-list.txt;
/sbin/iptables-save >iptables-save.txt 2>&1;

# Privilege Access
/bin/cat /etc/sudoers >sudoers.txt ;
for sf in $(/bin/ls -1 /etc/sudoers.d); do 
    /bin/echo "== included file: ${sf} =========================" ; 
    /bin/cat /etc/sudoers.d/${sf} 2>&1 ; 
done >>sudoers.txt;
/bin/cat /etc/sudo.env >sudo_env.txt 2>&1 ;

# Processes/Services
/bin/ps -def >ps-ef.txt ;
/sbin/sysctl -a >>sysctl.txt 2>&1 ; 
/bin/netstat -lnutp >netstat.txt ;
/bin/cat /etc/inetd.conf >inetd_conf.txt 2>&1 ;
/bin/cat /etc/xinetd.conf >xinetd_conf.txt 2>&1 ;
/bin/ls -la /etc/xinetd.d >>xinetd.d.txt 2>&1 ;
/usr/sbin/service --status-all >services.txt 2>&1 ;
/bin/systemctl -t service --state=active > systemctl.txt 2>&1 #RHEL 7
# If not Debian/Ubuntu
/sbin/chkconfig --list >>services.txt 2>&1 ;
/bin/systemctl list-unit-files >>services.txt 2>&1 ; #RHEL 7

# Remote Access
/bin/cat /etc/ssh/sshd_config >sshd_config.txt ;
/bin/ls -l /etc/hosts.equiv >hosts_equiv.txt 2>&1 ;
/bin/cat /etc/hosts.equiv >>hosts_equiv.txt 2>&1 ;
/bin/cat /etc/snmp/snmp*.conf >snmp_conf.txt 2>&1 ;
/bin/cat /etc/motd >motd.txt 2>&1 ;

# Logging / Logs
/usr/bin/find /etc/ -iname '*syslog*\.conf' -exec  cat {} > syslog_conf.txt 2>&1 \;
/bin/cat /etc/logrotate.conf > logrotate.txt 2>&1;
/bin/cat /etc/logrotate.d/*syslog >> logrotate.txt 2>&1;
/usr/bin/last >last.txt ;
/usr/bin/lastlog >lastlog.txt ;
/bin/cat /var/log/secure >securelog.txt ;
/bin/cat /var/*/sudo.log >sudolog.txt 2>&1 ;
/usr/bin/utmpdump /var/log/wtmp >wtmpdump.txt 2>&1 ;
/usr/bin/utmpdump /var/log/btmp >btmpdump.txt 2>&1 ;

sudolog=$(/usr/bin/grep "Defaults logfile" /etc/sudoers | /usr/bin/sed 's/^.*=//') ;
if [ "${sudolog}" != "" ]; then
   /usr/bin/echo "== SUDOLOG ${sudolog} =========================" > sudolog2.txt ;
   /bin/cat $sudolog >> sudolog2.txt 2>&1 ;
fi

/bin/cat /etc/profile >profile.txt ;
for pe1 in / /root /home /etc /opt /usr /var/log /etc/security /etc/ssh /etc/pam.d \
    /etc/sysconfig /var/spool/cron /var/spool/cron/crontabs /etc/profile.d ; do
    if [ "X${pe1}" != "X/" ]; then
        pe2=$(/bin/echo ${pe1} | /usr/bin/tr '/' '_' | /bin/sed -e 's/^_//') ;
    else pe2='fsroot-perms.txt' ;
    fi;
    /bin/ls -lac ${pe1} >${pe2}-perms.txt 2>&1 ;
    /usr/bin/stat ${pe1} >>${pe2}-perms.txt 2>&1 ;
done;

# Supplementary root crontabs
/bin/ls -la /etc/cron* >crontab_root.txt 2>&1 ;

# User Crawler
uidmin=$(/usr/bin/awk '$1 ~ /^UID_MIN/ {print $2}' /etc/login.defs) ;
/bin/echo "UID_MIN=${uidmin}" >pwchages.txt ;
if [[ -z ${uidmin} ]] ; then
    uidmin=100
fi
while read lg; do
    lid=$(/bin/echo ${lg} | /usr/bin/awk -F: '{print $3}') ;
    if [[ $lid -ge $uidmin || $lid -eq 0 ]]; then
        ln=$(/bin/echo ${lg} | /usr/bin/awk -F: '{print $1}') ;
        /bin/echo "== PWCHGS ${ln} =========================" >>pwchages.txt ;
        /usr/bin/chage -l ${ln} >>pwchages.txt ;
        /bin/echo "== PRIVS ${ln} =========================" >>sudoable.txt ;
        sudo -lU ${ln} >>sudoable.txt ;
        /bin/echo "== SSH ${ln} =========================" >>keys.txt ;
        hd=$(/bin/echo ${lg} | /usr/bin/awk -F: '{print $6}') ;
        /bin/ls -la ${hd}/.ssh >>keys.txt 2>&1 ;
        /bin/echo "== SSHKPUB ${ln} =========================" >>keys.txt ;
        /bin/cat ${hd}/.ssh/authorized_keys >>keys.txt 2>&1 ;
        /bin/cat ${hd}/.ssh/authorized_keys2 >>keys.txt 2>&1 ;
        /bin/echo "== SSHK ${ln} =========================" >>keys.txt ;
        /bin/cat ${hd}/.ssh/id_* >>keys.txt 2>&1 ;
        for sinit in .profile .bashrc .bash_profile .login .kshrc .cshrc .tcshrc ; do
            /bin/echo "== PROFILE ${ln} ${hd}/${sinit} ============" >>sinit_${ln}.txt ;
            /bin/ls -l ${hd}/$sinit 2>/dev/null >>sinit_${ln}.txt ;
            /bin/cat ${hd}/$sinit 2>/dev/null >>sinit_${ln}.txt ;
        done;
        /bin/echo "== HOMEFILES ${ln} =========================" >homedir_${ln}.txt ;
        /bin/ls -lac ${hd} >>homedir_${ln}.txt ;
        if [ -f /var/spool/cron/crontabs/${ln} ] ; then
            /bin/echo "== CRONTABS ${ln} =========================" >crontab_${ln}.txt ;
            /bin/ls -lc /var/spool/cron/crontabs/${ln} >>crontab_${ln}.txt ;
            /bin/cat /var/spool/cron/crontabs/${ln} >>crontab_${ln}.txt ;
        elif [ -f /var/spool/cron/${ln} ] ; then
            /bin/echo "== CRONTABS ${ln} =========================" >crontab_${ln}.txt ;
            /bin/ls -lc /var/spool/cron/${ln} >>crontab_${ln}.txt ;
            /bin/cat /var/spool/cron/${ln} >>crontab_${ln}.txt ;
        fi
        for uf1 in $(/usr/bin/crontab -l ${ln} | /usr/bin/awk '{print $6}' | \
            /usr/bin/grep "^/" | /usr/bin/sort | /usr/bin/uniq) ; do 
            /bin/echo "== CRONTARGETPERM ${ln};${hd} =========================" ;
            /bin/ls -ld ${uf1} ;
            /bin/echo "== CRONTARGETCONTENTS ${ln};${uf1} =========================" ;
            /usr/bin/strings ${uf1} ;
        done 2>/dev/null >>cron_targetfiles.txt ; 
        if [ -f ${hd}/.netrc ] ; then
            /bin/ls -l ${hd}/.netrc >>rperms_${ln}.txt ;
            /usr/bin/stat ${hd}/.netrc >>rperms_${ln}.txt ;
        fi ;
        if [ -f ${hd}/.rhosts ] ; then
            /bin/cat ${hd}/.rhosts >>rperms_${ln}.txt ;
            /bin/ls -l ${hd}/.rhosts >>rperms_${ln}.txt ;
            /usr/bin/stat ${hd}/.rhosts >>rperms_${ln}.txt ;
        fi ;
    fi ;
done < ./ge-passwd.txt ;

# Package/Patch ###################
/usr/bin/which bash >shellshock.txt
env x='() { :;}; echo bash vulnerable' bash -c 'echo bash ok' >>shellshock.txt ;
exec 2>> sudoshock.txt && sudoedit -s '\' $(perl -e 'print "A" x 65536') 2>&1 >>sudoshock.txt &
sudo -V >>sudoshock.txt;

# RedHat/SuSE/Oracle/CentOS/Fedora
rpm -qa --qf '%{INSTALLTIME}~%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' >rpm2vuln.txt 2>&1 ;
rpm -qa --last >rpm-revinstorder.txt 2>&1 ;

# RHEL 5 and higher Systems
/bin/cat /var/log/yum.log >yum-update-history.txt 2>&1 ;

# RHEL 7 and higher Systems
yum list-sec >yum-listsec.txt 2>&1 ;

# Debian / Ubuntu systems ONLY
for file_list in $(/bin/ls -t /var/lib/dpkg/info/*.list); do 
    stat_result=$(/usr/bin/stat --format=%y "$file_list"); 
    /usr/bin/printf "%-50s %s\n" $(basename $file_list .list) "$stat_result"; 
done >debstyle-packages.txt 2>&1 ;

# Ubuntu 16+ and possibly Debian/Fedora/SuSE (ignore not found if not installed)
/usr/bin/snap list --all >snap-history.txt 2>&1 ;
/usr/bin/snap changes >>snap-history.txt 2>&1 ;

# SLES 11 and higher Systems ONLY
/bin/cat /var/log/zypp/history >zypp-update-history.txt 2>&1 ;
# ALL
/usr/bin/sha256sum ./*.txt > sha256.sum
