#!/bin/ksh
# Solaris Data Request Commands NG
# v1611965323 gnotske
#
# Instructions:
#    a. Please create a temporary directory called /tmp/corpaudit_<Hostname>
#    b. cd to /tmp/corpaudit_<Hostname>
#    c. Run the following commands:  (Please change the command if the location of the log is not standard)
#    d. Follow any additional directions in the Data Request
#    e. tar and zip the /tmp/corpaudit_<Hostname> directory and post into audit team room
#
export LANG=C ; 
# sysID
/usr/bin/nawk 'BEGIN{print srand()}' > epoch.txt ;
/usr/bin/hostname >sysinfo.txt 2>&1;
/usr/bin/uname -sr >>sysinfo.txt 2>&1;
/usr/bin/cat /etc/*release >>sysinfo.txt 2>&1;
/usr/bin/uptime >>sysinfo.txt 2>&1;
/usr/bin/cat /var/sadm/system/admin/INST_RELEASE >>sysinfo.txt 2>&1;
/usr/bin/cat /var/sadm/system/admin/CLUSTER >>sysinfo.txt 2>&1;
/usr/sbin/zoneadm list -cv >>sysinfo.txt 2>&1; 
/sbin/ifconfig -a >>sysinfo.txt 2>&1;
/usr/bin/netstat -rn >>sysinfo.txt 2>&1; 

# Disks, Mounts, Exports
/usr/sbin/mount >mountedfs.txt 2>&1;
/usr/bin/cat /etc/vfstab >>mountedfs.txt 2>&1;
/usr/bin/cat /etc/auto_master >auto_master.txt 2>&1;
/bin/df -h >df-h.txt 2>&1; 
/usr/bin/cat /etc/dfs/sharetab >exportedfs.txt 2>&1;
/usr/bin/cat /etc/dfs/dfstab >>exportedfs.txt 2>&1;
/usr/sbin/showmount -e localhost >>exportedfs.txt 2>&1;

# Security Config Files
/usr/bin/cat /etc/hosts >hosts.txt ;
/usr/bin/cat /etc/default/login >login_defs.txt ;
/usr/bin/cat /etc/default/passwd >>login_defs.txt ;
/usr/bin/cat /etc/pam.conf >pamd-conf.txt ;
/usr/bin/cat /etc/securetty >securetty.txt ;
/usr/bin/cat /etc/ftpusers >ftpusers.txt ;
/usr/bin/cat /etc/passwd >passwd.txt ;
/usr/bin/cat /etc/shadow >shadow.txt ;
/usr/bin/cat /etc/group >group.txt ;
/usr/bin/cat /etc/security/policy.conf >policy_conf.txt ;
/usr/bin/getent passwd >ge-passwd.txt ;
/usr/bin/getent group >ge-group.txt ;
/usr/sbin/pwck /etc/passwd 2>pwck.txt ;
/usr/sbin/grpck /etc/group 2>grpck.txt ;
/usr/bin/passwd -sa >pwchages.txt ;

# Privilege Access
sstat() { /usr/bin/truss -t lstat64 -v lstat64 ls ${1} | /usr/bin/tail -0 ; }; export sstat
/usr/bin/cat /etc/sudoers >sudoers.txt ;
for sf in $(/usr/bin/ls -1 /etc/sudoers.d); do 
    /usr/bin/echo "== included file: ${sf} =========================" ; 
    /usr/bin/cat /etc/sudoers.d/${sf} 2>&1 ; 
done >>sudoers.txt ;
/usr/bin/cat /etc/sudo.env >sudo_env.txt 2>&1 ;
/usr/bin/cat /etc/user_attr >rbac-user_attr.txt 2>&1;
/usr/bin/cat /etc/security/auth_attr >rbac-auth_attr.txt 2>&1;
/usr/bin/cat /etc/security/prof_attr >rbac-prof_attr.txt 2>&1;

# Processes/Services

if [ $(uname -r) = '5.11' ]; then
    /usr/bin/netstat -auf inet >netstat.txt 2>&1;
    /usr/bin/ps -eZf >ps-ef.txt 2>&1;
else
    /usr/bin/netstat -af inet >netstat.txt 2>&1;
    /usr/bin/ps -ef >ps-ef.txt 2>&1;
fi
/usr/bin/cat /etc/inetd.conf >inetd_conf.txt 2>&1;
# Solaris 10/11 only
/usr/sbin/inetadm >>inetd_conf.txt 2>&1;
# Solaris 2.6/7/8/9
/usr/bin/ls -l /etc/rc*.d >services.txt 2>&1
# Solaris 10/11 only
/usr/bin/svcs -a >>services.txt 2>&1;
/usr/sbin/inetadm >>services.txt 2>&1;

# Remote Access
/usr/bin/cat /etc/ssh/sshd_config >sshd_config.txt 2>&1;
/usr/bin/cat /etc/hosts.equiv >hosts_equiv.txt 2>&1;
/usr/bin/cat /etc/motd >motd.txt 2>&1;
/usr/bin/cat /etc/issue >issue.txt 2>&1;

# Logging / Logs
/usr/bin/cat /etc/syslog.conf >syslog_conf.txt 2>&1;
/usr/bin/cat /etc/logadm.conf >logrotate.txt 2>&1;
/usr/bin/last >last.txt 2>&1;
/usr/bin/cat /var/*/sudo.log >sudo_log.txt 2>&1 ;
/usr/bin/cat /var/adm/wtmpx >wtmp.bin ;
/usr/bin/cat /var/adm/sulog >sulog.txt ;
/usr/bin/cat /var/*/authlog >authlog.txt 2>&1 ;
/usr/lib/acct/fwtmp < /var/adm/wtmpx > wtmpdump.txt 2>&1 ; 

/usr/bin/cat /etc/profile >profile.txt ;
for pe1 in / /root /home /etc /etc/ssh /opt /usr /var/log /var/adm /etc/default \
    /etc/security /net /vol /var/spool/cron/crontabs /etc/profiles.d ; do
    if [ "X${pe1}" != "X/" ] ; then
        pe2=$(echo ${pe1} | /usr/bin/tr '/' '_' | /usr/bin/sed -e 's/^_//') ;
    else pe2='fsroot-perms.txt' ;
    fi ;
    /usr/bin/ls -la ${pe1} >${pe2}-perms.txt 2>&1 ;
    sstat ${pe1} >>${pe2}-perms.txt 2>&1;
done ;

# User Crawler
uidmin=100 ;
while read lg; do
    lid=$(/usr/bin/echo ${lg} | /usr/bin/awk -F: '{print $3}') ;
    if [[ $lid -ge $uidmin || $lid -eq 0 ]]; then
        ln=$(/usr/bin/echo ${lg} | /usr/bin/awk -F: '{print $1}') ;
        /usr/bin/echo "== PWCHGS ${ln} =========================" >>pwchages.txt ;
        /usr/bin/passwd -s ${ln} >>pwchages.txt ;
        /usr/bin/echo "== PRIVS ${ln} =========================" >>sudoable.txt ;
        sudo -lU ${ln} >>sudoable.txt ;
        /usr/bin/echo "== SSH ${ln} =========================" >>keys.txt ;
        hd=$(/usr/bin/echo ${lg} | /usr/bin/awk -F: '{print $6}') ;
        /usr/bin/ls -la ${hd}/.ssh >>keys.txt 2>&1 ;
        /usr/bin/echo "== SSHKPUB ${ln} =========================" >>keys.txt ;
        /usr/bin/cat ${hd}/.ssh/authorized_keys* >>keys.txt 2>&1 ;
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
            /usr/bin/ls -lc /var/spool/cron/crontabs/${ln} >>crontab_${ln}.txt 2>&1;
            /usr/bin/cat /var/spool/cron/crontabs/${ln} >>crontab_${ln}.txt 2>&1;
        fi
        for uf1 in $(/usr/bin/crontab -l ${ln} | /usr/bin/awk '{print $6}' | \
            /usr/bin/grep "^/" | /usr/bin/sort | /usr/bin/uniq) ; do 
            /usr/bin/echo "== CRONTARGETPERM ${ln};${hd} =========================" ;
            /usr/bin/ls -ld ${uf1} ;
            /usr/bin/echo "== CRONTARGETCONTENTS ${ln};${uf1} =========================" ;
            /usr/bin/strings ${uf1} ;
        done 2>/dev/null >>cron_targetfiles.txt ; 
        if [ -f ${hd}/.netrc ] ; then
            /usr/bin/ls -l ${hd}/.netrc >>rperms_${ln}.txt 2>&1;
            sstat ${hd}/.netrc >>rperms_${ln}.txt 2>&1;
        fi ;
        if [ -f ${hd}/.rhosts ] ; then
            /usr/bin/cat ${hd}/.rhosts >>rperms_${ln}.txt 2>&1;
            /usr/bin/ls -l ${hd}/.rhosts >>rperms_${ln}.txt 2>&1;
            sstat ${hd}/.rhosts >>rperms_${ln}.txt 2>&1;
        fi ;
    fi ;
done < /etc/passwd ;

# Package Dump
/usr/bin/which bash >shellshock.txt
env x='() { :;}; echo bash vulnerable' bash -c 'echo bash ok' >>shellshock.txt ;
sudoedit -s '\' $(perl -e 'print "A" x 65536') 2>&1 >sudoshock.txt;

for pkgname in $(/usr/bin/pkginfo -i | awk '{ print $2 }'); do echo \
    "${pkgname},$(grep '^NAME=' /var/sadm/pkg/${pkgname}/pkginfo | \
    sed -e 's/NAME=//'),$(grep 'VERSION=' /var/sadm/pkg/${pkgname}/pkginfo | \
    sed -e 's/VERSION=//'),$(grep 'INSTDATE=' /var/sadm/pkg/${pkgname}/pkginfo | \
    sed -e 's/INSTDATE=//')"; 
done >pkglist.txt;
if [ $(uname -r) = '5.10' ]; then grep -h PATCH_INFO_ /var/sadm/pkg/SUNW*/pkginfo | sed -e 's/From:.*//' \
    -e 's/PATCH_INFO_//' | cut -c0-50 | awk '{ print $1" "$2" "$3" "$4" "$7 }' | \
    sort -u >patch-history.txt ;
fi ;
/usr/bin/digest -va sha256 ./*.txt >sha256.sum