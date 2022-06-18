#!/bin/sh
# FreeBSD Data Request Commands
# v1471397936 gnotske
#
# Instructions:
#    a. Please create a temporary directory called /tmp/corpaudit_<Hostname>
#    b. cd to /tmp/corpaudit_<Hostname>
#    c. Run the following commands:  (Please change the command if the location of the log is not standard)
#    d. Follow any additional directions in the Data Request
#    e. tar and zip the /tmp/corpaudit_<Hostname> directory and post into audit team room
#
export LANG=C
# sysID
date +"%s" >epoch.txt
grep hostname /etc/rc.conf >sysinfo.txt;
cat /etc/hostid >>sysinfo.txt;
/usr/bin/uname -a >>sysinfo.txt;
/usr/bin/uptime >>sysinfo.txt;
/sbin/ifconfig >>sysinfo.txt;

# Disks, Mounts, Exports
mount >mountedfs.txt;
/usr/sbin/showmount -a >> mountedfs.txt;
cat /etc/exports >exportedfs.txt;
cat /etc/auto.master >auto_master.txt;
/bin/df -k >df-k.txt;
/sbin/fdisk -v >disk-partitions.txt;

# Security Config Files
cat /etc/shells >shells.txt;
cat /etc/hosts >hosts.txt;
cat /etc/login.conf >login_defs.txt;
cat /etc/pam.d/system >pamd-system-auth.txt;
cat /etc/pam.d/other >pamd-other.txt;
cat /etc/pam.d/passwd >pamd-passwd.txt;
cat /etc/pam.d/rsh >pamd-rsh.txt;
cat /etc/pam.d/login >pamd-login.txt;
cat /etc/ttys >securetty.txt;
cat /etc/ftpusers >ftpusers.txt;
cat /etc/login.access >access.conf.txt;
cat /etc/passwd >passwd.txt;
cat /etc/master.passwd >shadow.txt;
# username:passwdhash:uid:gid:loginclass:pwchgdate:expire:gecos:home_dir:shell:
cat /etc/group >group.txt;
getent passwd >ge-passwd.txt;
getent group >ge-group.txt;

# Privilege Access
cat /usr/local/etc/sudoers >sudoers.txt;
for sf in `ls -1 /etc/sudoers.d`; do echo "== included file: ${sf} =========="; cat /etc/sudoers.d/${sf}; done >>sudoers.txt;
cat /etc/sudo.env >sudo_env.txt;

# Processes/Services
ps aux >ps-ef.txt;
/usr/bin/netstat -aLS -f inet >netstat.txt;
cat /etc/inetd.conf >inetd_conf.txt;
/usr/sbin/service -ev >services.txt;
cat /etc/rc.conf >services-config.txt;
cat /etc/rc.conf.local >>services-config.txt;
/sbin/sysctl -a > sysctl.txt;

# Remote Access
cat /etc/ssh/sshd_config >sshd_config.txt;
cat /etc/hosts.equiv >hosts_equiv.txt;
ls -l /etc/hosts.equiv >>hosts_equiv.txt;
cat /etc/hosts.allow >tcpw-hosts_allow.txt;
cat /etc/hosts.deny >tcpw-hosts_deny.txt;
cat /etc/snmpd.config >snmpd_conf.txt;
cat /etc/motd >motd.txt;
cat /.rhosts >root_rhosts.txt;
ls -l /.rhosts >>root_rhosts.txt;

# Logging / Logs
cat `ls -R /etc 2>/dev/null | grep 'syslog' | grep '.conf' | grep -v '.d$'` >syslog_conf.txt;
/usr/bin/last >last.txt;
/usr/sbin/lastlogin >lastlog.txt;
cat /var/log/secure >securelog.txt;
cat /var/adm/sudo.log >sudolog.txt;
cat /var/log/sudo.log >>sudolog.txt;
head -30 /var/log/messages >messageslog.txt;
tail -30 /var/log/messages >>messageslog.txt;
cat /var/log/utx.log >utx_log.bin;

# shell init files .profile, .bash_profile, .bashrc, .kshrc, .cshrc, .login, .tchrc
cat /etc/profile >profile.txt
cat /etc/csh.login >>profile
for pe1 in / /root /home /etc /opt /usr/local /usr /var/log /etc/pam.d /var/cron/tabs ; do
    if [ "X${pe1}" != "X/" ]; then
        pe2=`echo ${pe1} | tr '/' '_' | sed -e 's/^_//'`;
    else pe2='fsroot-perms.txt';
    fi;
    ls -la ${pe1} >${pe2}-perms.txt;
done;

ls -la /etc/crontab >>etc_cronfiles-perms.txt;
cat /etc/crontab >>root_crontab.txt;

# User Crawler
uidmin=100;
while read lg; do
    lid=`echo ${lg} | awk -F: '{print $3}'`
    if [[ $lid -ge $uidmin || $lid -eq 0 ]]; then
        ln=`echo ${lg} | awk -F: '{print $1}'`;
        echo "== ${ln} =========================" >>pwchages.txt;
        chage -l $ln >>pwchages.txt;
        echo "== ${ln} =========================" >>keys.txt;
        hd=`echo ${lg} | awk -F: '{print $6}'`;
        ls -ld ${hd}/.ssh >>keys.txt;
        ls -l ${hd}/.ssh/authorized_keys* ${hd}/.ssh/id_* >>keys.txt;
        cat ${hd}/.ssh/authorized_keys* ${hd}/.ssh/id_* >>keys.txt;
        for sinit in .profile .bashrc .bash_profile .login .cshrc .tcshrc; do
            echo "== ${ln} ${hd}/${sinit} ============" >>sinit_${ln}.txt;
            ls -l ${hd}/$sinit >>sinit_${ln}.txt;
            cat ${hd}/$sinit >>sinit_${ln}.txt;
        done;
        # OSR Permissions
        if [ -f ${hd}/.netrc ]; then
            ls -l ${hd}/.netrc >>${ln}_rperms.txt;
        fi;
        if [ -f ${hd}/.rhosts ]; then
            ls -l ${hd}/.rhosts >>${ln}_rperms.txt;
        fi;
    fi;
done < /etc/passwd;

# Package Dump
# Package Mangement
cat /etc/freebsd-update.conf >freebsd-update_conf.txt;
cat /usr/local/etc/pkg.conf >pkg_conf.txt;
# FreeBSD "old-style" w/pkg_* tools
/usr/sbin/pkg_info -aI >pkg_info.txt;
ls -l /var/db/pkg/* >>pkg_info.txt;
# FreeBSD w/pkgng
/usr/sbin/pkg info >pkg_info.txt;
for pack in `pkg info | awk '{ print $1 }'`; do
   pkg info ${pack} >pkg_info_full.txt
done;
