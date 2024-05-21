#!/bin/bash

export LANG=C ;

# Collect System Information
/bin/date +"%s" > epoch.txt ;  # Save current epoch time to a file
/bin/hostname > sysinfo.txt ;  # Get hostname and save to sysinfo.txt
/bin/uname -sr >> sysinfo.txt ;  # Get kernel release information and append to sysinfo.txt
/bin/cat /etc/*release >> sysinfo.txt ;  # Get OS release information and append to sysinfo.txt
/usr/bin/uptime >> sysinfo.txt ;  # Get system uptime and append to sysinfo.txt
/usr/sbin/dmidecode | /usr/bin/grep -A9 '^System Information' >> sysinfo.txt 2>&1 ;  # Get system hardware information and append to sysinfo.txt
/sbin/ifconfig >> sysinfo.txt ;  # Get network interface configuration and append to sysinfo.txt
/sbin/ip addr >> sysinfo.txt ; # RHEL 6 and later - Get IP address information and append to sysinfo.txt
/sbin/ip route >> sysinfo.txt ;  # Get routing table information and append to sysinfo.txt

# Disks, Mounts, Exports
/bin/mount > mountedfs.txt ;  # Get mounted filesystems and save to mountedfs.txt
/bin/cat /etc/exports > exportedfs.txt 2>&1 ;  # Get NFS exports configuration and save to exportedfs.txt
/sbin/showmount -e localhost >> exportedfs.txt 2>&1 ;  # Get NFS shares from localhost and append to exportedfs.txt
/bin/cat /etc/auto.master > auto_master.txt ;  # Get autofs master configuration and save to auto_master.txt
/bin/df -k > df-k.txt ;  # Get disk space usage and save to df-k.txt
/sbin/fdisk -l > disk-partitions.txt 2>&1 ;  # List disk partitions and save to disk-partitions.txt
/sbin/vgs > lsvg.txt ;  # Display volume group information for all volume groups and save to lsvg.txt
/sbin/lvs >> lsvg.txt ;  # Display logical volumes and save to lsvg.txt
/sbin/pvs >> lsvg.txt ;  # Display physical volumes and save to lsvg.txt

# Security Configuration Files
/bin/cat /etc/shells > shells.txt ;  # List valid login shells and save to shells.txt
/bin/cat /etc/hosts > hosts.txt ;  # Display hosts file content and save to hosts.txt
/bin/cat /etc/login.defs > login_defs.txt ;  # Display login configuration and save to login_defs.txt
/bin/cat /etc/ldap.conf /etc/openldap/ldap.conf > ldap.conf.txt 2>&1 ;  # Display LDAP configuration and save to ldap.conf.txt
/bin/cat /etc/sssd/sssd.conf > sssd.txt 2>&1;  # Display SSSD configuration and save to sssd.txt
/bin/cat /etc/nsswitch.conf > nsswitch_conf.txt;  # Display Name Service Switch configuration and save to nsswitch_conf.txt
/bin/cat /etc/krb5/krb5.conf > krb5_conf.txt 2>&1;  # Display Kerberos configuration and save to krb5_conf.txt
/bin/cat /usr/local/etc/krb5.conf >> krb5_conf.txt 2>&1;  # Append Kerberos configuration from an alternate location and save to krb5_conf.txt
/bin/cat /etc/pam.d/*auth > pamd-auth.txt ;  # Display PAM authentication configuration and save to pamd-auth.txt
/bin/cat /etc/pam.d/*passwd > pamd-passwd.txt ;  # Display PAM password configuration and save to pamd-passwd.txt
/bin/cat /etc/pam.d/*login > pamd-login.txt ;  # Display PAM login configuration and save to pamd-login.txt
/bin/cat /etc/securetty > securetty.txt ;  # Display securetty configuration and save to securetty.txt
/bin/cat /etc/ftpusers > ftpusers.txt 2>&1 ;  # Display FTP users configuration and save to ftpusers.txt
/bin/cat /etc/security/access.conf > access.conf.txt ;  # Display access control configuration and save to access.conf.txt
/bin/cat /etc/security/pwquality.conf > pwquality.conf.txt 2>&1;  # Display password quality configuration and save to pwquality.conf.txt
/bin/cat /etc/passwd > passwd.txt ;  # Display user account information and save to passwd.txt
/bin/cat /etc/shadow > shadow.txt ;  # Display shadow password file and save to shadow.txt
/bin/cat /etc/group > group.txt ;  # Display group information and save to group.txt
/bin/cat /etc/sysconfig/authconfig  > sysconfig-authconfig.txt 2>&1;  # Display authconfig configuration (RHEL only) and save to sysconfig-authconfig.txt
/usr/sbin/pwck -r > usrck.txt 2>&1 ;  # Verify integrity of password files and save to usrck.txt
/sbin/auditd -l > audit-subsystem.txt 2>&1 ;  # Display audit subsystem status and save to audit-subsystem.txt
/sbin/iptables --list > iptables-list.txt;  # List iptables rules and save to iptables-list.txt
/sbin/iptables-save > iptables-save.txt 2>&1;  # Save iptables rules to a file and save output to iptables-save.txt

# Privilege Access
/bin/cat /etc/sudoers > sudoers.txt ;  # Display sudoers configuration and save to sudoers.txt
for sf in $(/bin/ls -1 /etc/sudoers.d); do  # Loop through sudoers.d files
    /bin/echo "== included file: ${sf} =========================" ;  # Print included file header
    /bin/cat /etc/sudoers.d/${sf} 2>&1 ;  # Display contents of sudoers.d file and append to sudoers.txt
done >> sudoers.txt;  # Append to sudoers.txt
/bin/cat /etc/sudo.env > sudo_env.txt 2>&1 ;  # Display sudo environment configuration and save to sudo_env.txt

# Processes/Services
/bin/ps -def > ps-ef.txt ;  # Display current processes and save to ps-ef.txt
/sbin/sysctl -a >> sysctl.txt 2>&1 ;  # Display kernel parameters and save to sysctl.txt
/bin/netstat -lnutp > netstat.txt ;  # Display network connections and save to netstat.txt
/bin/cat /etc/inetd.conf > inetd_conf.txt 2>&1 ;  # Display inetd configuration and save to inetd_conf.txt
/bin/cat /etc/xinetd.conf > xinetd_conf.txt 2>&1 ;  # Display xinetd configuration and save to xinetd_conf.txt
/bin/ls -la /etc/xinetd.d

 >> xinetd.d.txt 2>&1 ;  # List xinetd.d directory contents and save to xinetd.d.txt
/usr/sbin/service --status-all > services.txt 2>&1 ;  # Display service status and save to services.txt
/bin/systemctl -t service --state=active > systemctl.txt 2>&1 ;  # Display active services (RHEL 7) and save to systemctl.txt
/sbin/chkconfig --list >> services.txt 2>&1 ;  # List system services (if not Debian/Ubuntu) and append to services.txt
/bin/systemctl list-unit-files >> services.txt 2>&1 ;  # List unit files (RHEL 7) and append to services.txt

# Remote Access
/bin/cat /etc/ssh/sshd_config > sshd_config.txt ;  # Display SSH server configuration and save to sshd_config.txt
/bin/ls -l /etc/hosts.equiv > hosts_equiv.txt 2>&1 ;  # Display hosts.equiv file permissions and save to hosts_equiv.txt
/bin/cat /etc/hosts.equiv >> hosts_equiv.txt 2>&1 ;  # Display contents of hosts.equiv and append to hosts_equiv.txt
/bin/cat /etc/snmp/snmp*.conf > snmp_conf.txt 2>&1 ;  # Display SNMP configuration and save to snmp_conf.txt
/bin/cat /etc/motd > motd.txt 2>&1 ;  # Display message of the day and save to motd.txt

# Logging / Logs
/usr/bin/find /etc/ -iname '*syslog*\.conf' -exec  cat {} > syslog_conf.txt 2>&1 \;  # Find and display syslog configuration files and save to syslog_conf.txt
/bin/cat /etc/logrotate.conf > logrotate.txt 2>&1;  # Display logrotate configuration and save to logrotate.txt
/bin/cat /etc/logrotate.d/*syslog >> logrotate.txt 2>&1;  # Append logrotate syslog configuration files and save to logrotate.txt
/usr/bin/last > last.txt ;  # Display last logged in users and save to last.txt
/usr/bin/lastlog > lastlog.txt ;  # Display lastlog information and save to lastlog.txt
/bin/cat /var/log/secure > securelog.txt ;  # Display secure log and save to securelog.txt
/bin/cat /var/*/sudo.log > sudolog.txt 2>&1 ;  # Display sudo logs and save to sudolog.txt
/usr/bin/utmpdump /var/log/wtmp > wtmpdump.txt 2>&1 ;  # Display wtmp content and save to wtmpdump.txt
/usr/bin/utmpdump /var/log/btmp > btmpdump.txt 2>&1 ;  # Display btmp content and save to btmpdump.txt

sudolog=$(/usr/bin/grep "Defaults logfile" /etc/sudoers | /usr/bin/sed 's/^.*=//') ;  # Get sudo log file location
if [ "${sudolog}" != "" ]; then
   /usr/bin/echo "== SUDOLOG ${sudolog} =========================" > sudolog2.txt ;  # Print sudo log file header
   /bin/cat $sudolog >> sudolog2.txt 2>&1 ;  # Display sudo log file contents and append to sudolog2.txt
fi

/bin/cat /etc/profile > profile.txt ;  # Display profile file content and save to profile.txt
for pe1 in / /root /home /etc /opt /usr /var/log /etc/security /etc/ssh /etc/pam.d \  # Loop through specified directories
    /etc/sysconfig /var/spool/cron /var/spool/cron/crontabs /etc/profile.d ; do
    if [ "X${pe1}" != "X/" ]; then
        pe2=$(/bin/echo ${pe1} | /usr/bin/tr '/' '_' | /bin/sed -e 's/^_//') ;  # Replace / with _ in directory path
    else pe2='fsroot-perms.txt' ;  # Set pe2 to 'fsroot-perms.txt' if directory is root
    fi;
    /bin/ls -lac ${pe1} > ${pe2}-perms.txt 2>&1 ;  # List directory permissions and save to ${pe2}-perms.txt
    /usr/bin/stat ${pe1} >> ${pe2}-perms.txt 2>&1 ;  # Display file status and save to ${pe2}-perms.txt
done;

# Supplementary root crontabs
/bin/ls -la /etc/cron* > crontab_root.txt 2>&1 ;  # List root crontabs and save to crontab_root.txt

# User Crawler
uidmin=$(/usr/bin/awk '$1 ~ /^UID_MIN/ {print $2}' /etc/login.defs) ;  # Get UID_MIN from login.defs
/bin/echo "UID_MIN=${uidmin}" > pwchages.txt ;  # Print UID_MIN to pwchages.txt
if [[ -z ${uidmin} ]] ; then  # If UID_MIN is not set
    uidmin=100  # Set UID_MIN to default value 100
fi
while read lg; do
    lid=$(/bin/echo ${lg} | /usr/bin/awk -F: '{print $3}') ;  # Get UID from passwd entry
    if [[ $lid -ge $uidmin || $lid -eq 0 ]]; then  # If UID is greater than or equal to UID_MIN or UID is 0 (root)
        ln=$(/bin/echo ${lg} | /usr/bin/awk -F: '{print $1}') ;  # Get username
        /bin/echo "== PWCHGS ${ln} =========================" >> pwchages.txt ;  # Print username header to pwchages.txt
        /usr/bin/chage -l ${ln} >> pwchages.txt ;  # Display user password change information and append to pwchages.txt
        /bin/echo "== PRIVS ${ln} =========================" >> sudoable.txt ;  # Print username header to sudoable.txt
        sudo -lU ${ln} >> sudoable.txt ;  # Display sudo privileges for user and append to sudoable.txt
        /bin/echo "== SSH ${ln} =========================" >> keys.txt ;  # Print username header to keys.txt
        hd=$(/bin/echo ${lg} | /usr/bin/awk -F: '{print $6}') ;  # Get user's home directory
        /bin/ls -la ${hd}/.ssh >> keys.txt 2>&1 ;  # List .ssh directory contents and save to keys.txt
        /bin/echo "== SSHKPUB ${ln} =========================" >> keys.txt ;  # Print username header to keys.txt
        /bin/cat ${hd}/.ssh/authorized_keys >> keys.txt 2>&1 ;  # Display authorized_keys file contents and append to keys.txt
        /bin/cat ${hd}/.ssh/authorized_keys2 >> keys.txt 2>&1 ;  # Display authorized_keys2 file contents and append to keys.txt
        /

bin/echo "== SSHK ${ln} =========================" >> keys.txt ;  # Print username header to keys.txt
        /bin/cat ${hd}/.ssh/id_* >> keys.txt 2>&1 ;  # Display SSH keys and append to keys.txt
        for sinit in .profile .bashrc .bash_profile .login .kshrc .cshrc .tcshrc ; do  # Loop through shell initialization files
            /bin/echo "== PROFILE ${ln} ${hd}/${sinit} ============" >> sinit_${ln}.txt ;  # Print username and file header to sinit_${ln}.txt
            /bin/ls -l ${hd}/$sinit 2>/dev/null >> sinit_${ln}.txt ;  # Display file permissions and append to sinit_${ln}.txt
            /bin/cat ${hd}/$sinit 2>/dev/null >> sinit_${ln}.txt ;  # Display file contents and append to sinit_${ln}.txt
        done;
        /bin/echo "== HOMEFILES ${ln} =========================" > homedir_${ln}.txt ;  # Print username header to homedir_${ln}.txt
        /bin/ls -lac ${hd} >> homedir_${ln}.txt ;  # List home directory contents and save to homedir_${ln}.txt
        if [ -f /var/spool/cron/crontabs/${ln} ] ; then  # If user has a crontab
            /bin/echo "== CRONTABS ${ln} =========================" > crontab_${ln}.txt ;  # Print username header to crontab_${ln}.txt
            /bin/ls -lc /var/spool/cron/crontabs/${ln} >> crontab_${ln}.txt ;  # List crontab file and save to crontab_${ln}.txt
            /bin/cat /var/spool/cron/crontabs/${ln} >> crontab_${ln}.txt ;  # Display crontab contents and append to crontab_${ln}.txt
        elif [ -f /var/spool/cron/${ln} ] ; then  # If user has a system-wide crontab
            /bin/echo "== CRONTABS ${ln} =========================" > crontab_${ln}.txt ;  # Print username header to crontab_${ln}.txt
            /bin/ls -lc /var/spool/cron/${ln} >> crontab_${ln}.txt ;  # List crontab file and save to crontab_${ln}.txt
            /bin/cat /var/spool/cron/${ln} >> crontab_${ln}.txt ;  # Display crontab contents and append to crontab_${ln}.txt
        fi
        for uf1 in $(/usr/bin/crontab -l ${ln} | /usr/bin/awk '{print $6}' | \
            /usr/bin/grep "^/" | /usr/bin/sort | /usr/bin/uniq) ; do  # Loop through cron jobs
            /bin/echo "== CRONTARGETPERM ${ln};${hd} =========================" ;  # Print username and directory header
            /bin/ls -ld ${uf1} ;  # List directory permissions
            /bin/echo "== CRONTARGETCONTENTS ${ln};${uf1} =========================" ;  # Print username and file header
            /usr/bin/strings ${uf1} ;  # Display file contents
        done 2>/dev/null >> cron_targetfiles.txt ;  # Redirect error output and append to cron_targetfiles.txt
        if [ -f ${hd}/.netrc ] ; then  # If .netrc file exists
            /bin/ls -l ${hd}/.netrc >> rperms_${ln}.txt ;  # List .netrc file permissions and save to rperms_${ln}.txt
            /usr/bin/stat ${hd}/.netrc >> rperms_${ln}.txt ;  # Display file status and append to rperms_${ln}.txt
        fi ;
        if [ -f ${hd}/.rhosts ] ; then  # If .rhosts file exists
            /bin/cat ${hd}/.rhosts >> rperms_${ln}.txt ;  # Display .rhosts file contents and append to rperms_${ln}.txt
            /bin/ls -l ${hd}/.rhosts >> rperms_${ln}.txt ;  # List .rhosts file permissions and append to rperms_${ln}.txt
            /usr/bin/stat ${hd}/.rhosts >> rperms_${ln}.txt ;  # Display file status and append to rperms_${ln}.txt
        fi ;
    fi ;
done < ge-passwd.txt ;

# Package/Patch ###################
/usr/bin/which bash > shellshock.txt  # Check if bash is installed and save to shellshock.txt
env x='() { :;}; echo bash vulnerable' bash -c 'echo bash ok' >> shellshock.txt ;  # Test for Shellshock vulnerability and append result to shellshock.txt
exec 2>> sudoshock.txt && sudoedit -s '\' $(perl -e 'print "A" x 65536') 2>&1 >> sudoshock.txt &  # Test for sudo vulnerability and append result to sudoshock.txt
sudo -V >> sudoshock.txt;  # Get sudo version and append to sudoshock.txt

# RedHat/SuSE/Oracle/CentOS/Fedora
rpm -qa --qf '%{INSTALLTIME}~%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' > rpm2vuln.txt 2>&1 ;  # List installed packages with installation time and save to rpm2vuln.txt
rpm -qa --last > rpm-revinstorder.txt 2>&1 ;  # List installed packages in reverse installation order and save to rpm-revinstorder.txt

# RHEL 5 and higher Systems
/bin/cat /var/log/yum.log > yum-update-history.txt 2>&1 ;  # Display YUM update history and save to yum-update-history.txt

# RHEL 7 and higher Systems
yum list-sec > yum-listsec.txt 2>&1 ;  # List security updates available via YUM and save to yum-listsec.txt

# SLES 11 and higher Systems ONLY
/bin/cat /var/log/zypp/history > zypp-update-history.txt 2>&1 ;  # Display Zypper update history and save to zypp-update-history.txt

# ALL
/usr/bin/sha256sum ./*.txt > sha256.sum  # Calculate SHA-256 checksums for all .txt files and save to sha256.sum
