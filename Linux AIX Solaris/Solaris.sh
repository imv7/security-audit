#!/bin/ksh

export LANG=C

# sysID
/usr/bin/nawk 'BEGIN{print srand()}' > epoch.txt        # Generate a random number for use as system ID
/usr/bin/hostname > sysinfo.txt 2>&1                     # Collect system hostname
/usr/bin/uname -sr >> sysinfo.txt 2>&1                   # Collect operating system information
/usr/bin/cat /etc/*release >> sysinfo.txt 2>&1            # Append release information to system info
/usr/bin/uptime >> sysinfo.txt 2>&1                      # Collect system uptime
/usr/bin/cat /var/sadm/system/admin/INST_RELEASE >> sysinfo.txt 2>&1  # Collect Solaris installation information
/usr/bin/cat /var/sadm/system/admin/CLUSTER >> sysinfo.txt 2>&1       # Append cluster information to system info
/usr/sbin/zoneadm list -cv >> sysinfo.txt 2>&1           # Collect and append zone information
/sbin/ifconfig -a >> sysinfo.txt 2>&1                    # Collect network interface information
/usr/bin/netstat -rn >> sysinfo.txt 2>&1                 # Collect routing table information

# Disks, Mounts, Exports
/usr/sbin/mount > mountedfs.txt 2>&1                     # Collect mounted file systems information
/usr/bin/cat /etc/vfstab >> mountedfs.txt 2>&1           # Append vfstab information to mounted file systems
/usr/bin/cat /etc/auto_master > auto_master.txt 2>&1     # Collect and redirect auto master configuration
/bin/df -h > df-h.txt 2>&1                               # Collect disk space usage information
/usr/bin/cat /etc/dfs/sharetab > exportedfs.txt 2>&1     # Collect DFS shares information
/usr/bin/cat /etc/dfs/dfstab >> exportedfs.txt 2>&1      # Append DFSTAB information to DFS shares
/usr/sbin/showmount -e localhost >> exportedfs.txt 2>&1 # Append NFS exported shares information

# Security Config Files
/usr/bin/cat /etc/hosts > hosts.txt                     # Collect hosts file information
/usr/bin/cat /etc/default/login > login_defs.txt        # Collect login defaults information
/usr/bin/cat /etc/default/passwd >> login_defs.txt      # Append password defaults to login defaults
/usr/bin/cat /etc/pam.conf > pamd-conf.txt             # Collect PAM configuration information
/usr/bin/cat /etc/securetty > securetty.txt            # Collect securetty configuration information
/usr/bin/cat /etc/ftpusers > ftpusers.txt              # Collect FTP users information
/usr/bin/cat /etc/passwd > passwd.txt                  # Collect password file information
/usr/bin/cat /etc/shadow > shadow.txt                  # Collect shadow file information
/usr/bin/cat /etc/group > group.txt                    # Collect group file information
/usr/bin/cat /etc/security/policy.conf > policy_conf.txt  # Collect security policy information
/usr/bin/getent passwd > ge-passwd.txt                 # Collect passwd entries via getent
/usr/bin/getent group > ge-group.txt                   # Collect group entries via getent
/usr/sbin/pwck /etc/passwd 2> pwck.txt                # Perform passwd file consistency check
/usr/sbin/grpck /etc/group 2> grpck.txt               # Perform group file consistency check
/usr/bin/passwd -sa > pwchanges.txt                   # Collect password aging information

# Privileged Access
sstat() { /usr/bin/truss -t lstat64 -v lstat64 ls ${1} | /usr/bin/tail -0; }; export sstat  # Define and export sstat function
/usr/bin/cat /etc/sudoers > sudoers.txt              # Collect sudoers file information
for sf in $(/usr/bin/ls -1 /etc/sudoers.d); do      # Loop through sudoers.d directory
    /usr/bin/echo "== included file: ${sf} ========================="   # Print included file header
    /usr/bin/cat /etc/sudoers.d/${sf} 2>&1         # Collect content of sudoers.d files
done >> sudoers.txt                                   # Redirect sudoers.d content to sudoers file
/usr/bin/cat /etc/sudo.env > sudo_env.txt 2>&1       # Collect sudo environment information
/usr/bin/cat /etc/user_attr > rbac-user_attr.txt 2>&1  # Collect user attributes information
/usr/bin/cat /etc/security/auth_attr > rbac-auth_attr.txt 2>&1   # Collect authorization attributes information
/usr/bin/cat /etc/security/prof_attr > rbac-prof_attr.txt 2>&1    # Collect profile attributes information

# Processes/Services
if [ $(uname -r) = '5.11' ]; then                   # Check if Solaris version is 5.11
    /usr/bin/netstat -auf inet > netstat.txt 2>&1    # Collect network statistics
    /usr/bin/ps -eZf > ps-ef.txt 2>&1               # Collect process information with labels
else
    /usr/bin/netstat -af inet > netstat.txt 2>&1    # Collect network statistics
    /usr/bin/ps -ef > ps-ef.txt 2>&1                # Collect process information
fi
/usr/bin/cat /etc/inetd.conf > inetd_conf.txt 2>&1   # Collect inetd configuration
/usr/sbin/inetadm >> inetd_conf.txt 2>&1             # Append inetadm information to inetd configuration
/usr/bin/ls -l /etc/rc*.d > services.txt 2>&1       # List startup services directories
/usr/bin/svcs -a >> services.txt 2>&1               # Append service status information
/usr/sbin/inetadm >> services.txt 2>&1              # Append inetadm information to services file

# Remote Access
/usr/bin/cat /etc/ssh/sshd_config > sshd_config.txt 2>&1  # Collect SSH daemon configuration
/usr/bin/cat /etc/hosts.equiv > hosts_equiv.txt 2>&1      # Collect hosts.equiv information
/usr/bin/cat /etc/motd > motd.txt 2>&1                   # Collect MOTD information
/usr/bin/cat /etc/issue > issue.txt 2>&1                 # Collect system issue information

# Logging / Logs
/usr/bin/cat /etc/syslog.conf > syslog_conf.txt 2>&1      # Collect syslog configuration
/usr/bin/cat /etc/logadm.conf > logrotate.txt 2>&1        # Collect log rotation configuration
/usr/bin/last > last.txt 2>&1                            # Collect last logged in users
/usr/bin/cat /var/*/sudo.log > sudo_log.txt 2>&1          # Collect sudo logs
/usr/bin/cat /var/ad

m/wtmpx > wtmp.bin                   # Copy wtmpx to wtmp.bin
/usr/bin/cat /var/adm/sulog > sulog.txt 2>&1             # Collect sulog information
/usr/bin/cat /var/*/authlog > authlog.txt 2>&1           # Collect authentication logs
/usr/lib/acct/fwtmp < /var/adm/wtmpx > wtmpdump.txt 2>&1 # Convert wtmpx to text format

/usr/bin/cat /etc/profile > profile.txt                  # Collect profile information
for pe1 in / /root /home /etc /etc/ssh /opt /usr /var/log /var/adm /etc/default \
    /etc/security /net /vol /var/spool/cron/crontabs /etc/profiles.d; do    # Loop through directories for permissions
    if [ "X${pe1}" != "X/" ]; then
        pe2=$(echo ${pe1} | /usr/bin/tr '/' '_' | /usr/bin/sed -e 's/^_//')
    else
        pe2='fsroot-perms.txt'
    fi
    /usr/bin/ls -la ${pe1} > ${pe2}-perms.txt 2>&1     # Collect directory permissions
    sstat ${pe1} >> ${pe2}-perms.txt 2>&1             # Collect status information of directories
done

# User Crawler
uidmin=100                                           # Set minimum UID value
while read lg; do                                   # Loop through /etc/passwd entries
    lid=$(/usr/bin/echo ${lg} | /usr/bin/awk -F: '{print $3}')  # Get UID
    if [[ $lid -ge $uidmin || $lid -eq 0 ]]; then   # Check if UID is within range
        ln=$(/usr/bin/echo ${lg} | /usr/bin/awk -F: '{print $1}')  # Get username
        /usr/bin/echo "== PWCHGS ${ln} =========================" >> pwchages.txt   # Print password change header
        /usr/bin/passwd -s ${ln} >> pwchages.txt    # Collect password change information
        /usr/bin/echo "== PRIVS ${ln} =========================" >> sudoable.txt    # Print privilege header
        sudo -lU ${ln} >> sudoable.txt              # Collect sudo privileges information
        /usr/bin/echo "== SSH ${ln} =========================" >> keys.txt           # Print SSH header
        hd=$(/usr/bin/echo ${lg} | /usr/bin/awk -F: '{print $6}')  # Get home directory
        /usr/bin/ls -la ${hd}/.ssh >> keys.txt 2>&1 # Collect SSH directory information
        /usr/bin/echo "== SSHKPUB ${ln} =========================" >> keys.txt        # Print SSH public key header
        /usr/bin/cat ${hd}/.ssh/authorized_keys* >> keys.txt 2>&1 # Collect authorized keys
        /usr/bin/echo "== SSHK ${ln} =========================" >> keys.txt           # Print SSH key header
        /usr/bin/cat ${hd}/.ssh/id_* >> keys.txt 2>&1  # Collect SSH keys
        for sinit in .profile .bashrc .bash_profile .login .kshrc .cshrc .tcshrc; do   # Loop through shell init files
            /usr/bin/echo "== PROFILE ${ln} ${hd}/${sinit} ============" >> sinit_${ln}.txt  # Print shell init header
            /usr/bin/ls -l ${hd}/$sinit 2>/dev/null >> sinit_${ln}.txt     # Collect shell init file permissions
            /usr/bin/cat ${hd}/$sinit 2>/dev/null >> sinit_${ln}.txt       # Collect shell init file content
        done
        /usr/bin/echo "== HOMEFILES ${ln} =========================" > homedir_${ln}.txt   # Print home directory header
        /usr/bin/ls -lac ${hd} >> homedir_${ln}.txt    # Collect home directory information
        if [ -f /var/spool/cron/crontabs/${ln} ]; then  # Check if user has a crontab
            /usr/bin/echo "== CRONTABS ${ln} =========================" > crontab_${ln}.txt   # Print crontab header
            /usr/bin/ls -lc /var/spool/cron/crontabs/${ln} >> crontab_${ln}.txt 2>&1     # Collect crontab permissions
            /usr/bin/cat /var/spool/cron/crontabs/${ln} >> crontab_${ln}.txt 2>&1       # Collect crontab content
        fi
        for uf1 in $(/usr/bin/crontab -l ${ln} | /usr/bin/awk '{print $6}' | \
            /usr/bin/grep "^/" | /usr/bin/sort | /usr/bin/uniq); do       # Loop through cron job files
            /usr/bin/echo "== CRONTARGETPERM ${ln};${hd} ========================="    # Print cron job target permissions header
            /usr/bin/ls -ld ${uf1}                      # Collect cron job target permissions
            /usr/bin/echo "== CRONTARGETCONTENTS ${ln};${uf1} ========================="  # Print cron job target contents header
            /usr/bin/strings ${uf1}                     # Collect cron job target contents
        done 2>/dev/null >> cron_targetfiles.txt      # Redirect cron job target information to file
        if [ -f ${hd}/.netrc ]; then                   # Check if .netrc file exists
            /usr/bin/ls -l ${hd}/.netrc >> rperms_${ln}.txt 2>&1    # Collect .netrc file permissions
            sstat ${hd}/.netrc >> rperms_${ln}.txt 2>&1           # Collect .netrc file status
        fi
        if [ -f ${hd}/.rhosts ]; then                  # Check if .rhosts file exists
            /usr/bin/cat ${hd}/.rhosts >> rperms_${ln}.txt 2>&1    # Collect .rhosts file content
            /usr/bin/ls -l ${hd}/.rhosts >> rperms_${ln}.txt 2>&1  # Collect .rhosts file permissions
            sstat ${hd}/.rhosts >> rperms_${ln}.txt 2>&1          # Collect .rhosts file status
        fi
    fi
done < /etc/passwd                                   # Redirect input from /etc/passwd

# Package Dump
/usr/bin/which bash > shellshock.txt                # Check if system is vulnerable to Shellshock
env x='() { :;}; echo bash vulnerable' bash -c 'echo bash ok' >> shellshock.txt  # Append Shellshock status
sudoedit -s '\' $(perl -e 'print "A" x 65536') 2>&1 > sudoshock.txt   # Check sudo for overflow vulnerability

for pkgname in

 $(/usr/bin/pkginfo -i | awk '{ print $2 }'); do    # Loop through installed packages
    echo "${pkgname},$(grep '^NAME=' /var/sadm/pkg/${pkgname}/pkginfo | \
    sed -e 's/NAME=//'),$(grep 'VERSION=' /var/sadm/pkg/${pkgname}/pkginfo | \
    sed -e 's/VERSION=//'),$(grep 'INSTDATE=' /var/sadm/pkg/${pkgname}/pkginfo | \
    sed -e 's/INSTDATE=//')"                               # Collect package information
done > pkglist.txt                                      # Redirect package information to file
if [ $(uname -r) = '5.10' ]; then                      # Check if Solaris version is 5.10
    grep -h PATCH_INFO_ /var/sadm/pkg/SUNW*/pkginfo | sed -e 's/From:.*//' \
    -e 's/PATCH_INFO_//' | cut -c0-50 | awk '{ print $1" "$2" "$3" "$4" "$7 }' | \
    sort -u > patch-history.txt                        # Collect patch history information
fi
/usr/bin/digest -va sha256 ./*.txt > sha256.sum       # Generate SHA256 checksums for collected files