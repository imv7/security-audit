#!/bin/bash

# Export Language Settings
export LANG=C

# System Information
{
    date +"%s" > epoch.txt                # Output current date in epoch format to epoch.txt
    hostname > sysinfo.txt               # Output hostname to sysinfo.txt
    uname -sr >> sysinfo.txt             # Output system name and release to sysinfo.txt
    cat /etc/*release >> sysinfo.txt     # Append contents of all release files to sysinfo.txt
    uptime >> sysinfo.txt                # Output system uptime to sysinfo.txt
    dmidecode | grep -A9 '^System Information' >> sysinfo.txt 2>&1  # Extract system information using dmidecode and append to sysinfo.txt
    ifconfig >> sysinfo.txt              # Output network interface configuration to sysinfo.txt
}

# Disks, Mounts, Exports
{
    mount > mountedfs.txt                # Output mounted filesystems to mountedfs.txt
    cat /etc/exports > exportedfs.txt 2>&1  # Output NFS exports configuration to exportedfs.txt
    showmount -e localhost >> exportedfs.txt 2>&1  # Append NFS mount information to exportedfs.txt
    cat /etc/auto.master > auto_master.txt  # Output automounter configuration to auto_master.txt
    df -k > df-k.txt                     # Output disk space usage to df-k.txt
    fdisk -l > disk-partitions.txt 2>&1  # Output disk partition information to disk-partitions.txt
    vgs > lsvg.txt                       # Output volume group information to lsvg.txt
    lvs >> lsvg.txt                      # Append logical volume information to lsvg.txt
    pvs >> lsvg.txt                      # Append physical volume information to lsvg.txt
}

# Security Config Files
{
    cat /etc/shells > shells.txt                  # Output list of allowed shells to shells.txt
    cat /etc/hosts > hosts.txt                    # Output hosts configuration to hosts.txt
    cat /etc/login.defs > login_defs.txt          # Output login definitions to login_defs.txt

    cat /etc/sssd/sssd.conf > sssd.txt 2>&1       # Output SSSD configuration to sssd.txt
    cat /etc/nsswitch.conf > nsswitch_conf.txt     # Output name service switch configuration to nsswitch_conf.txt
    cat /etc/krb5/krb5.conf > krb5_conf.txt 2>&1  # Output Kerberos configuration to krb5_conf.txt
    cat /usr/local/etc/krb5.conf >> krb5_conf.txt 2>&1  # Append additional Kerberos configuration to krb5_conf.txt
    cat /etc/pam.d/*auth > pamd-auth.txt          # Output PAM authentication configuration to pamd-auth.txt
    cat /etc/pam.d/*passwd > pamd-passwd.txt      # Output PAM password configuration to pamd-passwd.txt
    cat /etc/pam.d/*login > pamd-login.txt        # Output PAM login configuration to pamd-login.txt
    cat /etc/securetty > securetty.txt            # Output secure tty configuration to securetty.txt
    cat /etc/ftpusers > ftpusers.txt 2>&1         # Output FTP users configuration to ftpusers.txt
    cat /etc/security/access.conf > access.conf.txt  # Output access control configuration to access.conf.txt
    cat /etc/security/pwquality.conf > pwquality.conf.txt 2>&1  # Output password quality configuration to pwquality.conf.txt
    cat /etc/passwd > passwd.txt                  # Output user account information to passwd.txt
    cat /etc/group > group.txt                    # Output group information to group.txt
    auditd -l > audit-subsystem.txt 2>&1          # Output audit subsystem configuration to audit-subsystem.txt
    iptables --list > iptables-list.txt           # Output iptables rules to iptables-list.txt
    iptables-save > iptables-save.txt 2>&1        # Save iptables rules to iptables-save.txt
}

# Processes/Services
{
    ps -def > ps-ef.txt                          # Output list of processes to ps-ef.txt
    sysctl -a >> sysctl.txt 2>&1                 # Output system control parameter settings to sysctl.txt
    netstat -lnutp > netstat.txt                 # Output network statistics to netstat.txt
    cat /etc/inetd.conf > inetd_conf.txt 2>&1    # Output inetd configuration to inetd_conf.txt
    cat /etc/xinetd.conf > xinetd_conf.txt 2>&1  # Output xinetd configuration to xinetd_conf.txt
    ls -la /etc/xinetd.d >> xinetd.d.txt 2>&1    # List xinetd configuration files to xinetd.d.txt
    service --status-all > services.txt 2>&1     # Output service status to services.txt
    chkconfig --list >> services.txt 2>&1        # Append service configuration to services.txt
}

# Remote Access
{
    cat /etc/ssh/sshd_config > sshd_config.txt   # Output SSH daemon configuration to sshd_config.txt
    ls -l /etc/hosts.equiv > hosts_equiv.txt 2>&1  # Output hosts.equiv permissions to hosts_equiv.txt
    cat /etc/hosts.equiv >> hosts_equiv.txt 2>&1  # Append contents of hosts.equiv to hosts_equiv.txt
    cat /etc/motd > motd.txt 2>&1                # Output message of the day to motd.txt
}

# Logging / Logs
{
    find /etc/ -iname '*syslog*\.conf' -exec cat {} \; > syslog_conf.txt 2>&1  # Output syslog configuration to syslog_conf.txt
    cat /etc/logrotate.conf > logrotate.txt 2>&1  # Output logrotate configuration to logrotate.txt
    cat /etc/logrotate.d/*syslog >> logrotate.txt 2>&1  # Append syslog logrotate configuration to logrotate.txt
    last > last.txt                              # Output last logins to last.txt
    lastlog > lastlog.txt                        # Output lastlog information to lastlog.txt
    cat /var/*/sudo.log > sudolog.txt 2>&1       # Output sudo logs to sudolog.txt
    utmpdump /var/log/wtmp > wtmpdump.txt 2>&1   # Dump wtmp log to wtmpdump.txt
    utmpdump /var/log/btmp > btmpdump.txt 2>&1   # Dump btmp log to btmpdump.txt

    sudolog=$(grep "Defaults logfile" /etc/sudoers | sed 's/^.*=//')  # Find sudo log file location
    if [ -n "$sudolog

" ]; then
        echo "== SUDOLOG $sudolog =========================" > sudolog2.txt  # Output sudo log file location to sudolog2.txt
        cat "$sudolog" >> sudolog2.txt 2>&1       # Append sudo log contents to sudolog2.txt
    fi

    cat /etc/profile > profile.txt               # Output profile configuration to profile.txt
    for pe1 in / /root /home /etc /opt /usr /var/log /etc/security /etc/ssh /etc/pam.d \
        /etc/sysconfig /var/spool/cron /var/spool/cron/crontabs /etc/profile.d; do
        if [ "$pe1" != "/" ]; then
            pe2=$(echo "$pe1" | tr '/' '_' | sed -e 's/^_//')
        else
            pe2='fsroot-perms.txt'
        fi
        ls -lac "$pe1" > "${pe2}-perms.txt" 2>&1  # Output permissions of specified directories to respective files
        stat "$pe1" >> "${pe2}-perms.txt" 2>&1     # Append file status to respective files
    done
}

# Supplementary root crontabs
ls -la /etc/cron* > crontab_root.txt 2>&1      # Output root crontab information to crontab_root.txt

# User Crawler
{
    uidmin=$(awk '$1 ~ /^UID_MIN/ {print $2}' /etc/login.defs)  # Determine minimum UID value
    echo "UID_MIN=${uidmin}" > pwchages.txt        # Output minimum UID value to pwchages.txt
    if [ -z "$uidmin" ]; then
        uidmin=100
    fi
    while IFS=: read -r lg; do
        lid=$(echo "$lg" | awk -F: '{print $3}')  # Extract UID from passwd entry
        if [ "$lid" -ge "$uidmin" ] || [ "$lid" -eq 0 ]; then
            ln=$(echo "$lg" | awk -F: '{print $1}')  # Extract username from passwd entry
            echo "== PWCHGS $ln =========================" >> pwchages.txt  # Output password change information for user to pwchages.txt
            chage -l "$ln" >> pwchages.txt
            echo "== PRIVS $ln =========================" >> sudoable.txt  # Output sudo privileges for user to sudoable.txt
            sudo -lU "$ln" >> sudoable.txt
            echo "== SSH $ln =========================" >> keys.txt         # Output SSH keys and configuration for user to keys.txt
            hd=$(echo "$lg" | awk -F: '{print $6}')
            ls -la "${hd}/.ssh" >> keys.txt 2>&1
            echo "== SSHKPUB $ln =========================" >> keys.txt
            cat "${hd}/.ssh/authorized_keys" >> keys.txt 2>&1
            cat "${hd}/.ssh/authorized_keys2" >> keys.txt 2>&1

            for sinit in .profile .bashrc .bash_profile .login .kshrc .cshrc .tcshrc; do
                echo "== PROFILE $ln ${hd}/${sinit} ============" >> "sinit_${ln}.txt"  # Output shell initialization file information to respective files
                ls -l "${hd}/$sinit" 2>/dev/null >> "sinit_${ln}.txt"
            done
            echo "== HOMEFILES $ln =========================" > "homedir_${ln}.txt"  # Output contents of user's home directory to respective files
            ls -lac "$hd" >> "homedir_${ln}.txt"

            if [ -f "/var/spool/cron/crontabs/${ln}" ]; then
                echo "== CRONTABS $ln =========================" > "crontab_${ln}.txt"  # Output user's crontab information to respective files
                ls -lc "/var/spool/cron/crontabs/${ln}" >> "crontab_${ln}.txt"
                cat "/var/spool/cron/crontabs/${ln}" >> "crontab_${ln}.txt"
            elif [ -f "/var/spool/cron/${ln}" ]; then
                echo "== CRONTABS $ln =========================" > "crontab_${ln}.txt"
                ls -lc "/var/spool/cron/${ln}" >> "crontab_${ln}.txt"
                cat "/var/spool/cron/${ln}" >> "crontab_${ln}.txt"
            fi
            while read -r uf1; do
                echo "== CRONTARGETPERM ${ln};${hd} ========================="
                ls -ld "$uf1"                          # Output permissions of cron target files to console
                echo "== CRONTARGETCONTENTS ${ln};${uf1} ========================="
                strings "$uf1"                         # Output contents of cron target files to console
            done < <(crontab -l "$ln" | awk '{print $6}' | grep "^/" | sort | uniq) 2>/dev/null >> cron_targetfiles.txt  # Output information about cron target files to cron_targetfiles.txt
            if [ -f "${hd}/.netrc" ]; then
                ls -la "${hd}/.netrc" >> "rperms_${ln}.txt"  # Output permissions of .netrc file to respective file
                stat "${hd}/.netrc" >> "rperms_${ln}.txt"    # Append file status to respective file
            fi
            if [ -f "${hd}/.rhosts" ]; then
                ls -la "${hd}/.rhosts" >> "rperms_${ln}.txt"  # Output permissions of .rhosts file to respective file
                stat "${hd}/.rhosts" >> "rperms_${ln}.txt"    # Append file status to respective file
            fi
        fi
    done < ./passwd.txt
}

# Package/Patch ###################
{
    which bash > shellshock.txt                    # Check for presence of bash shell
    env x='() { :;}; echo bash vulnerable' bash -c 'echo bash ok' >> shellshock.txt  # Check for shellshock vulnerability and output result to shellshock.txt
    exec 2>> sudoshock.txt && sudoedit -s '\' $(perl -e 'print "A" x 65536') 2>&1 >> sudoshock.txt &  # Attempt to exploit sudo vulnerability and log results to sudoshock.txt
    sudo -V >> sudoshock.txt                      # Output sudo version information to sudoshock.txt
}

# ALL
sha256sum ./*.txt > sha256.sum                  # Compute SHA-256 checksums for all .txt files and output to sha256.sum