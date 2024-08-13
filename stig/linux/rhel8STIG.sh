#!/bin/bash

set -x
# Exit on any error
set -e  

# Log file
LOG_FILE="/var/log/rhel8STIG.log"
exec 1>>${LOG_FILE} 2>&1

# only run once during deployment
if [ -f ./azAutomationComplete ]; then
    echo "STIG Automation completed, exiting..."
    exit 0
fi

echo "Setting script variables"
version=$(. /etc/os-release && echo $VERSION_ID)

echo "Enabling Microsoft Repos"
yum update -y --disablerepo='*' --enablerepo='*microsoft*'

echo "Automating Rule Id V-230233"
sed -i.bak "s/\(password\s*sufficient.*\)/\1 rounds=5000/g" /etc/pam.d/password-auth /etc/pam.d/system-auth
echo "V-230233 completed"

echo "Automating Rule Id V-230234"
firmwarecheck=$([ -d /sys/firmware/efi ] && echo UEFI || echo BIOS)
if [ $firmwarecheck = 'BIOS' ]; then
    mv /boot/efi/EFI/redhat/grub.cfg /boot/efi/EFI/redhat/grub.bak
fi
echo "V-230234 completed"

echo "Automating Rule Id V-230253"
sed -i.bak "s/^SSH_USE_STRONG_RNG=.*/SSH_USE_STRONG_RNG=32/g" /etc/sysconfig/sshd
echo "V-230253 completed"

echo "Automating Rule Id V-230257"
find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /0022 -type f -exec chmod 0755 {} \;
echo "V-230257 completed"

echo "Automating Rule Id V-230271"
grep -r -l -i nopasswd /etc/sudoers.d/* /etc/sudoers | xargs sed -i.bak 's/\s*NOPASSWD://g' 2>&1
echo "V-230271 completed"

echo "Automating Rule Id V-230287"
chmod 0600 /etc/ssh/ssh_host*key
echo "V-230287 completed"

echo "Automating Rule Id V-230301"
sed -i.bak "s/\(.*[[:space:]]\/[[:alpha:]].*defaults\)/\1,nodev/g" /etc/fstab
echo "V-230301 completed"

echo "Automating Rule Id V-230311"
rm -f /usr/lib/sysctl.d/50-coredump.conf
echo "kernel.core_pattern = |/bin/false" > /etc/sysctl.d/90-azurestig-v230311.conf
echo "V-230311 completed"

echo "Automating Rule Ids V-230332, V-230334, V-230336, V-230338, V-230340, V-230342, V-230344"
if [ "${version}" == '8.0' ] || [ "${version}" == '8.1' ]; then
    authRequired='auth        required'
    acctRequired='account     required'
    spacing='                                     '
    authFaillockPreAuth='pam_faillock.so preauth dir=\/var\/log\/faillock silent audit deny=3 even_deny_root fail_interval=900 unlock_time=0'
    authFaillockAuthFail='pam_faillock.so authfail dir=\/var\/log\/faillock unlock_time=0'
    sed -i.bak "s/\(auth.*pam_unix.so.*\)/${authRequired}${spacing}${authFaillockPreAuth}\n\1/g" /etc/pam.d/password-auth /etc/pam.d/system-auth
    sed -i "s/\(auth.*pam_unix.so.*\)/\1\n${authRequired}${spacing}${authFaillockAuthFail}/g" /etc/pam.d/password-auth /etc/pam.d/system-auth
    sed -i "s/\(account.*pam_unix.so\)/${acctRequired}${spacing}pam_faillock.so\n\1/g" /etc/pam.d/password-auth /etc/pam.d/system-auth
else
    echo "  Automation intended for 8.0 and 8.1; '$version' detected, skipping..."
fi
echo "V-230332, V-230334, V-230336, V-230338, V-230340, V-230342, V-230344 completed"

echo "Automating Rule Id V-230333"
if [ "${version}" == '8.0' ] || [ "${version}" == '8.1' ]; then
    echo "  Automation intended for 8.2 and newer, '$version' detected, skipping..."
else
    authRequiredFaillock='auth        required      pam_faillock.so'
    acctRequiredFaillock='account     required      pam_faillock.so'
    sed -i.bak "s/\(auth.*required.*pam_env.so\)/\1\n${authRequiredFaillock} preauth/g" /etc/pam.d/password-auth /etc/pam.d/system-auth
    sed -i "s/\(auth.*required.*pam_deny.so\)/${authRequiredFaillock} authfail\n\1/g" /etc/pam.d/password-auth /etc/pam.d/system-auth
    sed -i "s/\(account.*required.*pam_unix.so\)/${acctRequiredFaillock}\n\1/g" /etc/pam.d/password-auth /etc/pam.d/system-auth
    sed -i "s/.*deny\s*=.*/deny = 3/g" /etc/security/faillock.conf
fi
echo "V-230333 completed"

echo "Automating Rule Id V-230335"
if [ "${version}" == '8.0' ] || [ "${version}" == '8.1' ]; then
    echo "  Automation intended for 8.2 and newer, '$version' detected, skipping..."
else
    sed -i.bak "s/.*fail_interval\s*=.*/fail_interval = 900/g" /etc/security/faillock.conf
fi
echo "V-230335 completed"

echo "Automating Rule Id V-230337"
if [ "${version}" == '8.0' ] || [ "${version}" == '8.1' ]; then
    echo "  Automation intended for 8.2 and newer, '$version' detected, skipping..."
else
    sed -i.bak "s/^\(#\|\)[[:space:]]*unlock_time\s*=.*/unlock_time = 0/g" /etc/security/faillock.conf
fi
echo "V-230337 completed"

echo "Automating Rule Id V-230341"
if [ "${version}" == '8.0' ] || [ "${version}" == '8.1' ]; then
    echo "  Automation intended for 8.2 and newer, '$version' detected, skipping..."
else
    if grep -q -i silent /etc/security/faillock.conf; then
        sed -i.bak "s/.*silent.*/silent/g" /etc/security/faillock.conf
    else
        echo "silent" >> /etc/security/faillock.conf
    fi
fi
echo "V-230341 completed"

echo "Automating Rule Id V-230343"
if [ "${version}" == '8.0' ] || [ "${version}" == '8.1' ]; then
    echo "  Automation intended for 8.2 and newer, '$version' detected, skipping..."
else
    if grep -q -i audit /etc/security/faillock.conf; then
        sed -i.bak "s/.*audit.*/audit/g" /etc/security/faillock.conf
    else
        echo "audit" >> /etc/security/faillock.conf
    fi
fi
echo "V-230343 completed"

echo "Automating Rule Id V-230345"
if [ "${version}" == '8.0' ] || [ "${version}" == '8.1' ]; then
    echo "  Automation intended for 8.2 and newer, '$version' detected, skipping..."
else
    sed -i.bak "s/^\(#\|\)[[:space:]]*even_deny_root.*/even_deny_root/g" /etc/security/faillock.conf
fi
echo "V-230345 completed"

echo "Automating Rule Id V-230349"
echo 'if [ "$PS1" ]; then' >> /etc/profile.d/230348-customshell.sh
echo 'parent=$(ps -o ppid= -p $$)' >> /etc/profile.d/230348-customshell.sh
echo 'name=$(ps -o comm= -p $parent)' >> /etc/profile.d/230348-customshell.sh
echo 'case "$name" in (sshd|login) exec tmux ;; esac' >> /etc/profile.d/230348-customshell.sh
echo 'fi' >> /etc/profile.d/230348-customshell.sh
echo "V-230349 completed"

echo "Automating Rule Id V-230367"
chage -M 60 $1
chage -M 60 root
echo "V-230367 completed"

echo "Automating Rule Id V-230368"
passwordRequired='password    required'
spacing='      '
passwordReqPwHist='pam_pwhistory.so use_authtok remember=5 retry=3'
sed -i.bak "s/\(password.*pam_unix.so.*\)/${passwordRequired}${spacing}${passwordReqPwHist}\n\1/g" /etc/pam.d/password-auth /etc/pam.d/system-auth
echo "V-230368 completed"

echo "Automating Rule Id V-230373"
useradd -D -f 35
echo "V-230373 completed"

echo "Automating Rule Id V-230380"
sed -i.bak 's/\s*nullok\s*/ /g' /etc/pam.d/system-auth /etc/pam.d/password-auth
sed -i "s/.*PermitEmptyPasswords.*/PermitEmptyPasswords no/g" /etc/ssh/sshd_config
echo "V-230380 completed"

echo "Automating Rule Id V-230439"
echo '-a always,exit -F arch=b32 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete' >> /etc/audit/rules.d/audit.rules
echo "V-230439 completed"

echo "Automating Rule Id V-230485"
if ! grep -q -w 'port' /etc/chrony.conf; then
    echo 'port 0' >> /etc/chrony.conf
else
    sed -i.bak 's/\(^port\|^#port\).*/port 0/g' /etc/chrony.conf
fi
echo "V-230485 completed"

echo "Automating Rule Id V-230486"
if ! grep -q -w 'cmdport' /etc/chrony.conf; then
    echo 'cmdport 0' >> /etc/chrony.conf
else
    sed -i.bak 's/\(^cmdport\|^#cmdport\).*/cmdport 0/g' /etc/chrony.conf
fi
echo "V-230486 completed"

echo "Automating Rule Id V-230494"
echo 'install atm /bin/true' > /etc/modprobe.d/atm.conf
echo 'blacklist atm' >> /etc/modprobe.d/blacklist.conf
echo "V-230494 completed"

echo "Automating Rule Id V-230495"
echo 'install can /bin/true' > /etc/modprobe.d/can.conf
echo 'blacklist can' >> /etc/modprobe.d/blacklist.conf
echo "V-230495 completed"

echo "Automating Rule Id V-230496"
echo 'install sctp /bin/true' > /etc/modprobe.d/sctp.conf
echo 'blacklist sctp' >> /etc/modprobe.d/blacklist.conf
echo "V-230496 completed"

echo "Automating Rule Id V-230497"
echo 'install tipc /bin/true' > /etc/modprobe.d/tipc.conf
echo 'blacklist tipc' >> /etc/modprobe.d/blacklist.conf
echo "V-230497 completed"

echo "Automating Rule Id V-230498"
echo 'install cramfs /bin/true' > /etc/modprobe.d/cramfs.conf
echo 'blacklist cramfs' >> /etc/modprobe.d/blacklist.conf
echo "V-230498 completed"

echo "Automating Rule Id V-230499"
echo 'install firewire-core /bin/true' > /etc/modprobe.d/firewire-core.conf
echo 'blacklist firewire-core' >> /etc/modprobe.d/blacklist.conf
echo "V-230499 completed"

echo "Automating Rule Id V-230503"
echo 'install usb-storage /bin/true' > /etc/modprobe.d/usb-storage.conf
echo 'blacklist usb-storage' >> /etc/modprobe.d/blacklist.conf
echo "V-230503 completed"

echo "Automating Rule Id V-230507"
echo 'install bluetooth /bin/true' > /etc/modprobe.d/bluetooth.conf
echo "V-230507 completed"

echo "Automating Rule Ids V-230508, V-230509, V-230510"
echo 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0' >> /etc/fstab
echo "V-230508, V-230509, V-230510 completed"

echo "Automating Rule Id V-230511, V-230512, V-230513"
sed -i.bak 's/\(\/tmp.*\)defaults.*/\1defaults,nodev,nosuid,noexec 0 0/g' /etc/fstab
echo "V-230511, V-230512, V-230513 completed"

echo "Automating Rule Id V-230546"
rm -f /usr/lib/sysctl.d/10-default-yama-scope.conf
sysctl -w kernel.yama.ptrace_scope=1
echo "kernel.yama.ptrace_scope = 1" > /etc/sysctl.d/90-azurestig-v230546.conf
echo "V-230546 completed"

echo "Automating Rule Id V-237642"
echo 'Defaults !targetpw' >> /etc/sudoers.d/237642
echo 'Defaults !rootpw' >> /etc/sudoers.d/237642
echo 'Defaults !runaspw' >> /etc/sudoers.d/237642
echo "V-237642 completed"

echo "Installing Ansible for STIG automation (pip3 install)..."
pip3 install ansible --user
echo "Ansible installed"

echo "Unzipping rhel8STIG-ansible.zip to ./rhel8STIG"
unzip rhel8STIG-ansible.zip -d ./rhel8STIG
echo "Unzipped rhel8STIG-ansible.zip"

echo "Invoking ansible-playbook to automate STIG rules"
/root/.local/bin/ansible-playbook -v -b -i /dev/null ./rhel8STIG/site.yml
echo "Ansible playbook executed"

echo "Automating Rule Id V-230483"
if [ "${version}" == '8.0' ]; then
    sed -i.bak 's/25%/2048/g' /etc/audit/auditd.conf
fi
echo "V-230483 completed"

echo "Automating Rule Id V-230350"
sed -i.bak 's/.*tmux.*//g' /etc/shells
echo '---------- /etc/shells content begin ----------'
cat /etc/shells
echo '---------- /etc/shells content end ----------'
echo "V-230350 completed"

echo "Automating Rule Id V-230223"
fips-mode-setup --enable
echo "V-230223 completed"

echo "Restarting system to apply STIG settings..."
touch ./azAutomationComplete
shutdown -r +1 2>&1
set +x