#!/bin/bash

set -ex

# Create the log file with the correct permissions
sudo touch /var/log/rhel8STIG.log
sudo chown $USER:$USER /var/log/rhel8STIG.log

# Log file
LOG_FILE="/var/log/rhel8STIG.log"
exec 1>>${LOG_FILE} 2>&1

# Only run once during deployment
if [ -f ./azAutomationComplete ]; then
    echo "STIG Automation completed, exiting..."
    exit 0
fi

# Set PATH and PYTHONPATH to use the locally installed Ansible
export PATH=/home/stigadmin/ato-toolkit/stig/linux/bin:$PATH
export PYTHONPATH=/home/stigadmin/ato-toolkit/stig/linux/lib/python3.6/site-packages

# Check if pip3 is already installed
if ! command -v pip3 &> /dev/null; then
    echo "Installing pip3 from get-pip.py binary..."
    sudo python3 get-pip.py --no-index --find-links ./ --trusted-host localhost
    echo "pip3 installed"
fi

# Install Ansible Core using the local wheels
echo "Installing Ansible Core for STIG automation..."
pip3 install --no-index --find-links ./ ansible-core==2.11.12 ansible==4.10.0 --prefix=/home/stigadmin/ato-toolkit/stig/linux/
echo "Ansible Core installed"

###############################################################################
echo "Setting script variables"
###############################################################################
version=$(grep VERSION_ID /etc/os-release | cut -d '"' -f 2)

###############################################################################
echo "Enabling Microsoft Repos"
###############################################################################
sudo yum update -y --disablerepo='*' --enablerepo='*microsoft*'

###############################################################################
echo "Automating Rule Id V-230233"
###############################################################################
sudo sed -i "s/\(password\s*sufficient.*\)/\1 rounds=5000/g" /etc/pam.d/password-auth /etc/pam.d/system-auth
# END V-230233

###############################################################################
echo "Automating Rule Id V-230234"
# SCAP fails if /boot/efi/EFI/redhat/grub.cfg exists on Gen 1 Azure VM
###############################################################################
firmwarecheck=$([ -d /sys/firmware/efi ] && echo UEFI || echo BIOS)
if [ $firmwarecheck = 'BIOS' ]; then
    sudo mv /boot/efi/EFI/redhat/grub.cfg /boot/efi/EFI/redhat/grub.bak
fi
# END V-230234

###############################################################################
echo "Automating Rule Id V-230253"
###############################################################################
sudo sed -i "s/^SSH_USE_STRONG_RNG=.*/SSH_USE_STRONG_RNG=32/g" /etc/sysconfig/sshd
# END V-230253

###############################################################################
echo "Automating Rule Id V-230257"
###############################################################################
sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /0022 -type f -exec chmod 0755 {} \;
# END V-230257

###############################################################################
echo "Automating Rule Id V-230271"
###############################################################################
sudo grep -r -l -i nopasswd /etc/sudoers.d/* /etc/sudoers | sudo xargs sed -i 's/\s*NOPASSWD://g' 2>&1
# END V-230271

###############################################################################
echo "Automating Rule Id V-230287"
###############################################################################
sudo chmod 0600 /etc/ssh/ssh_host*key
# END V-230287

###############################################################################
echo "Automating Rule Id V-230301"
###############################################################################
sudo sed -i "s/\(.*[[:space:]]\/[[:alpha:]].*defaults\)/\1,nodev/g" /etc/fstab
# END V-230301

###############################################################################
echo "Automating Rule Id V-230311"
###############################################################################
sudo rm -f /usr/lib/sysctl.d/50-coredump.conf
echo "kernel.core_pattern = |/bin/false" | sudo tee /etc/sysctl.d/90-azurestig-v230311.conf
# END V-230311

###############################################################################
echo "Automating Rule Ids V-230332, V-230334, V-230336, V-230338, V-230340, V-230342, V-230344"
###############################################################################
if [ ${version} == '8.0' ] || [ ${version} == '8.1' ]; then
    authRequired='auth        required'
    acctRequired='account     required'
    spacing='                                     '
    authFaillockPreAuth='pam_faillock.so preauth dir=\/var\/log\/faillock silent audit deny=3 even_deny_root fail_interval=900 unlock_time=0'
    authFaillockAuthFail='pam_faillock.so authfail dir=\/var\/log\/faillock unlock_time=0'
    sudo sed -i "s/\(auth.*pam_unix.so.*\)/${authRequired}${spacing}${authFaillockPreAuth}\n\1/g" /etc/pam.d/password-auth /etc/pam.d/system-auth
    sudo sed -i "s/\(auth.*pam_unix.so.*\)/\1\n${authRequired}${spacing}${authFaillockAuthFail}/g" /etc/pam.d/password-auth /etc/pam.d/system-auth
    sudo sed -i "s/\(account.*pam_unix.so\)/${acctRequired}${spacing}pam_faillock.so\n\1/g" /etc/pam.d/password-auth /etc/pam.d/system-auth
else
    echo "  Automation intended for 8.0 and 8.1; '$version' detected, skipping..."
fi
# END V-230332, V-230334, V-230336, V-230338, V-230340, V-230342, V-230344

###############################################################################
echo "Automating Rule Id V-230333"
###############################################################################
if [ ${version} == '8.0' ] || [ ${version} == '8.1' ]; then
    echo "  Automation intended for 8.2 and newer, '$version' detected, skipping..."
else
    authRequiredFaillock='auth        required      pam_faillock.so'
    acctRequiredFaillock='account     required      pam_faillock.so'
    sudo sed -i "s/\(auth.*required.*pam_env.so\)/\1\n${authRequiredFaillock} preauth/g" /etc/pam.d/password-auth /etc/pam.d/system-auth
    sudo sed -i "s/\(auth.*required.*pam_deny.so\)/${authRequiredFaillock} authfail\n\1/g" /etc/pam.d/password-auth /etc/pam.d/system-auth
    sudo sed -i "s/\(account.*required.*pam_unix.so\)/${acctRequiredFaillock}\n\1/g" /etc/pam.d/password-auth /etc/pam.d/system-auth
    sudo sed -i "s/.*deny\s*=.*/deny = 3/g" /etc/security/faillock.conf
fi
# END V-230333

###############################################################################
echo "Automating Rule Id V-230335"
###############################################################################
if [ ${version} == '8.0' ] || [ ${version} == '8.1' ]; then
    echo "  Automation intended for 8.2 and newer, '$version' detected, skipping..."
else
    sudo sed -i "s/.*fail_interval\s*=.*/fail_interval = 900/g" /etc/security/faillock.conf
fi
# END V-230335

###############################################################################
echo "Automating Rule Id V-230337"
###############################################################################
if [ ${version} == '8.0' ] || [ ${version} == '8.1' ]; then
    echo "  Automation intended for 8.2 and newer, '$version' detected, skipping..."
else
    sudo sed -i "s/^\(#\|\)[[:space:]]*unlock_time\s*=.*/unlock_time = 0/g" /etc/security/faillock.conf
fi
# END V-230337

###############################################################################
echo "Automating Rule Id V-230341"
###############################################################################
if [ ${version} == '8.0' ] || [ ${version} == '8.1' ]; then
    echo "  Automation intended for 8.2 and newer, '$version' detected, skipping..."
else
    if sudo grep -q -i silent /etc/security/faillock.conf; then
        sudo sed -i "s/.*silent.*/silent/g" /etc/security/faillock.conf
    else
        echo "silent" | sudo tee -a /etc/security/faillock.conf
    fi
fi
# END V-230341

###############################################################################
echo "Automating Rule Id V-230343"
###############################################################################
if [ ${version} == '8.0' ] || [ ${version} == '8.1' ]; then
    echo "  Automation intended for 8.2 and newer, '$version' detected, skipping..."
else
    if sudo grep -q -i audit /etc/security/faillock.conf; then
        sudo sed -i "s/.*audit.*/audit/g" /etc/security/faillock.conf
    else
        echo "audit" | sudo tee -a /etc/security/faillock.conf
    fi
fi
# END V-230343

###############################################################################
echo "Automating Rule Id V-230345"
###############################################################################
if [ ${version} == '8.0' ] || [ ${version} == '8.1' ]; then
    echo "  Automation intended for 8.2 and newer, '$version' detected, skipping..."
else
    sudo sed -i "s/^\(#\|\)[[:space:]]*even_deny_root.*/even_deny_root/g" /etc/security/faillock.conf
fi
# END V-230345

###############################################################################
echo "Automating Rule Id V-230349"
###############################################################################
echo 'if [ "$PS1" ]; then' | sudo tee -a /etc/profile.d/230348-customshell.sh
echo 'parent=$(ps -o ppid= -p $$)' | sudo tee -a /etc/profile.d/230348-customshell.sh
echo 'name=$(ps -o comm= -p $parent)' | sudo tee -a /etc/profile.d/230348-customshell.sh
echo 'case "$name" in (sshd|login) exec tmux ;; esac' | sudo tee -a /etc/profile.d/230348-customshell.sh
echo 'fi' | sudo tee -a /etc/profile.d/230348-customshell.sh
# END V-230349

###############################################################################
echo "Automating Rule Id V-230367"
###############################################################################
sudo chage -M 60 "$1"
sudo chage -M 60 root
# END V-230367

###############################################################################
echo "Automating Rule Id V-230368"
###############################################################################
passwordRequired='password    required'
spacing='      '
passwordReqPwHist='pam_pwhistory.so use_authtok remember=5 retry=3'
sudo sed -i "s/\(password.*pam_unix.so.*\)/${passwordRequired}${spacing}${passwordReqPwHist}\n\1/g" /etc/pam.d/password-auth /etc/pam.d/system-auth
# END V-230368

###############################################################################
echo "Automating Rule Id V-230373"
###############################################################################
sudo useradd -D -f 35
# END V-230373

###############################################################################
echo "Automating Rule Id V-230380"
###############################################################################
sudo sed -i 's/\s*nullok\s*/ /g' /etc/pam.d/system-auth /etc/pam.d/password-auth
sudo sed -i "s/.*PermitEmptyPasswords.*/PermitEmptyPasswords no/g" /etc/ssh/sshd_config
# END V-230380

###############################################################################
echo "Automating Rule Id V-230439"
###############################################################################
echo '-a always,exit -F arch=b32 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete' | sudo tee -a /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete' | sudo tee -a /etc/audit/rules.d/audit.rules
# END V-230439

###############################################################################
echo "Automating Rule Id V-230485"
###############################################################################
if ! sudo grep -q -w 'port' /etc/chrony.conf; then
    echo 'port 0' | sudo tee -a /etc/chrony.conf
else
    sudo sed -i 's/\(^port\|^#port\).*/port 0/g' /etc/chrony.conf
fi
# END V-230485

###############################################################################
echo "Automating Rule Id V-230486"
###############################################################################
if ! sudo grep -q -w 'cmdport' /etc/chrony.conf; then
    echo 'cmdport 0' | sudo tee -a /etc/chrony.conf
else
    sudo sed -i 's/\(^cmdport\|^#cmdport\).*/cmdport 0/g' /etc/chrony.conf
fi
# END V-230486

###############################################################################
echo "Automating Rule Id V-230494"
###############################################################################
echo 'install atm /bin/true' | sudo tee /etc/modprobe.d/atm.conf
echo 'blacklist atm' | sudo tee -a /etc/modprobe.d/blacklist.conf
# END V-230494

###############################################################################
echo "Automating Rule Id V-230495"
###############################################################################
echo 'install can /bin/true' | sudo tee /etc/modprobe.d/can.conf
echo 'blacklist can' | sudo tee -a /etc/modprobe.d/blacklist.conf
# END V-230495

###############################################################################
echo "Automating Rule Id V-230496"
###############################################################################
echo 'install sctp /bin/true' | sudo tee /etc/modprobe.d/sctp.conf
echo 'blacklist sctp' | sudo tee -a /etc/modprobe.d/blacklist.conf
# END V-230496

###############################################################################
echo "Automating Rule Id V-230497"
###############################################################################
echo 'install tipc /bin/true' | sudo tee /etc/modprobe.d/tipc.conf
echo 'blacklist tipc' | sudo tee -a /etc/modprobe.d/blacklist.conf
# END V-230497

###############################################################################
echo "Automating Rule Id V-230498"
###############################################################################
echo 'install cramfs /bin/true' | sudo tee /etc/modprobe.d/cramfs.conf
echo 'blacklist cramfs' | sudo tee -a /etc/modprobe.d/blacklist.conf
# END V-230498

###############################################################################
echo "Automating Rule Id V-230499"
###############################################################################
echo 'install firewire-core /bin/true' | sudo tee /etc/modprobe.d/firewire-core.conf
echo 'blacklist firewire-core' | sudo tee -a /etc/modprobe.d/blacklist.conf
# END V-230499

###############################################################################
echo "Automating Rule Id V-230503"
###############################################################################
echo 'install usb-storage /bin/true' | sudo tee /etc/modprobe.d/usb-storage.conf
echo 'blacklist usb-storage' | sudo tee -a /etc/modprobe.d/blacklist.conf
# END V-230503

###############################################################################
echo "Automating Rule Id V-230507"
###############################################################################
echo 'install bluetooth /bin/true' | sudo tee /etc/modprobe.d/bluetooth.conf
# END V-230507

###############################################################################
echo "Automating Rule Ids V-230508, V-230509, V-230510"
###############################################################################
echo 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0' | sudo tee -a /etc/fstab
# END V-230508, V-230509, V-230510

###############################################################################
echo "Automating Rule Id V-230511, V-230512, V-230513"
###############################################################################
sudo sed -i 's/\(\/tmp.*\)defaults.*/\1defaults,nodev,nosuid,noexec 0 0/g' /etc/fstab
# END V-230511, V-230512, V-230513

###############################################################################
echo "Automating Rule Id V-230546"
###############################################################################
sudo rm -f /usr/lib/sysctl.d/10-default-yama-scope.conf
sudo sysctl -w kernel.yama.ptrace_scope=1
echo "kernel.yama.ptrace_scope = 1" | sudo tee /etc/sysctl.d/90-azurestig-v230546.conf
# END V-230546

###############################################################################
echo "Automating Rule Id V-237642"
###############################################################################
echo 'Defaults !targetpw' | sudo tee /etc/sudoers.d/237642
echo 'Defaults !rootpw' | sudo tee -a /etc/sudoers.d/237642
echo 'Defaults !runaspw' | sudo tee -a /etc/sudoers.d/237642
# END V-237642


###############################################################################
#echo "Unzipping rhel8STIG-ansible.zip to ./rhel8STIG"
###############################################################################
#unzip rhel8STIG-ansible.zip -d ./rhel8STIG

###############################################################################
echo "Invoking ansible-playbook to automate STIG rules"
###############################################################################
/home/stigadmin/ato-toolkit/stig/linux/bin/ansible-playbook -v -b -i /dev/null ./config/site.yml

###############################################################################
# "Automating Rule Id V-230483" 8.0 auditd.conf does not recogn. percent sign
###############################################################################
if [ ${version} == '8.0' ]; then
    echo "Automating Rule Id V-230483"
    sudo sed -i 's/25%/2048/g' /etc/audit/auditd.conf
fi
# END V-230483

###############################################################################
echo "Automating Rule Id V-230350"
###############################################################################
sudo sed -i 's/.*tmux.*//g' /etc/shells
echo '---------- /etc/shells content begin ----------'
cat /etc/shells
echo '---------- /etc/shells content end ----------'
# END V-230350

###############################################################################
echo "Automating Rule Id V-230223"
###############################################################################
sudo fips-mode-setup --enable
# END V-230223

###############################################################################
echo "Restarting system to apply STIG settings..."
###############################################################################
sudo touch ./azAutomationComplete
sudo shutdown -r +1 2>&1