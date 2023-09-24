To ensure that the Datagram Congestion Control Protocol (DCCP) is disabled on a Linux system using a Bash script, you can follow these steps:

#!/bin/bash

# Define an array of modules to check and disable
modules=("tipc" "sctp" "dccp")

# Function to disable a kernel module if it's currently enabled
disable_module() {
    local module_name="$1"
    if lsmod | grep -q "$module_name"; then
        echo "$module_name is currently enabled. Disabling..."
        sudo modprobe -r "$module_name"
    else
        echo "$module_name is already disabled."
    fi
}

# Iterate through the array and disable each module
for module in "${modules[@]}"; do
    disable_module "$module"
done

echo "TIPC, SCTP, and DCCP are disabled."

To ensure that the SSH LoginGraceTime is set to 1 minute (1m) if its default value is greater than 1 minute, you can create a Bash script as follows:

#!/bin/bash

# Check the current LoginGraceTime value in sshd_config
current_grace_time=$(grep -E '^LoginGraceTime' /etc/ssh/sshd_config | awk '{print $2}')

# Check if the value is set and greater than 1m
if [[ -n "$current_grace_time" && "$current_grace_time" != "1m" && "$current_grace_time" > "1m" ]]; then
    echo "LoginGraceTime is currently set to $current_grace_time. Changing it to 1m..."
    sudo sed -i 's/^LoginGraceTime.*/LoginGraceTime 1m/' /etc/ssh/sshd_config
    sudo systemctl restart sshd
    echo "LoginGraceTime has been set to 1m."
else
    echo "LoginGraceTime is already set to 1m or not found in sshd_config."
fi

To ensure SSH access is limited to selected users and groups, you can create a Bash script that modifies the SSH server configuration (sshd_config) to specify the allowed users and groups. Here's a script to achieve this:

#!/bin/bash

# List of allowed users (replace with your desired usernames)
allowed_users=("user1" "user2")

# List of allowed groups (replace with your desired group names)
allowed_groups=("group1" "group2")

# Path to the sshd_config file
sshd_config="/etc/ssh/sshd_config"

# Backup the original sshd_config file
sudo cp "$sshd_config" "$sshd_config.bak"

# Ensure SSH access is restricted to selected users
for user in "${allowed_users[@]}"; do
    sudo grep -qE "^AllowUsers.*$user" "$sshd_config" || \
        echo "AllowUsers $user" | sudo tee -a "$sshd_config"
done

# Ensure SSH access is restricted to selected groups
for group in "${allowed_groups[@]}"; do
    sudo grep -qE "^AllowGroups.*$group" "$sshd_config" || \
        echo "AllowGroups $group" | sudo tee -a "$sshd_config"
done

# Restart the SSH server to apply the changes
sudo systemctl restart sshd

echo "SSH access is now limited to selected users and groups."

To ensure that only selected users can use cron and at for scheduling tasks, you can create a Bash script that modifies the /etc/cron.allow and /etc/at.allow files to specify the allowed users. Here's a script to achieve this:

#!/bin/bash

# List of allowed users (replace with your desired usernames)
allowed_users=("user1" "user2")

# Path to the cron.allow and at.allow files
cron_allow="/etc/cron.allow"
at_allow="/etc/at.allow"

# Backup the original cron.allow and at.allow files
sudo cp "$cron_allow" "$cron_allow.bak"
sudo cp "$at_allow" "$at_allow.bak"

# Ensure only allowed users can use cron
for user in "${allowed_users[@]}"; do
    echo "$user" | sudo tee -a "$cron_allow" > /dev/null
    echo "$user" | sudo tee -a "$at_allow" > /dev/null
done

# Remove other users from cron.allow and at.allow
for file in "$cron_allow" "$at_allow"; do
    for user in $(cat "$file"); do
        if [[ ! " ${allowed_users[@]} " =~ " $user " ]]; then
            sudo sed -i "/$user/d" "$file"
        fi
    done
done

echo "Only selected users can use cron and at."

To set a default deny firewall policy on Ubuntu using the Uncomplicated Firewall (UFW), you can create a Bash script to configure the firewall rules. Here's a script to achieve this:

#!/bin/bash

# Ensure UFW is installed
if ! command -v ufw &>/dev/null; then
    sudo apt-get update
    sudo apt-get install ufw -y
fi

# Reset UFW to default settings (disable it)
sudo ufw --force reset

# Set the default policy to deny incoming and outgoing traffic
sudo ufw default deny incoming
sudo ufw default deny outgoing

# Enable the firewall
sudo ufw enable

# Display the current UFW status
sudo ufw status

echo "Default deny firewall policy is set."

To ensure that only approved MAC (Message Authentication Code) algorithms are used in your SSH configuration, you can create a Bash script to modify the SSH server's configuration file (sshd_config) and specify the allowed MAC algorithms. Here's a script to achieve this:

#!/bin/bash

# List of approved MAC algorithms (modify as needed)
approved_mac_algorithms="hmac-sha2-256,hmac-sha2-512"

# Path to the sshd_config file
sshd_config="/etc/ssh/sshd_config"

# Backup the original sshd_config file
sudo cp "$sshd_config" "$sshd_config.bak"

# Ensure approved MAC algorithms are set
if sudo grep -qE "^MACs" "$sshd_config"; then
    # Update existing MACs line with approved algorithms
    sudo sed -i "s/^MACs .*/MACs $approved_mac_algorithms/" "$sshd_config"
else
    # Add a new MACs line with approved algorithms
    echo "MACs $approved_mac_algorithms" | sudo tee -a "$sshd_config"
fi

# Restart the SSH server to apply the changes
sudo systemctl restart sshd

echo "Only approved MAC algorithms are now allowed in SSH configuration."

To ensure lockout for failed password attempts is configured on a Linux system, you can create a Bash script that modifies the Pluggable Authentication Module (PAM) configuration and the /etc/security/pwquality.conf file. Here's a script to achieve this:

#!/bin/bash

# Set the maximum number of allowed failed password attempts
max_failed_attempts=3

# Set the lockout duration (in seconds)
lockout_duration=600  # 600 seconds (10 minutes)

# Configure PAM to enforce lockout for failed password attempts
echo "auth required pam_tally2.so deny=$max_failed_attempts unlock_time=$lockout_duration" | sudo tee -a /etc/pam.d/common-auth

# Configure pwquality.conf to set retry limit
if [ -f /etc/security/pwquality.conf ]; then
    sudo sed -i "s/retry = [0-9]*/retry = $max_failed_attempts/" /etc/security/pwquality.conf
else
    echo "retry = $max_failed_attempts" | sudo tee -a /etc/security/pwquality.conf
fi

echo "Lockout for failed password attempts is configured."

# To ensure that TIPC, SCTP, and DCCP are disabled on a Linux system, you can create a Bash script that unloads the corresponding kernel modules if they are currently loaded. Here's a script to achieve this:

# #!/bin/bash

# # Check if TIPC is currently enabled
# if lsmod | grep -q tipc; then
#     echo "TIPC is currently enabled. Disabling..."
#     # Disable TIPC kernel module
#     sudo modprobe -r tipc
# else
#     echo "TIPC is already disabled."
# fi

# # Check if SCTP is currently enabled
# if lsmod | grep -q sctp; then
#     echo "SCTP is currently enabled. Disabling..."
#     # Disable SCTP kernel module
#     sudo modprobe -r sctp
# else
#     echo "SCTP is already disabled."
# fi

# # Check if DCCP is currently enabled
# if lsmod | grep -q dccp; then
#     echo "DCCP is currently enabled. Disabling..."
#     # Disable DCCP kernel module
#     sudo modprobe -r dccp
# else
#     echo "DCCP is already disabled."
# fi

# echo "TIPC, SCTP, and DCCP are disabled."


To disable support for the Reliable Datagram Sockets (RDS) protocol on a Linux system, you can create a Bash script that unloads the RDS kernel module and prevents it from being loaded on boot. Here's a script to achieve this:

#!/bin/bash

# Check if RDS is currently enabled
if lsmod | grep -q rds; then
    echo "RDS is currently enabled. Disabling..."
    # Disable RDS kernel module
    sudo modprobe -r rds
else
    echo "RDS is already disabled."
fi

# Prevent RDS from being loaded on boot
if [ -f /etc/modprobe.d/rds.conf ]; then
    echo "options rds disable=1" | sudo tee -a /etc/modprobe.d/rds.conf
else
    echo "options rds disable=1" | sudo tee /etc/modprobe.d/rds.conf
fi

echo "Support for RDS is disabled."

To ensure that permissions on bootloader configuration files are correctly configured, you can create a Bash script to check and set the permissions on those files. Here's a script that you can use as a starting point:

#!/bin/bash

# Define the path to the bootloader configuration files
bootloader_config="/boot/grub/grub.cfg"  # Replace with your bootloader configuration file path

# Define the desired permissions (e.g., 600 for read-write only by root)
desired_permissions="600"

# Check if the bootloader config file exists
if [ -e "$bootloader_config" ]; then
    # Get the current permissions of the bootloader config file
    current_permissions=$(stat -c %a "$bootloader_config")

    # Check if the current permissions are different from the desired permissions
    if [ "$current_permissions" != "$desired_permissions" ]; then
        echo "Setting permissions on bootloader configuration file..."
        sudo chmod "$desired_permissions" "$bootloader_config"
        echo "Permissions on bootloader configuration file have been set to $desired_permissions."
    else
        echo "Permissions on bootloader configuration file are already correctly configured."
    fi
else
    echo "Bootloader configuration file does not exist at $bootloader_config."
fi

To disable the installation and use of file systems that are not required, such as HFS and CramFS, you can create a Bash script that removes their kernel modules and blacklists them to prevent them from being loaded in the future. Here's a script to achieve this:

#!/bin/bash

# List of file systems to disable (e.g., HFS and CramFS)
file_systems=("hfs" "cramfs")

# Remove kernel modules for specified file systems
for fs in "${file_systems[@]}"; do
    if lsmod | grep -q "$fs"; then
        echo "$fs is currently enabled. Disabling..."
        sudo modprobe -r "$fs"
    else
        echo "$fs is already disabled."
    fi
done

# Create blacklist files to prevent loading of specified file systems
for fs in "${file_systems[@]}"; do
    if [ ! -f "/etc/modprobe.d/blacklist-$fs.conf" ]; then
        echo "Blacklisting $fs..."
        echo "install $fs /bin/true" | sudo tee -a "/etc/modprobe.d/blacklist-$fs.conf"
    else
        echo "$fs is already blacklisted."
    fi
done

echo "Installation and use of unnecessary file systems (HFS and CramFS) are disabled."


To ensure that core dumps are restricted on a Linux system, you can create a Bash script that configures the system to limit core dumps. This involves changing the core pattern and modifying the ulimit settings for core files. Here's a script to achieve this:

#!/bin/bash

# Set the path for core dumps (empty to disable)
core_pattern=""

# Set the hard limit for core file size to 0 (unlimited)
ulimit_core_size=0

# Ensure the core pattern is set to an empty string (disable core dumps)
echo -n "$core_pattern" | sudo tee /proc/sys/kernel/core_pattern

# Set the hard limit for core file size to 0 (unlimited)
ulimit -c "$ulimit_core_size"

# Check if changes were successful
if [ -z "$core_pattern" ]; then
    echo "Core dumps are restricted. The core pattern is empty."
else
    echo "Failed to restrict core dumps."
fi

if [ "$ulimit_core_size" -eq 0 ]; then
    echo "Core file size is restricted to 0 (unlimited)."
else
    echo "Failed to restrict core file size."
fi

