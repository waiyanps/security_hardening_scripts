
bootloader_config_security() {
    bootloader_config="/path/to/bootloader/config/file"  # Replace with the actual path

    # Check if the bootloader config file exists
    if [ -f "$bootloader_config" ]; then
        # Get the current permissions and owner of the bootloader config file
        config_perm=$(stat -c '%a' "$bootloader_config")
        config_owner=$(stat -c '%U' "$bootloader_config")

        # Check if the permissions are not 400 or the owner is not root
        if [ "$config_perm" != "400" ] || [ "$config_owner" != "root" ]; then
            echo -e "${YELLOW}Bootloader config file permissions or owner are not set to the desired values.${NC}"

            # Ask the user if they want to remediate
            read -p "Do you want to set permissions to 400 and owner to root for $bootloader_config? (yes/no): " input

            if [[ $input =~ (Y|y|Yes|YES|yes) ]]; then
                # Set desired permissions and owner for the bootloader config file
                chmod 400 "$bootloader_config"
                chown root:root "$bootloader_config"
                echo -e "${GREEN}[ PASS => Set permissions to 400 and owner to root for $bootloader_config ] ${NC}"
                echo "Configuring $bootloader_config to desired permissions and owner is complete." >> "$file_audit/audit.log"
            else
                echo -e "${RED}[ FAIL => Set permissions to 400 and owner to root for $bootloader_config ] ${NC}"
            fi
        else
            echo -e "${GREEN}[ PASS => Bootloader config file already has the desired permissions and owner ] ${NC}"
        fi
    else
        echo -e "${RED}[ FAIL => Bootloader config file does not exist ] ${NC}"
    fi
}

# Call the function to execute it
bootloader_config_security

#!/bin/bash

configure_ssh_idle_timeout() {
    sshd_config="/etc/ssh/sshd_config"

    # Check if the sshd configuration file exists
    if [ -f "$sshd_config" ]; then
        # Check if the client_alive_interval and client_alive_count_max settings exist
        if grep -qE "^ClientAliveInterval[[:space:]]+300" "$sshd_config" && grep -qE "^ClientAliveCountMax[[:space:]]+3" "$sshd_config"; then
            echo -e "${GREEN}[ PASS => SSH idle timeout configuration is already set ] ${NC}"
        else
            echo -e "${YELLOW}SSH idle timeout configuration needs to be configured.${NC}"

            # Ask the user if they want to remediate
            read -p "Do you want to set ClientAliveInterval to 300 seconds and ClientAliveCountMax to 3? (yes/no): " input

            if [[ $input =~ (Y|y|Yes|YES|yes) ]]; then
                # Set desired SSH idle timeout configuration
                echo "ClientAliveInterval 300" >> "$sshd_config"
                echo "ClientAliveCountMax 3" >> "$sshd_config"
                echo -e "${GREEN}[ PASS => Set SSH idle timeout configuration in $sshd_config ] ${NC}"
                echo "Configuring SSH idle timeout in $sshd_config is complete." >> "$file_audit/audit.log"
            else
                echo -e "${RED}[ FAIL => SSH idle timeout configuration not set ] ${NC}"
            fi
        fi
    else
        echo -e "${RED}[ FAIL => SSH configuration file does not exist ] ${NC}"
    fi
}

# Call the function to execute it
configure_ssh_idle_timeout


#!/bin/bash

configure_syslog_permissions() {
    syslog_file="/var/log/syslog"

    # Check if the syslog file exists
    if [ -f "$syslog_file" ]; then
        # Get the current permissions of the syslog file
        syslog_perm=$(stat -c '%a' "$syslog_file")

        # Check if the permissions are not secure (e.g., too permissive)
        if [ "$syslog_perm" != "640" ]; then
            echo -e "${YELLOW}Syslog file permissions are not set to a secure value.${NC}"

            # Ask the user if they want to remediate
            read -p "Do you want to set permissions to 640 for $syslog_file? (yes/no): " input

            if [[ $input =~ (Y|y|Yes|YES|yes) ]]; then
                # Set desired permissions for the syslog file
                chmod 640 "$syslog_file"
                echo -e "${GREEN}[ PASS => Set permissions to 640 for $syslog_file ] ${NC}"
                echo "Configuring syslog file permissions is complete." >> "$file_audit/audit.log"
            else
                echo -e "${RED}[ FAIL => Set permissions to 640 for $syslog_file ] ${NC}"
            fi
        else
            echo -e "${GREEN}[ PASS => Syslog file permissions are already set to a secure value ] ${NC}"
        fi
    else
        echo -e "${RED}[ FAIL => Syslog file does not exist ] ${NC}"
    fi
}

# Call the function to execute it
configure_syslog_permissions

#!/bin/bash

configure_login_grace_time() {
    sshd_config="/etc/ssh/sshd_config"

    # Check if the sshd configuration file exists
    if [ -f "$sshd_config" ]; then
        # Check if the LoginGraceTime setting exists
        if grep -qE "^LoginGraceTime[[:space:]]+60" "$sshd_config"; then
            echo -e "${GREEN}[ PASS => LoginGraceTime is already set to 1 minute ] ${NC}"
        else
            echo -e "${YELLOW}LoginGraceTime needs to be configured.${NC}"

            # Ask the user if they want to remediate
            read -p "Do you want to set LoginGraceTime to 1 minute? (yes/no): " input

            if [[ $input =~ (Y|y|Yes|YES|yes) ]]; then
                # Set desired LoginGraceTime configuration
                echo "LoginGraceTime 60" >> "$sshd_config"
                echo -e "${GREEN}[ PASS => Set LoginGraceTime to 1 minute in $sshd_config ] ${NC}"
                echo "Configuring LoginGraceTime in $sshd_config is complete." >> "$file_audit/audit.log"
            else
                echo -e "${RED}[ FAIL => LoginGraceTime not set ] ${NC}"
            fi
        fi
    else
        echo -e "${RED}[ FAIL => SSH configuration file does not exist ] ${NC}"
    fi
}

# Call the function to execute it
configure_login_grace_time



configure_restrictive_umask() {
    # Check if the umask is already set to 077
    if [ "$(umask)" = "0077" ]; then
        echo -e "${GREEN}[ PASS => Umask is already set to 077 ] ${NC}"
    else
        echo -e "${YELLOW}Umask needs to be configured.${NC}"

        # Ask the user if they want to remediate
        read -p "Do you want to set umask to 077? (yes/no): " input

        if [[ $input =~ (Y|y|Yes|YES|yes) ]]; then
            # Set desired umask
            umask 0077
            echo -e "${GREEN}[ PASS => Set umask to 077 ] ${NC}"
            echo "Configuring umask is complete." >> "$file_audit/audit.log"
        else
            echo -e "${RED}[ FAIL => Umask not set ] ${NC}"
        fi
    fi
}

# Call the function to execute it
configure_restrictive_umask
