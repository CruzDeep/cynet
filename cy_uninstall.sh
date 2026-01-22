#!/bin/bash

RANSOM_DIR_PATH="/home/.! Cynet Ransom Protection"

decrypt_service_name() 
{
    local encrypted_b64="$1"
    local decrypted_name=""
    local key="W@tchD0gEncKey!" 

    local decoded
    if ! decoded=$(echo "$encrypted_b64" | base64 -d 2>/dev/null); then
        echo "[ERROR] Failed to decode base64 service name"
        return 1
    fi

    for ((i = 0; i < ${#decoded}; i++)); do
        key_char=$(printf "%d" "'${key:i % ${#key}:1}")
        enc_char=$(printf "%d" "'${decoded:i:1}")
        dec_char=$((enc_char ^ key_char))
        decrypted_name+=$(printf "\\$(printf '%03o' "$dec_char")")
    done

    echo "$decrypted_name"
}

disable_watchdog_monitoring() 
{
	DISABLE_WATCHDOG_FILE="/opt/Cynet/DisableWatchdog"

	if [ ! -f "$DISABLE_WATCHDOG_FILE" ]; then
		echo "Creating DisableWatchdog marker..."
		echo "DISABLE" > "$DISABLE_WATCHDOG_FILE"
	fi

	WATCHDOG_SERVICE_FILE="/opt/Cynet/WatchDogServiceName.txt"

	if [ ! -f "$WATCHDOG_SERVICE_FILE" ]; then
		echo "[WARNING] WatchDog service name file not found. Skipping WatchDog service stop."
		return
	fi

	ENCRYPTED_SERVICE_NAME=$(cat "$WATCHDOG_SERVICE_FILE" | tr -d '\n')
	WATCHDOG_SERVICE_NAME=$(decrypt_service_name "$ENCRYPTED_SERVICE_NAME")
	if [ -z "$WATCHDOG_SERVICE_NAME" ]; then
		echo "[WARNING] Failed to decrypt WatchDog service name. Using default: watchdog.service"
		WATCHDOG_SERVICE_NAME="watchdog.service"
	fi

	if [ -x "$(command -v systemctl)" ]; then
		if systemctl is-active --quiet "$WATCHDOG_SERVICE_NAME"; then
			echo "Stopping WatchDog service: $WATCHDOG_SERVICE_NAME"
			if ! systemctl stop "$WATCHDOG_SERVICE_NAME"; then
				echo "[ERROR] Failed to stop WatchDog service: $WATCHDOG_SERVICE_NAME"
			else
				systemctl disable "$WATCHDOG_SERVICE_NAME"
			fi
		else
			echo "[INFO] WatchDog service '$WATCHDOG_SERVICE_NAME' is not active."
		fi
	elif [ -x "$(command -v service)" ]; then
		echo "Stopping WatchDog service via 'service' command: $WATCHDOG_SERVICE_NAME"
		if ! service "$WATCHDOG_SERVICE_NAME" stop; then
			echo "[ERROR] Failed to stop WatchDog service via 'service': $WATCHDOG_SERVICE_NAME"
		fi
	fi
}

cleanup_watchdog_unit_file()
{
    WATCHDOG_SERVICE_FILE="/opt/Cynet/WatchDogServiceName.txt"
    if [ ! -f "$WATCHDOG_SERVICE_FILE" ]; then
        echo "[INFO] No WatchDog service name file found. Skipping unit file cleanup."
        return
    fi

    ENCRYPTED_SERVICE_NAME=$(cat "$WATCHDOG_SERVICE_FILE" | tr -d '\n')
    SERVICE_NAME=$(decrypt_service_name "$ENCRYPTED_SERVICE_NAME")

    if [ -z "$SERVICE_NAME" ]; then
        echo "[WARNING] Failed to decrypt WatchDog service name. Skipping unit file removal."
        return
    fi

    UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
    if [ -f "$UNIT_PATH" ]; then
        echo "Removing WatchDog systemd unit file: $UNIT_PATH"
        rm -f "$UNIT_PATH"
        systemctl daemon-reload
        systemctl reset-failed
    else
        echo "[INFO] WatchDog unit file not found at $UNIT_PATH"
    fi
}

if [ $(id -u) != 0 ]; then
    echo "[ERROR] Uninstaller must be run as root (or with sudo), please run uninstaller as root"
    exit 1
fi

if [ -f /etc/debian_version ]; then
	HAS_DEB=true
elif [ -f /etc/system-release-cpe ]; then
	HAS_RPM=true
elif command -v rpm >/dev/null 2>&1 && ! command -v apt >/dev/null 2>&1; then
	HAS_RPM=true
else
	echo "Unsupported distro. Exiting!"
	exit 1
fi

if [ ! -z $HAS_DEB ]; then
	echo "Check if proccess if there is dpkg lock."
	if [ -x "$(command -v lsof)" ]; then
		echo "Unlock /var/lib/dpkg/lock"
		if [ -f /var/lib/dpkg/lock ]; then
			lsof /var/lib/dpkg/lock
		fi
		echo "Unlock /var/lib/dpkg/lock-frontend"
		if [ -f /var/lib/dpkg/lock-frontend ]; then
			lsof /var/lib/dpkg/lock-frontend
		fi
	fi
fi

disable_watchdog_monitoring
cleanup_watchdog_unit_file

echo "Trying to remove package if installed"
ServiceRemoveSucceed=false
ForceKill=true
if [ ! -z $HAS_DEB ]; then
	echo "Command dpkg found"
	dpkg --list cyneteps
	RET_VAL=$?
	echo "Return value of dpkg list: " $RET_VAL
	if [ $RET_VAL -eq 0 ]; then
		echo "Purging deb package"
		ForceKill=false
		dpkg --purge --force-all cyneteps
		if [ $? -ne 0 ]; then
			echo "Erasing deb failed - try apocaliptic step"
			rm /var/lib/dpkg/info/cyneteps.*
			echo "Purging deb package again"
			dpkg --purge --force-all cyneteps
		else
			dpkg --configure -a
			ServiceRemoveSucceed=true
		fi
	fi
elif [ ! -z $HAS_RPM ]; then
	rpm -qa | grep -i CynetEPS
	RET_VAL=$?
	echo "Return value of rpm -qa: " $RET_VAL
	if [ $RET_VAL -eq 0 ]; then
		echo "Removing RPM package"
		ForceKill=false
		rpm -e CynetEPS
		if [ $? -ne 0 ]; then
			echo "Erasing RPM failed - try apocaliptic step"
			rpm -e CynetEPS --noscripts
			#rpm -e --allmatches CynetEPS
		else
			ServiceRemoveSucceed=true
		fi
	fi
fi

echo "Trying to remove manual installation"
echo "Checking for existing service"

if [ "$ServiceRemoveSucceed" = false ]; then
	if [ -x "$(command -v systemctl)" ]; then
		echo "stopping service if running using systemctl"
		if [ "$(systemctl is-enabled cyuninstalleps.service)" = "enabled" ]
					then
			ERRORMESS=$( systemctl daemon-reexec )
			echo daemon-reexec error message: $ERRORMESS
			systemctl stop  cyuninstalleps.service
			systemctl disable  cyuninstalleps.service
			systemctl daemon-reload
			systemctl reset-failed
			rm /lib/systemd/system/cyuninstalleps.service
			rm /tmp/uninstallscrip.sh
		fi
		if [ "$(systemctl is-enabled cyservice)" = "enabled" ]
				then
			systemctl stop cyservice
			echo "removing existing service using systemctl"
			ERRORMESS=$( systemctl daemon-reexec )
			echo daemon-reexec error message: $ERRORMESS
			systemctl disable cyservice
			systemctl daemon-reload
			systemctl reset-failed
			ServiceRemoveSucceed=true
		fi
	fi
fi

if [ "$ServiceRemoveSucceed" = false ]; then
	if [ -x "$(command -v chkconfig)" ]; then
		chkconfig --list cyservice
		if [ $? -eq 0 ]; then
			echo "removing existing service using chkconfig"
			service cyservice stop
			chkconfig cyservice off
			chkconfig --del cyservice
			yes | rm -f /etc/init.d/cyservice
			yes | rm -f /etc/rc.d/init.d/cyservice
			ServiceRemoveSucceed=true
		fi
	fi
fi

if [ "$ServiceRemoveSucceed" = false ]; then
	if [ -x "$(command -v update-rc.d)" ]; then
		echo "removing service if running using update-rc.d"
		echo "removing existing service using update-rc"
		if [ -f /etc/init.d/cyservice ]; then
			update-rc.d cyservice disable
			yes | rm /etc/init.d/cyservice
			update-rc.d -f cyservice remove
		fi
	fi
fi

if [ "$ServiceRemoveSucceed" = false ] || [ "$ForceKill" = true ] ; then
    echo "Service is not installed or we try to uninstall not packages EPS version"
    echo "  try to terminate CynetEPS, if running"
    pkill -9 CynetEPS
    echo "  try to terminate avupdate.bin, if running"
	pkill -9 avupdate.bin
    echo "  try to terminate CynetAV, if running"
	pkill -9 CynetAV

	if [ -x "$(command -v lsof)" ]; then
	 	echo "Unlock /opt/Cynet/AV/CynetAV.sock.lock"
	 	if [ -f "/opt/Cynet/AV/CynetAV.sock.lock" ]; then
	 		echo "Unlocking /opt/Cynet/AV/CynetAV.sock.lock"
	 		lsof /opt/Cynet/AV/CynetAV.sock.lock
	 	fi
	fi

	echo   "Removing CynetEPS audit rules if needed."
	if [ -f "/etc/audit/rules.d/CynetAu.rules" ]; then
		echo "removing audit rules file /etc/audit/rules.d/CynetAu.rules"
		rm -f "/etc/audit/rules.d/CynetAu.rules"
	else 
		echo "No Cynet audit rules configured."
	fi

	if [ -x "$(command -v auditctl)" ]; then
		echo "Run auditctl to remove rules with cynetaukey key."
		auditctl -D -k cynetaukey
	fi

	# leave for possibility is some beta was installed in computer from deprecated plugin functionality to avoid junk
	echo   "Removing CynetEPS audit plugin if needed."
	restart_AuditD=false
	if [ -f "/etc/audit/plugins.d/CynetAu.conf" ]; then
		echo "removing plugin file /etc/audit/plugins.d/CynetAu.conf"
		rm -f "/etc/audit/plugins.d/CynetAu.conf"
		restart_AuditD=true
	fi
	if [ -f "/etc/audisp/plugins.d/CynetAu.conf" ]; then
		echo "removing plugin file /etc/audisp/plugins.d/CynetAu.conf"
		rm -f "/etc/audisp/plugins.d/CynetAu.conf"
		restart_AuditD=true
	fi

	#we do not use systemctl because in part of rh, it will refuse to restart auditd by strange error, the suggestion to workaround it by service util.!!!!
	if [ "$restart_AuditD" = true ]; then
		service auditd status >> /dev/null
		if [ $? -ne 0 ]; then
			echo "auditd stopped or disabled, no need to restart it to unregister cynet audit plugin"
		else 
			echo "restart auditd, to unregister cynet audit plugin"
			service auditd restart
		fi 
	else
		echo "No Cynet Audit plugin installed."
	fi	
fi

echo "Removing /opt/Cynet"
rm -fRd "/opt/Cynet"

if [ -f "/usr/lib/systemd/system/cyservice.service" ]; then
	echo "Removing /usr/lib/systemd/system/cyservice.service"
	rm -f "/usr/lib/systemd/system/cyservice.service"
fi

if [ -f "/lib/systemd/system/cyservice.service" ]; then
	echo "Removing /lib/systemd/system/cyservice.service"
	rm -f "/lib/systemd/system/cyservice.service"
fi

if [ -f "/tmp/CynetEPSArguments.txt" ]; then
	echo "Removing /tmp/CynetEPSArguments.txt"
	rm -f "/tmp/CynetEPSArguments.txt"
fi

if [ -f "$DISABLE_WATCHDOG_FILE" ]; then
    echo "Removing $DISABLE_WATCHDOG_FILE"
    rm -f "$DISABLE_WATCHDOG_FILE"
fi

if [ -d "$RANSOM_DIR_PATH" ]; then
    echo "Removing $RANSOM_DIR_PATH"
    rm -rf "$RANSOM_DIR_PATH"
fi

exit 0
