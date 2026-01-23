#!/bin/bash
#
# Copyright (C) Cynet Inc.
#
# Cynet Endpoint Installer

export SYSDIG_INSTALL_VERSION="0.40.1"

date_now=$(date "+%F %H:%M:%S")

DISTRO="placeholder"
VERSION=0
ARCH=$(uname -m)
KERNEL_RELEASE=$(uname -r)
KERNEL_VERSION=$(uname -v | sed 's/#\([[:digit:]]\+\).*/\1/')
DRIVER_NAME=${DRIVER_NAME:-"@DRIVER_NAME@"}
TARGET_ID="placeholder" # when no target id can be fetched, we try to build the driver from source anyway, using a placeholder name
args=("$@")

set_version_and_distro() {
    if [ -f /etc/debian_version ]; then
        if [ -f /etc/lsb-release ]; then
            . /etc/lsb-release
            DISTRO=$DISTRIB_ID
            VERSION=${DISTRIB_RELEASE%%.*}
        else
            DISTRO="Debian"
            VERSION=$(cat /etc/debian_version | cut -d'.' -f1)
        fi

    elif [ -f /etc/system-release-cpe ]; then
        DISTRO=$(cat /etc/system-release-cpe | cut -d':' -f3)

        # New Amazon Linux 2 distro
        if [[ -f /etc/image-id ]]; then
            AMZ_AMI_VERSION=$(cat /etc/image-id | grep 'image_name' | cut -d"=" -f2 | tr -d "\"")
        fi

        # amzn2
        if [[ "${DISTRO}" == "o" ]] && [[ ${AMZ_AMI_VERSION} = *"amzn2"* ]]; then
            DISTRO=$(cat /etc/system-release-cpe | cut -d':' -f4)
        fi
        # amzn3
        if [[ "${DISTRO}" == "o" ]]; then
            DISTRO=$(cat /etc/system-release-cpe | cut -d':' -f4)
            VERSION=$(cat /etc/system-release-cpe | cut -d':' -f6 | cut -d'.' -f1 | sed 's/[^0-9]*//g')
        else
          VERSION=$(cat /etc/system-release-cpe | cut -d':' -f5 | cut -d'.' -f1 | sed 's/[^0-9]*//g')
        fi

    elif [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=${VERSION_ID%%.*}

        # Specifically handle SUSE distributions
        if [[ "$ID" == "sles" || "$ID" == "opensuse-leap" ]]; then
            echo -e "[INFO] SUSE distribution detected. Skipping Sysdig installation but proceeding with EPS installation."
            echo "[INFO] SUSE distribution detected. Skipping Sysdig installation but proceeding with EPS installation."  >> /tmp/.cinstres
            return 2
        fi
    else
        echo "Unsupported system!" >> /tmp/.cinstres
        echo "[ERROR] could not resolve OS version, skipping Sysdig installation"
        return 0;
    fi

    echo "detected - Distro: $DISTRO    Version: $VERSION" >> /tmp/.cinstres
    return 1
}

get_target_id() {
    if [ -f "${HOST_ROOT}/etc/os-release" ]; then
        source "${HOST_ROOT}/etc/os-release"
        OS_ID=$ID
    elif [ -f "${HOST_ROOT}/etc/debian_version" ]; then
        OS_ID=debian
    elif [ -f "${HOST_ROOT}/etc/centos-release" ]; then
        OS_ID=centos
    elif [ -f "${HOST_ROOT}/etc/redhat-release" ]; then
        OS_ID=rhel
    else
        return 1
    fi

    if [ -f "${HOST_ROOT}/etc/VERSION" ]; then
        OS_ID=minikube
    fi

    case "${OS_ID}" in
        ("amzn")
            case "${VERSION_ID}" in
                ("2")    TARGET_ID="amazonlinux2" ;;
                ("2022") TARGET_ID="amazonlinux2022" ;;
                ("2023") TARGET_ID="amazonlinux2023" ;;
                (*)      TARGET_ID="amazonlinux" ;;
            esac
            ;;
        ("debian")
            TARGET_ID=$(echo "${OS_ID}" | tr '[:upper:]' '[:lower:]')
            local ARCH_extra=""
            if [[ $KERNEL_RELEASE =~ -?(rt-|cloud-|)(amd64|arm64) ]];
            then
                ARCH_extra="-${BASH_REMATCH[1]}${BASH_REMATCH[2]}"
            fi
            if [[ $(uname -v) =~ ([0-9]+\.[0-9]+\.[0-9]+\-[0-9]+) ]];
            then
                KERNEL_RELEASE="${BASH_REMATCH[1]}${ARCH_extra}"
            fi
            ;;
        ("ubuntu")
            if [[ $KERNEL_RELEASE =~ -([a-zA-Z]+)(-.*)?$ ]];
            then
                TARGET_ID="ubuntu-${BASH_REMATCH[1]}"
            else
                TARGET_ID="ubuntu-generic"
            fi

            if [[ $(uname -v) =~ (^\#[0-9]+\~[^-]*-Ubuntu .*$) ]];
            then
                KERNEL_VERSION=$(uname -v | sed 's/#\([^-\\ ]*\).*/\1/g')
            fi
            ;;
        ("flatcar")
            KERNEL_RELEASE="${VERSION_ID}"
            TARGET_ID=$(echo "${OS_ID}" | tr '[:upper:]' '[:lower:]')
            ;;
        ("minikube")
            TARGET_ID=$(echo "${OS_ID}" | tr '[:upper:]' '[:lower:]')
            if [[ $(cat ${HOST_ROOT}/etc/VERSION) =~ ([0-9]+(\.[0-9]+){2}) ]]; then
                KERNEL_VERSION="1_${BASH_REMATCH[1]}"
            else
                echo "* Unable to extract minikube version from ${HOST_ROOT}/etc/VERSION"
                exit 1
            fi
            ;;
        ("bottlerocket")
            TARGET_ID=$(echo "${OS_ID}" | tr '[:upper:]' '[:lower:]')
            if [[ -n ${VARIANT_ID} ]];  then
                VARIANT_ID_CUT=${VARIANT_ID%%-*}
            fi
            KERNEL_VERSION="1_${VERSION_ID}-${VARIANT_ID_CUT}"
            ;;
        ("talos")
            TARGET_ID=$(echo "${OS_ID}" | tr '[:upper:]' '[:lower:]')
            KERNEL_VERSION="1_${VERSION_ID}"
            ;;
        (*)
            TARGET_ID=$(echo "${OS_ID}" | tr '[:upper:]' '[:lower:]')
            ;;
    esac
    return 0
}

log_filename_components() {
    get_target_id
    FALCO_KERNEL_MODULE_FILENAME="${DRIVER_NAME}_${TARGET_ID}_${KERNEL_RELEASE}_${KERNEL_VERSION}.ko"
    echo "* Filename '${FALCO_KERNEL_MODULE_FILENAME}' is composed of:" >> /tmp/.cinstres
    echo " - target identifier: ${TARGET_ID}" >> /tmp/.cinstres
    echo " - kernel release: ${KERNEL_RELEASE}" >> /tmp/.cinstres
    echo " - kernel version: ${KERNEL_VERSION}" >> /tmp/.cinstres
    echo " - architecture: ${ARCH}" >> /tmp/.cinstres
    hostnamectl >> /tmp/.cinstres
}

redhat94patches() {
  if [ -f /etc/redhat-release ]; then
    redhat_version=$(grep -oP '(?<=release )[\d.]+' /etc/redhat-release)

    if [ "$(printf '%s\n' "$redhat_version" "9.4" | sort -V | head -n1)" == "9.4" ]; then
        echo "RedHat $redhat_version detected. Installing sysdig-$SYSDIG_INSTALL_VERSION and enabling codeready-builder" >> /tmp/.cinstres
        echo "executing: subscription-manager repos --enable codeready-builder-for-rhel-9-$(arch)-rpms" >> /tmp/.cinstres
        subscription-manager repos --enable codeready-builder-for-rhel-9-$(arch)-rpms 2>> /tmp/.cinstres
    fi
  fi
}

function install_rpm {
    if ! hash curl > /dev/null 2>&1; then
        echo "no curl found, attempting to install curl via yum" >> /tmp/.cinstres
        echo "executing: yum -q -y install curl" >> /tmp/.cinstres
        yum -q -y install curl
    fi
    if [ $VERSION -eq 9 ]; then
        redhat94patches
    fi
    if ! yum -q list dkms > /dev/null 2>&1; then
        echo "no DKMS found, attempting to install correct EPEL rpm version" >> /tmp/.cinstres
        if [ $VERSION -eq 8 ]; then
            echo "executing: rpm --quiet -i https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm" >> /tmp/.cinstres
            rpm --quiet -i https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm 2>> /tmp/.cinstres
        elif [ $VERSION -eq 7 ]; then
            echo "executing: rpm --quiet -i https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm" >> /tmp/.cinstres
            rpm --quiet -i https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm 2>> /tmp/.cinstres
        elif [ $VERSION -eq 9 ]; then
            echo "[WARNING] EPEL version 9 detected, this is not officially supported but best effort" >> /tmp/.cinstres
            echo "executing: rpm --quiet -i https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm" >> /tmp/.cinstres
            rpm --quiet -i https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm 2>> /tmp/.cinstres
        else
            echo "no exact version found: $VERSION, opting to try EPEL 6" >> /tmp/.cinstres
            echo "executing: rpm --quiet -i https://mirrors.kernel.org/fedora-epel/6/i386/epel-release-6-8.noarch.rpm" >> /tmp/.cinstres
            rpm --quiet -i https://mirrors.kernel.org/fedora-epel/6/i386/epel-release-6-8.noarch.rpm 2>> /tmp/.cinstres
        fi
    fi

    echo "Getting and installing Sysdig key via rpm" >> /tmp/.cinstres
    echo "executing: rpm --quiet --import https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public" >> /tmp/.cinstres
    rpm --quiet --import https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public 2>> /tmp/.cinstres || echo "[ERROR] Unable to download sysdig public key" >> /tmp/.cinstres
    echo "executing: curl -s -o /etc/yum.repos.d/draios.repo https://s3.amazonaws.com/download.draios.com/stable/rpm/draios.repo" >> /tmp/.cinstres
    curl -s -o /etc/yum.repos.d/draios.repo https://s3.amazonaws.com/download.draios.com/stable/rpm/draios.repo || echo "[ERROR] Unable to download sysdig repository" >> /tmp/.cinstres

    echo "Installing kernel headers" >> /tmp/.cinstres
    KERNEL_VERSION=$(uname -r)
    if [[ $KERNEL_VERSION == *PAE* ]]; then
        echo "executing: yum -q -y install kernel-PAE-devel-${KERNEL_VERSION%.PAE}" >> /tmp/.cinstres
        yum -q -y install kernel-PAE-devel-${KERNEL_VERSION%.PAE} 2>> /tmp/.cinstres || kernel_warning
    elif [[ $KERNEL_VERSION == *stab* ]]; then
        echo "executing: yum -q -y install vzkernel-devel-$KERNEL_VERSION" >> /tmp/.cinstres
        yum -q -y install vzkernel-devel-$KERNEL_VERSION 2>> /tmp/.cinstres || kernel_warning
    elif [[ $KERNEL_VERSION == *uek* ]]; then
        echo "executing: yum -q -y install kernel-uek-devel-$KERNEL_VERSION" >> /tmp/.cinstres
        yum -q -y install kernel-uek-devel-$KERNEL_VERSION 2>> /tmp/.cinstres || kernel_warning
    else
        echo "executing: yum -q -y install kernel-devel-$KERNEL_VERSION" >> /tmp/.cinstres
        yum -q -y install kernel-devel-$KERNEL_VERSION 2>> /tmp/.cinstres || kernel_warning
    fi

    echo "* Installing Sysdig"
    echo "executing: yum -y install sysdig-$SYSDIG_INSTALL_VERSION" >> /tmp/.cinstres
    yum -q -y install sysdig-$SYSDIG_INSTALL_VERSION 2>> /tmp/.cinstres
    if [ $? -ne 0 ]; then
        yum -q -y install sysdig-$SYSDIG_INSTALL_VERSION-* 2>> /tmp/.cinstres
    fi

    echo "attempting to install versionlock and lock sysdig version" >> /tmp/.cinstres
    if [[ $(sysdig --version) =~ $SYSDIG_INSTALL_VERSION ]]; then
        echo "executing: yum -q -y install yum-plugin-versionlock" >> /tmp/.cinstres
        yum -q -y install yum-plugin-versionlock 2>> /tmp/.cinstres
        echo "executing: yum versionlock sysdig" >> /tmp/.cinstres
        yum -q -y versionlock sysdig 2>> /tmp/.cinstres
    fi
}

function install_deb {
    export DEBIAN_FRONTEND=noninteractive

    if ! hash curl > /dev/null 2>&1; then
        echo "no curl found, attempting to install curl via apt-get" >> /tmp/.cinstres
        echo "executing: apt-get -qq -y install curl" >> /tmp/.cinstres
        apt-get -qq -y install curl 2>> /tmp/.cinstres
    fi

    echo "Getting and installing Sysdig via apt" >> /tmp/.cinstres
    echo "executing: curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | apt-key add -" >> /tmp/.cinstres
    curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | apt-key add - 2>> /tmp/.cinstres || echo "[ERROR] Unable to download sysdig public key" >> /tmp/.cinstres
    echo "executing: curl -s -o /etc/apt/sources.list.d/draios.list https://s3.amazonaws.com/download.draios.com/stable/deb/draios.list" >> /tmp/.cinstres
    curl -s -o /etc/apt/sources.list.d/draios.list https://s3.amazonaws.com/download.draios.com/stable/deb/draios.list 2>> /tmp/.cinstres || echo "[ERROR] Unable to download sysdig repository" >> /tmp/.cinstres
    echo "executing: apt-get -qq update < /dev/null" >> /tmp/.cinstres
    apt-get -qq update < /dev/null

    echo "Installing kernel headers" >> /tmp/.cinstres
    echo "executing: apt-get -qq -y install linux-headers-$(uname -r) < /dev/null" >> /tmp/.cinstres
    apt-get -qq -y install linux-headers-$(uname -r) 2>> /tmp/.cinstres || kernel_warning

    echo "* Installing Sysdig"
    echo "executing: apt-get -qq -y install sysdig=$SYSDIG_INSTALL_VERSION" >> /tmp/.cinstres
    apt-get -qq -y install sysdig=$SYSDIG_INSTALL_VERSION 2>> /tmp/.cinstres || echo "[ERROR] Failed to install sysdig via apt" >> /tmp/.cinstres
    if [ $? -ne 0 ]; then
        apt-get -qq -y install sysdig=$SYSDIG_INSTALL_VERSION-* 2>> /tmp/.cinstres
    fi

    SYS_VER=$(sysdig --version)
    if [[ $SYS_VER =~ $SYSDIG_INSTALL_VERSION ]]; then
        echo "Correct sysdig version is present, locking via apt-mark" >> /tmp/.cinstres
        echo "executing: apt-mark hold sysdig" >> /tmp/.cinstres
        apt-mark -qq hold sysdig || echo "[ERROR] failed to lock sysdig version" >> /tmp/.cinstres
    else
        echo "[ERROR] Couldn't locate sysdig after installation, check out installation errors" >> /tmp/.cinstres
    fi
}

function unsupported_arch {
    echo '[ERROR] Unsupported architecture. Please see supported architectures in this page: https://help.cynet.com/en/articles/47-supported-operating-systems'
    echo '[ERROR] Unsupported architecture. Full details:' >> /tmp/.cinstres
    log_filename_components
    exit 1
}

function unsupported_distribution {
    echo '[ERROR] Unsupported distribution. Please see supported distribution in this page: https://help.cynet.com/en/articles/47-supported-operating-systems'
    echo '[ERROR] Unsupported distribution. Full details:' >> /tmp/.cinstres
    log_filename_components
    exit 1
}

function unsupported_sysdig {
    echo '[ERROR] Sysdig does not support this specific OS version, skipping Sysdig installation'
    echo '[ERROR] skipping sysdig installation, Host Details:' >> /tmp/.cinstres
    log_filename_components
}

function kernel_warning {
    echo "[WARNING] Unable to find kernel files for the current kernel version $(uname -r), This might interfere with Sysdig installation"
    echo "[WARNING] Kernel Headers Failure, unable to install kernel headers for: " $(uname -r) >> /tmp/.cinstres
    echo "Full details:" >> /tmp/.cinstres
    log_filename_components
}

echo_script_usage_instructions()
{
    echo "[-h | --help] Print this help menu and exit"
    echo ""
    echo "Usage: $0 [disable_sysdig_installation] [disable_auditd_installation] [package_path]"
    echo "       - disable_sysdig_installation: true/false (default: false)"
    echo "       - disable_auditd_installation: true/false (default: true)"
    echo "       - package_path: Path to rpm/deb"
    echo ""
    echo "Examples: {Command line = Outcome}"
    echo "       $0                                       = Install Cynet and auditd"
    echo "       $0 true true                             = Install Cynet, auditd, sysdig"
    echo "       $0 false true                            = Install Cynet and, sysdig"
    echo "       $0 /Explicit/Path/To/cyneteps.rpm true   = Install Cynet and, sysdig"
}

help()
{
    for arg in "${args[@]}"; do
        if [[ "$arg" == "--help" || "$arg" == "-h" ]]; then
            echo "This script is used to install Cynet and its dependencies"
            echo_script_usage_instructions
            exit 0
        fi
    done
}

starting_log()
{
    echo "* Cynet Installer Started $date_now"
    echo "Cynet Installer Started $date_now" > /tmp/.cinstres
}

detect_architecture()
{
    echo "* Detecting architecture"

    if [[ ! $ARCH = *86 ]] && [ ! $ARCH = "x86_64" ] && [ ! $ARCH = "s390x" ]; then
        unsupported_arch
    fi

    if [ $ARCH = "s390x" ]; then
        echo "[WARNING] A Docker container is the only officially supported platform on s390x"
        echo "[WARNING] A Docker container is the only officially supported platform on s390x" >> /tmp/.cinstres
    fi
}

is_sysdig_installed()
{
    echo "Checking if Sysdig is already installed before attempting to install Sysdig: $SYSDIG_INSTALL_VERSION"
    if command -v sysdig >/dev/null 2>&1; then
        SYSDIG_CURRENT_VERSION=$(sysdig --version)
        IS_SYSDIG_INSTALLED=1
        echo "Sysdig is already installed with version: $SYSDIG_CURRENT_VERSION"
        echo "Sysdig is already installed with version: $SYSDIG_CURRENT_VERSION" >> /tmp/.cinstres
        if [[ $SYSDIG_CURRENT_VERSION =~ $SYSDIG_INSTALL_VERSION ]]; then
            echo "Valid Sysdig version detected: $SYSDIG_CURRENT_VERSION" >> /tmp/.cinstres
        else
            echo "For optimal performance, it's recommended to use sysdig version $SYSDIG_INSTALL_VERSION. The currently installed version is: $SYSDIG_CURRENT_VERSION"
        fi
    else
        IS_SYSDIG_INSTALLED=0
        echo "Sysdig isn't installed" >> /tmp/.cinstres
    fi
}

is_sysdig_working()
{
    sysdig > /dev/null 2>&1 &
    local sysdig_pid=$!
    sleep 5
    if ps -p $sysdig_pid > /dev/null; then
        echo "Sysdig is working" >> /tmp/.cinstres
        kill $sysdig_pid
    else
        echo "[ERROR] could not verify if Sysdig is working as expected, please re-try or contact Cynet Support"
        echo "Sysdig isn't working" >> /tmp/.cinstres
    fi
}

start_install_sysdig()
{
    echo "Attempting to install Sysdig version: $SYSDIG_INSTALL_VERSION"
    case "$DISTRO" in

        "Ubuntu")
            if [ $VERSION -ge 10 ]; then
                install_deb
                return 1
            fi
            ;;

        "LinuxMint")
            if [ $VERSION -ge 9 ]; then
                install_deb
                return 1
            fi
            ;;

        "Debian")
            if [ $VERSION -ge 6 ]; then
                install_deb
                return 1
            elif [[ $VERSION == *sid* ]]; then
                install_deb
                return 1
            fi
            ;;

        "oracle" | "centos" | "redhat")
            if [ $VERSION -ge 6 ]; then
                install_rpm
                return 1
            fi
            ;;

        "almalinux" | "rocky")
            if [ $VERSION -ge 7 ]; then
                install_rpm
                return 1
            fi
            ;;

        "amazon")
            install_rpm
            return 1
            ;;

        "fedoraproject")
            if [ $VERSION -ge 13 ]; then
                install_rpm
                return 1
            fi
            ;;

        *)
            echo "[ERROR] Sysdig does not support this specific OS version, skipping Sysdig installation" >> /tmp/.cinstres
            unsupported_sysdig
            return 0
            ;;
    esac

    echo "[ERROR] Sysdig does not support this specific OS version, skipping Sysdig installation" >> /tmp/.cinstres
    unsupported_sysdig
    return 0
}

check_sysdig_version()
{
    if [[ $(sysdig --version) =~ $SYSDIG_INSTALL_VERSION ]]; then
        echo "Sysdig version: $SYSDIG_INSTALL_VERSION succesfully installed" >> /tmp/.cinstres
    else
        echo "[ERROR] Failed to install Sysdig version: $SYSDIG_INSTALL_VERSION"
        echo "[ERROR] sysdig version: $SYSDIG_INSTALL_VERSION failed to install" >> /tmp/.cinstres
    fi
}

install_auditd()
{
    case "$DISTRO" in
        "oracle" | "centos" | "redhat" | "amazon" | "fedoraproject" | "almalinux" | "rocky")
            echo "executing: yum -q -y install audit" >> /tmp/.cinstres
            yum -q -y install audit 2>> /tmp/.cinstres
            ;;
        "Ubuntu" | "Debian" | "LinuxMint" )
            echo "executing: apt-get -qq -y install auditd" >> /tmp/.cinstres
            apt-get -qq -y install auditd 2>> /tmp/.cinstres
            ;;
        *)
            echo "This script doesn't install auditd for this distro!" >> /tmp/.cinstres
            ;;
    esac
}

install_eps()
{
    echo "* Installing EPS"
    echo "Attempting to install EPS now" >> /tmp/.cinstres
    echo "Detected Distro: $DISTRO, Version: $VERSION" >> /tmp/.cinstres

    case "$DISTRO" in
        "oracle" | "centos" | "redhat" | "amazon" | "fedoraproject" | "almalinux" | "rocky")
            if [ ! -f "${EPS_PATH}" ]; then
                echo "[ERROR] couldn't find ${EPS_PATH} in current directory, please run installer from the same directory of the unzipped package"
                echo "[ERROR] no ${EPS_PATH} in current directory, exiting" >> /tmp/.cinstres
                exit 1
            fi
            echo "attempting to install EPS rpm" >> /tmp/.cinstres
            if [ $(rpm -qa | grep Cynet) ] ; then
                echo "[ERROR] detected existing Cynet package installed already: $(rpm -qa | grep Cynet), please properly uninstall before installing again"
                echo "[ERROR] detected existing Cynet package installed already: $(rpm -qa | grep Cynet), exiting" >> /tmp/.cinstres
                exit 1
            fi
            echo "executing: rpm -ivh ${EPS_PATH}" >> /tmp/.cinstres
            rpm -ivh ${EPS_PATH} >> /tmp/.cinstres 2>&1
            if [ $(rpm -qa | grep Cynet) ] ; then
                echo "RPM Installation Succeeded"
                echo "RPM Installation Succeeded, package details:" >> /tmp/.cinstres
                rpm -qa | grep Cynet >> /tmp/.cinstres
            else
                echo "[ERROR] Cynet RPM not detected, please try again or contact Cynet Support"
                echo "[ERROR] Couldn't locate EPS RPM after installation" >> /tmp/.cinstres
                log_filename_components
                exit 1
            fi
            ;;
        "Ubuntu" | "Debian" | "LinuxMint" )
            if [ ! -f "${EPS_PATH}" ]; then
                echo "[ERROR] could not find ${EPS_PATH} in current directory, please run installer from the same directory of the unzipped package"
                echo "[ERROR] no ${EPS_PATH} in current directory, exiting" >> /tmp/.cinstres
                exit 1
            fi
            echo "attempting to install EPS deb" >> /tmp/.cinstres
            if [ $(dpkg -l cyneteps | grep -o cyneteps) ] ; then
                echo "[ERROR] detected an existing Cynet package is installed already:"
                PACKAGE_INFO=$(echo -e $(dpkg -s cyneteps | grep -E '^(Status|Version):' | sed 's/Version:/\\nVersion:/'))
                echo "$PACKAGE_INFO"
                echo "please properly uninstall before attempting to re-install Cynet"
                echo -e "[ERROR] detected existing Cynet package installed already: \n$PACKAGE_INFO " >> /tmp/.cinstres
                exit 1
            fi
            echo "executing: dpkg -i ${EPS_PATH}" >> /tmp/.cinstres
            dpkg -i ${EPS_PATH} >> /tmp/.cinstres 2>&1
            if [ $(dpkg -l | grep -o cyneteps) ] ; then
                echo "deb Installation Succeeded"
                echo "deb Installation succeeded, package details:" >> /tmp/.cinstres
                dpkg -l cyneteps | grep cyneteps >> /tmp/.cinstres
            else
                echo "[ERROR] Cynet deb not detected, please try again or contact Cynet Support"
                echo "[ERROR] Couldn't locate EPS deb after installation" >> /tmp/.cinstres
                log_filename_components
                exit 1
            fi
            ;;
        "sles" | "opensuse-leap" )
            if [ ! -f "${EPS_PATH}" ]; then
                echo "[ERROR] could not find ${EPS_PATH} in current directory, please run installer from the same directory of the unzipped package"
                echo "[ERROR] no ${EPS_PATH} in current directory, exiting" >> /tmp/.cinstres
                exit 1
            fi
            echo "attempting to install EPS using zypper" >> /tmp/.cinstres
            if [ $(rpm -qa | grep Cynet) ] ; then
                echo "[ERROR] detected existing Cynet package installed already: $(rpm -qa | grep Cynet), please properly uninstall before installing again"
                echo "[ERROR] detected existing Cynet package installed already: $(rpm -qa | grep Cynet), exiting" >> /tmp/.cinstres
                exit 1
            fi
            echo "executing: zypper --non-interactive --no-gpg-checks install ${EPS_PATH}" >> /tmp/.cinstres
            zypper --non-interactive --no-gpg-checks install ${EPS_PATH} >> /tmp/.cinstres 2>&1
            if [ $(rpm -qa | grep Cynet) ] ; then
                echo "Zypper Installation Succeeded"
                echo "Zypper Installation Succeeded, package details:" >> /tmp/.cinstres
                rpm -qa | grep Cynet >> /tmp/.cinstres
            else
                echo "[ERROR] Cynet package not detected after installation, please try again or contact Cynet Support"
                echo "[ERROR] Couldn't locate EPS package after installation" >> /tmp/.cinstres
                log_filename_components
                exit 1
            fi
            ;;
        *)
            echo "[ERROR] undefined distro: $DISTRO, aborting EPS install" >> /tmp/.cinstres
            unsupported_distribution
            exit 1
            ;;
    esac
}

verify_eps_installation()
{
    echo "* Verifying installation, please wait"
    local timeout=50
    local counter=0
    while (( counter < timeout )); do
        sleep 2
        if [[ $(pgrep CynetEPS) ]] ; then
            echo "* Installation Completed Successfully"
            echo "Installation Succeeded, Detected cynetEPS pid: $(pgrep CynetEPS)" >> /tmp/.cinstres
            return;
        fi
        ((counter+=2))
    done
    echo "[ERROR] could not locate CynetEPS, Installation Failed"
    echo "[ERROR] could not detect CynetEPS process after 50 seconds, Installation likely failed" >> /tmp/.cinstres
    exit 1
}

set_real_package_name()
{
    EPS_PATH_LOWER=$(echo "${EPS_PATH}" | tr '[:upper:]' '[:lower:]')
    for file in *; do
        if [ "$(echo "${file}" | tr '[:upper:]' '[:lower:]')" = "${EPS_PATH_LOWER}" ]; then
            EPS_PATH=${file}
            echo "Package real name: ${EPS_PATH}"
            echo "Package real name: ${EPS_PATH}" >> /tmp/.cinstres
            break
        fi
    done
}

get_script_arguments()
{
    if [ -f /etc/debian_version ]; then
        EPS_PATH="cyneteps.deb"
    else
        EPS_PATH="cyneteps.rpm"
    fi
    set_real_package_name

    DISABLE_SYSDIG_INSTALL="false"
    DISABLE_AUDITD_INSTALL="true"
    if [[ -n "${args[0]}" ]]; then
        DISABLE_SYSDIG_INSTALL="${args[0]}"
    fi

    if [[ -n "${args[1]}" ]]; then
        DISABLE_AUDITD_INSTALL="${args[1]}"
    fi

    if [[ -n "${args[2]}" ]]; then
        EPS_PATH="${args[2]}";
    fi

    if [[ ${#args[@]} -gt 3 ]]; then
        echo "Invalid command line!"
        echo_script_usage_instructions
        exit 1
    fi
}

validate_script_argument()
{
    if [ ! -f "${EPS_PATH}" ]; then
        echo "Given EPS path '${EPS_PATH}' doesn't exist" >> /tmp/.cinstres
        echo "Given EPS path '${EPS_PATH}' doesn't exist"
        exit 1
    fi

    if [[ "$DISABLE_SYSDIG_INSTALL" != "true" && "$DISABLE_SYSDIG_INSTALL" != "false" ]]; then
        echo "Invalid value for DISABLE_SYSDIG_INSTALL: $DISABLE_SYSDIG_INSTALL" >> /tmp/.cinstres
        echo "Invalid value for DISABLE_SYSDIG_INSTALL: $DISABLE_SYSDIG_INSTALL"
        exit 1
    fi

    if [[ "$DISABLE_AUDITD_INSTALL" != "true" && "$DISABLE_AUDITD_INSTALL" != "false" ]]; then
        echo "Invalid value for DISABLE_AUDITD_INSTALL: $DISABLE_AUDITD_INSTALL" >> /tmp/.cinstres
        echo "Invalid value forxvalue for DISABLE_AUDITD_INSTALL: $DISABLE_AUDITD_INSTALL"
        exit 1
    fi
}

verify_CynetEPSArguments_txt()
{
    local scriptDirectory
    scriptDirectory="$(dirname "$0")"
    if [ -f "$scriptDirectory/CynetEPSArguments.txt" ]; then
        echo "Found $scriptDirectory/CynetEPSArguments in current directory, moving it to tmp" >> /tmp/.cinstres
        echo "executing: mv $scriptDirectory/CynetEPSArguments.txt /tmp/" >> /tmp/.cinstres
        mv "$scriptDirectory"/CynetEPSArguments.txt /tmp/ || echo "[ERROR] Failed to move CynetEPSArguments to tmp" >> /tmp/.cinstres
    elif [ -f CynetEPSArguments.txt ]; then
        echo "Found CynetEPSArguments in current directory, moving it to tmp" >> /tmp/.cinstres
        echo "executing: mv CynetEPSArguments.txt /tmp/" >> /tmp/.cinstres
        mv CynetEPSArguments.txt /tmp/ || echo "[ERROR] Failed to move CynetEPSArguments to tmp" >> /tmp/.cinstres
    elif [ -f /tmp/CynetEPSArguments.txt ]; then
        echo "Found CynetEPSArguments in /tmp/ already, will be used for installation" >> /tmp/.cinstres
    else
        echo "[ERROR] couldn't find CynetEPSArguments.txt in current directory, please run installer from the same directory of the unzipped package"
        echo "[ERROR] no CynetEPSArguments in current directory or /tmp/, exiting" >> /tmp/.cinstres
        exit 1
    fi
}

help

if [ $(id -u) != 0 ]; then
    echo "[ERROR] Installer must be run as root (or with sudo), please run installer as root"
    exit 1
fi

starting_log
detect_architecture

# script arguments
get_script_arguments
validate_script_argument

# CynetEPSArguments.txt
verify_CynetEPSArguments_txt

# Sysdig
set_version_and_distro
DISTRO_SUPPORTED=$?

# ================================
# RECOMENDACIÓN APLICADA:
# - Siempre detecta si sysdig existe.
# - SOLO intenta instalar sysdig si NO existe Y la distro es soportada ($DISTRO_SUPPORTED -eq 1).
# - Si sysdig ya existe (aunque la distro NO sea soportada), valida versión y prueba funcionamiento.
# ================================
if [[ "$DISABLE_SYSDIG_INSTALL" == "false" ]]; then
    is_sysdig_installed

    # Instalar SOLO si falta y la distro es soportada
    if [[ $IS_SYSDIG_INSTALLED -eq 0 && $DISTRO_SUPPORTED -eq 1 ]]; then
        start_install_sysdig
        check_sysdig_version
        is_sysdig_working
    fi

    # Si ya existe, validar y probar aunque la distro no sea soportada
    if [[ $IS_SYSDIG_INSTALLED -eq 1 ]]; then
        check_sysdig_version
        is_sysdig_working
    fi

    # Si falta sysdig y la distro NO es soportada: no instalar, solo registrar
    if [[ $IS_SYSDIG_INSTALLED -eq 0 && $DISTRO_SUPPORTED -ne 1 ]]; then
        echo "[WARNING] Sysdig no está instalado y la distro no es soportada ($DISTRO). No se intentará instalar sysdig." >> /tmp/.cinstres
    fi
fi

# Auditd
if [[ "$DISABLE_AUDITD_INSTALL" == "false" ]]; then
    install_auditd
fi

# EPS
install_eps
verify_eps_installation

mv /tmp/.cinstres  /opt/Cynet/EngineInstallationInfo.txt
chmod 600 /opt/Cynet/EngineInstallationInfo.txt
