#!/usr/bin/env bash
# shellcheck disable=SC1090

# tangram xtgmnode
# (c) 2021 Tangram
#
# Install with this command (from your Linux machine):
#
# bash <(curl -sSL https://raw.githubusercontent.com/tangramproject/tangram/master/install/linux/install.sh)

# -e option instructs bash to immediately exit if any command [1] has a non-zero exit status
# We do not want users to end up with a partially working install, so we exit the script
# instead of continuing the installation with something broken
set -e

while test $# -gt 0
do
    case "$1" in
        --help)
          echo "  Install script arguments:"
          echo
          echo "    --runasuser                   : use this user account instead of creating a new one"
          echo "    --runasgroup                  : use this user group instead of creating a new one"
          echo "    --config-skip                 : skip the node's configuration wizard (--noninteractive implies --config-skip)"
          echo "    --no-service                  : do not install node as a service"
          echo "    --noninteractive              : use default options without user interaction"
          echo "    --uninstall                   : uninstall node"
          echo
          exit 0
          ;;
        --upgrade)
            UPGRADE=true
            IS_SKIP_CONFIG=true
            ;;
        --runasuser)
            CUSTOM_USER=$2
            shift
            ;;
        --runasgroup)
            CUSTOM_GROUP=$2
            shift
            ;;
        --config-skip)
            IS_SKIP_CONFIG=true
            ;;
        --no-service)
            IS_NO_SERVICE=true
            ;;
        --noninteractive)
            IS_NON_INTERACTIVE=true
            IS_SKIP_CONFIG=true
            ;;
        --uninstall)
            IS_UNINSTALL=true
            ;;
        --*) echo "bad option $1"
            exit 1
            ;;
    esac
    shift
done

######## VARIABLES #########
# For better maintainability, we store as much information that can change in variables
# This allows us to make a change in one place that can propagate to all instances of the variable
# These variables should all be GLOBAL variables, written in CAPS
# Local variables will be in lowercase and will exist only within functions
# It's still a work in progress, so you may see some variance in this guideline until it is complete
if [[ "$OSTYPE" == "darwin"* ]]; then
  IS_MACOS=true
  ARCHITECTURE_UNIFIED="osx-x64"

  TANGRAM_XTGMNODE_VERSION=$(curl --silent "https://api.github.com/repos/tangramproject/tangram/releases/latest" | grep -w '"tag_name": "v.*"' | cut -f2 -d ":" | cut -f2 -d "\"")
  TANGRAM_XTGMNODE_GROUP="tangram_xtgmnode"
  TANGRAM_XTGMNODE_USER="_tangram_xtgmnode"

  LAUNCHD_SERVICE_PATH="/Library/LaunchDaemons/"
  TANGRAM_XTGMNODE_LAUNCHD_SERVICE="tangram-xtgmnode.plist"
  TANGRAM_XTGMNODE_LAUNCHD_SERVICE_URL="https://raw.githubusercontent.com/tangramproject/tangram/master/install/macos/${TANGRAM_XTGMNODE_LAUNCHD_SERVICE}"

elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
  IS_LINUX=true
  DISTRO=$(grep '^ID=' /etc/os-release | cut -d '=' -f 2)
  DISTRO_VERSION=$(grep '^VERSION_ID=' /etc/os-release | cut -d '=' -f 2 | tr -d '"')
  ARCHITECTURE=$(uname -m)

  ARCHITECTURE_ARM=("armv7l")
  ARCHITECTURE_ARM64=("aarch64")
  ARCHITECTURE_X64=("x86_64")

  if [[ " ${ARCHITECTURE_ARM[*]} " =~ " ${ARCHITECTURE} " ]]; then
    echo "32-bit architectures are not supported. Found architecture ${ARCHITECTURE}"
    exit 1

  elif [[ " ${ARCHITECTURE_ARM64[*]} " =~ " ${ARCHITECTURE} " ]]; then
    ARCHITECTURE_UNIFIED="linux-arm64"

  elif [[ " ${ARCHITECTURE_X64[*]} " =~ " ${ARCHITECTURE} " ]]; then
    ARCHITECTURE_UNIFIED="linux-x64"
  else
    # Fall back to x64 architecture
    ARCHITECTURE_UNIFIED="linux-x64"
  fi

  if [ -f /etc/debian_version ]; then
    IS_DEBIAN_BASED=true
  fi

  INIT=$(ps --no-headers -o comm 1)

  TANGRAM_XTGMNODE_VERSION=$(curl --silent "https://api.github.com/repos/tangramproject/tangram/releases/latest" | grep -Po '"tag_name": "\K.*?(?=")')
  TANGRAM_XTGMNODE_GROUP="tangram-xtgmnode"
  TANGRAM_XTGMNODE_USER="tangram-xtgmnode"

  SYSTEMD_SERVICE_PATH="/etc/systemd/system/"
  TANGRAM_XTGMNODE_SYSTEMD_SERVICE="tangram-xtgmnode.service"
  TANGRAM_XTGMNODE_SYSTEMD_SERVICE_URL="https://raw.githubusercontent.com/tangramproject/tangram/master/install/linux/${TANGRAM_XTGMNODE_SYSTEMD_SERVICE}"

else
  echo "Unsupported OS type ${OSTYPE}"
  exit 1
fi


TANGRAM_XTGMNODE_VERSION_SHORT=$(echo "${TANGRAM_XTGMNODE_VERSION}" | cut -c 2-)
TANGRAM_XTGMNODE_ARTIFACT_PREFIX="tangram-xtgmnode_${TANGRAM_XTGMNODE_VERSION_SHORT}_"
TANGRAM_XTGMNODE_URL_PREFIX="https://github.com/tangramproject/tangram/releases/download/${TANGRAM_XTGMNODE_VERSION}/"

TANGRAM_XTGMNODE_OPT_PATH="/opt/tangram/xtgmnode/"
TANGRAM_XTGMNODE_TMP_PATH="/tmp/opt/tangram/xtgmnode/"


# Check if we are running on a real terminal and find the rows and columns
# If there is no real terminal, we will default to 80x24
if [ -t 0 ] ; then
  screen_size=$(stty size)
else
  screen_size="24 80"
fi
# Set rows variable to contain first number
printf -v rows '%d' "${screen_size%% *}"
# Set columns variable to contain second number
printf -v columns '%d' "${screen_size##* }"


# Divide by two so the dialogs take up half of the screen, which looks nice.
r=$(( rows / 2 ))
c=$(( columns / 2 ))
# Unless the screen is tiny
r=$(( r < 20 ? 20 : r ))
c=$(( c < 70 ? 70 : c ))


# Set these values so the installer can still run in color
COL_NC='\e[0m' # No Color
COL_LIGHT_GREEN='\e[1;32m'
COL_LIGHT_RED='\e[1;31m'
TICK="[${COL_LIGHT_GREEN}✓${COL_NC}]"
CROSS="[${COL_LIGHT_RED}✗${COL_NC}]"
INFO="[i]"
# shellcheck disable=SC2034
DONE="${COL_LIGHT_GREEN} done!${COL_NC}"
OVER="\\r\\033[K"


is_command() {
  # Checks for existence of string passed in as only function argument.
  # Exit value of 0 when exists, 1 if not exists. Value is the result
  # of the `command` shell built-in call.
  local check_command="$1"

  command -v "${check_command}" >/dev/null 2>&1
}


install_info() {
  ARCHIVE="${TANGRAM_XTGMNODE_ARTIFACT_PREFIX}${ARCHITECTURE_UNIFIED}.tar.gz"
  printf "\n  %b Using installation archive %s\n" "${TICK}" "${ARCHIVE}"
}

install_dependencies() {
  printf "\n  %b Checking dependencies\n" "${INFO}"

  if [ "${IS_DEBIAN_BASED}" = true ]; then
    if dpkg -s libc6-dev &> /dev/null; then
      printf "  %b libc6-dev\n" "${TICK}"
    else
      printf "  %b libc6-dev\n" "${CROSS}"
      printf "  %b Installing libc6-dev\n" "${INFO}"
      sudo apt-get update
      if [ "${IS_NON_INTERACTIVE}" = true ]; then
        sudo DEBIAN_FRONTEND=noninteractive apt-get -yq install libc6-dev
      else
        sudo apt-get install libc6-dev
      fi
    fi
    if dpkg -s libgmp-dev &> /dev/null; then
      printf "  %b libgmp-dev\n" "${TICK}"
    else
      printf "  %b libgmp-dev\n" "${CROSS}"
      printf "  %b Installing libgmp-dev\n" "${INFO}"
      sudo apt-get update
      if [ "${IS_NON_INTERACTIVE}" = true ]; then
        sudo DEBIAN_FRONTEND=noninteractive apt-get -yq install libgmp-dev
      else
        sudo apt-get install libgmp-dev
      fi
    fi
    if dpkg -s libsodium-dev &> /dev/null; then
      printf "  %b libsodium-dev\n" "${TICK}"
    else
      printf "  %b libsodium-dev\n" "${CROSS}"
      printf "  %b Installing libsodium-dev\n" "${INFO}"
      sudo apt-get update
      if [ "${IS_NON_INTERACTIVE}" = true ]; then
        sudo DEBIAN_FRONTEND=noninteractive apt-get -yq install libsodium-dev
      else
        sudo apt-get install libsodium-dev
      fi
    fi
    if dpkg -s libssl-dev &> /dev/null; then
      printf "  %b libssl-dev\n" "${TICK}"
    else
      printf "  %b libssl-dev\n" "${CROSS}"
      printf "  %b Installing libssl-dev\n" "${INFO}"
      sudo apt-get update
      if [ "${IS_NON_INTERACTIVE}" = true ]; then
        sudo DEBIAN_FRONTEND=noninteractive apt-get -yq install libssl-dev
      else
        sudo apt-get install libssl-dev
      fi
    fi    
    if dpkg -s libatomic1 &> /dev/null; then
      printf "  %b libatomic1\n" "${TICK}"
    else
      printf "  %b libatomic1\n" "${CROSS}"
      printf "  %b Installing libatomic1\n" "${INFO}"
      sudo apt-get update
      if [ "${IS_NON_INTERACTIVE}" = true ]; then
        sudo DEBIAN_FRONTEND=noninteractive apt-get -yq install libatomic1
      else
        sudo apt-get install libatomic1
      fi
    fi

    # Create symlinks for libdl.so if they're not where we expect them
    if [ ! -e /usr/lib/x86_64-linux-gnu/libdl.so ]; then
        sudo ln -s /usr/lib/x86_64-linux-gnu/libdl.so.2 /usr/lib/x86_64-linux-gnu/libdl.so
    fi

  fi
  
  if cat /etc/*release | grep ^NAME | grep CentOS* || cat /etc/*release | grep ^NAME | grep AlmaLinux*; then
    if yum -q list installed glibc-devel &> /dev/null; then
      printf "  %b glibc-devel\n" "${TICK}"
    else
      printf "  %b glibc-devel\n" "${CROSS}"
      printf "  %b Installing glibc-devel\n" "${INFO}"
      sudo yum update
      yum install glibc-devel
    fi    
    if yum -q list installed libnsl.x86_64 &> /dev/null; then
      printf "  %b libnsl.x86_64\n" "${TICK}"
    else
      printf "  %b libnsl.x86_64\n" "${CROSS}"
      printf "  %b Installing libnsl.x86_64\n" "${INFO}"
      sudo yum update
      yum install libnsl.x86_64
    fi     
    if yum -q list installed libatomic.x86_64 &> /dev/null; then
      printf "  %b libatomic.x86_64\n" "${TICK}"
    else
      printf "  %b libatomic.x86_64\n" "${CROSS}"
      printf "  %b Installing libatomic.x86_64\n" "${INFO}"
      sudo yum update
      yum install libatomic.x86_64
    fi

    # Create symlinks for libdl.so if they're not where we expect them
    if [ ! -e /usr/lib64/libdl.so ]; then
        sudo ln -s /usr/lib64/libdl.so.2 /usr/lib64/libdl.so
    fi
  fi  
}

download_archive() {
  printf "\n"
  printf "  %b Checking download utility\n" "${INFO}"
  if is_command curl; then
    printf "  %b curl\n" "${TICK}"
    HAS_CURL=true
  else
    printf "  %b curl\n" "${CROSS}"
    HAS_CURL=false
  fi

  if [ ! "${HAS_CURL}" = true ]; then
    if is_command wget; then
      printf "  %b wget\n" "${TICK}"
    else
      printf "  %b wget\n" "${CROSS}"
      printf "\n"
      printf "      Could not find a utility to download the archive. Please install either curl or wget.\n\n"
      return 1
    fi
  fi

  DOWNLOAD_PATH="/tmp/tangram-xtgmnode/"
  DOWNLOAD_FILE="${DOWNLOAD_PATH}${ARCHIVE}"
  DOWNLOAD_URL="${TANGRAM_XTGMNODE_URL_PREFIX}${ARCHIVE}"

  printf "\n";
  printf "  %b Checking archive %s" "${INFO}" "${ARCHIVE}"
  if [ "${HAS_CURL}" = true ]; then
    if curl --silent --fail "${DOWNLOAD_URL}" &> /dev/null; then
      printf " %b  %b Archive %s found\n\n" "${OVER}" "${TICK}" "${ARCHIVE}"
    else
      printf " %b  %b Archive %s cannot be found\n\n" "${OVER}" "${CROSS}" "${ARCHIVE}"
      exit 1
    fi
  else
    if wget -q "${DOWNLOAD_URL}"; then
      printf " %b  %b Archive %s found\n\n" "${OVER}" "${TICK}" "${ARCHIVE}"
    else
      printf " %b  %b Archive %s cannot be found\n\n" "${OVER}" "${CROSS}" "${ARCHIVE}"
      exit 1
    fi
  fi

  printf "  %b Downloading archive %s" "${INFO}" "${ARCHIVE}"

  if [ "${HAS_CURL}" = true ]; then
    curl -s -L --create-dirs -o "${DOWNLOAD_FILE}" "${DOWNLOAD_URL}"
  else
    mkdir -p "${DOWNLOAD_PATH}"
    wget -q -O "${DOWNLOAD_FILE}" "${DOWNLOAD_URL}"
  fi

  printf "%b  %b Downloaded archive %s\n" "${OVER}" "${TICK}" "${ARCHIVE}"
}


install_systemd_service() {
  printf "\n  %b Downloading systemd service file" "${INFO}"

  if [ "${HAS_CURL}" = true ]; then
    curl -s -L -o "/tmp/${TANGRAM_XTGMNODE_SYSTEMD_SERVICE}" "${TANGRAM_XTGMNODE_SYSTEMD_SERVICE_URL}"
  else
    wget -q -O "/tmp/${TANGRAM_XTGMNODE_SYSTEMD_SERVICE}" "${TANGRAM_XTGMNODE_SYSTEMD_SERVICE_URL}"
  fi

  printf "%b  %b Downloaded systemd service file\n" "${OVER}" "${TICK}"

  printf "  %b Installing systemd service file" "${INFO}"

  CUSER=${TANGRAM_XTGMNODE_USER}
  if [ $CUSTOM_USER ]; then
      CUSER=${CUSTOM_USER}
      sed -ie "s/User=.*/User=${CUSER}/" "/tmp/${TANGRAM_XTGMNODE_SYSTEMD_SERVICE}"
  fi
  CGROUP=${TANGRAM_XTGMNODE_GROUP}
  if [ $CUSTOM_GROUP ]; then
      CGROUP=${CUSTOM_GROUP}
      sed -ie "s/Group=.*/Group=${CGROUP}/" "/tmp/${TANGRAM_XTGMNODE_SYSTEMD_SERVICE}"
  fi
  sudo install -m 755 -o "${CUSER}" -g "${CGROUP}" "/tmp/${TANGRAM_XTGMNODE_SYSTEMD_SERVICE}" "${SYSTEMD_SERVICE_PATH}${TANGRAM_XTGMNODE_SYSTEMD_SERVICE}"

  printf "%b  %b Installed systemd service file\n" "${OVER}" "${TICK}"

  printf "  %b Removing temporary systemd service file" "${INFO}"
  rm "/tmp/${TANGRAM_XTGMNODE_SYSTEMD_SERVICE}"
  printf "%b  %b Removed temporary systemd service file\n" "${OVER}" "${TICK}"

  printf "  %b Reloading systemd daemon" "${INFO}"
  sudo systemctl daemon-reload
  printf "%b  %b Reloading systemd daemon\n" "${OVER}" "${TICK}"

  printf "  %b Enabling systemd service" "${INFO}"
  sudo systemctl enable "${TANGRAM_XTGMNODE_SYSTEMD_SERVICE}" &> /dev/null
  printf "%b  %b Enabled systemd service\n" "${OVER}" "${TICK}"

  printf "  %b Starting systemd service" "${INFO}"
  sudo systemctl start "${TANGRAM_XTGMNODE_SYSTEMD_SERVICE}" > /dev/null
  printf "%b  %b Started systemd service\n" "${OVER}" "${TICK}"
}


install_launchd_service() {
  printf "\n  %b Downloading launchd service file" "${INFO}"

  if [ "${HAS_CURL}" = true ]; then
    curl -s -L -o "/tmp/${TANGRAM_XTGMNODE_LAUNCHD_SERVICE}" "${TANGRAM_XTGMNODE_LAUNCHD_SERVICE_URL}"
  else
    wget -q -O "/tmp/${TANGRAM_XTGMNODE_LAUNCHD_SERVICE}" "${TANGRAM_XTGMNODE_LAUNCHD_SERVICE_URL}"
  fi

  printf "%b  %b Downloaded launchd service file\n" "${OVER}" "${TICK}"

  printf "  %b Installing launchd service file" "${INFO}"

  sudo install -m 755 -o "${TANGRAM_XTGMNODE_USER}" -g "${TANGRAM_XTGMNODE_GROUP}" "/tmp/${TANGRAM_XTGMNODE_LAUNCHD_SERVICE}" "${LAUNCHD_SERVICE_PATH}${TANGRAM_XTGMNODE_LAUNCHD_SERVICE}"

  printf "%b  %b Installed launchd service file\n" "${OVER}" "${TICK}"

  printf "  %b Removing temporary launchd service file" "${INFO}"
  rm "/tmp/${TANGRAM_XTGMNODE_LAUNCHD_SERVICE}"
  printf "%b  %b Removed temporary launchd service file\n" "${OVER}" "${TICK}"

  printf "  %b Loading launchd service" "${INFO}"
  sudo launchctl load "${LAUNCHD_SERVICE_PATH}${TANGRAM_XTGMNODE_LAUNCHD_SERVICE}" &> /dev/null
  printf "%b  %b Loaded launchd service\n" "${OVER}" "${TICK}"

  printf "  %b Starting launchd service" "${INFO}"
  sudo launchctl start "${TANGRAM_XTGMNODE_LAUNCHD_SERVICE}" > /dev/null
  printf "%b  %b Started launchd service\n" "${OVER}" "${TICK}"
}

stop_service() {
  if [ "${IS_LINUX}" = true ]; then
    if [ "${INIT}" = "systemd" ]; then
      if [ $(systemctl is-active "${TANGRAM_XTGMNODE_SYSTEMD_SERVICE}") = "active" ]; then
        printf "\n"
        printf "  %b Stopping systemd service" "${INFO}"
        sudo systemctl stop "${TANGRAM_XTGMNODE_SYSTEMD_SERVICE}" >/dev/null
        printf "%b  %b Stopped systemd service\n" "${OVER}" "${TICK}"
      fi
    fi
  elif [ "${IS_MACOS}" = true ]; then
    if [ -f "${LAUNCHD_SERVICE_PATH}${TANGRAM_XTGMNODE_LAUNCHD_SERVICE}" ]; then
      if [ $(sudo launchctl list | grep "${TANGRAM_XTGMNODE_LAUNCHD_SERVICE}") ]; then
        printf "\n"
        printf "  %b Stopping launchd service" "${INFO}"
        sudo launchctl stop "${TANGRAM_XTGMNODE_LAUNCHD_SERVICE}" >/dev/null
        printf "%b  %b Stopped systemd service\n" "${OVER}" "${TICK}"
      fi
    fi
  fi
}

user_create_linux() {
  echo groupadd "$1"
  sudo groupadd -f "$1" >/dev/null
  if [ -f "/etc/arch-release" ]; then
    sudo useradd --system --gid $(getent group "$1" | cut -d: -f3) --no-create-home "$2" >/dev/null
  else
    sudo adduser --system --gid $(getent group "$1" | cut -d: -f3) --no-create-home "$2" >/dev/null
  fi
}

user_create_macos() {
  for (( uid = 500;; --uid )) ; do
    if ! id -u $uid &>/dev/null; then
      if ! dscl /Local/Default -ls Groups gid | grep -q [^0-9]$uid\$ ; then
        sudo dscl /Local/Default -create Groups/"$1" >/dev/null
        sudo dscl /Local/Default -create Groups/"$1" Password \* >/dev/null
        sudo dscl /Local/Default -create Groups/"$1" PrimaryGroupID $uid >/dev/null
        sudo dscl /Local/Default -create Groups/"$1" RealName "$1" >/dev/null
        sudo dscl /Local/Default -create Groups/"$1" RecordName _"$1" "$1" >/dev/null

        sudo dscl /Local/Default -create Users/"$2" >/dev/null
        sudo dscl /Local/Default -create Users/"$2" PrimaryGroupID $uid
        sudo dscl /Local/Default -create Users/"$2" UniqueID $uid >/dev/null
        USER_CREATED=true
        break
      fi
    fi
  done

  if [ ! "${USER_CREATED}" = true ]; then
    printf "\n  %b Could not create user\n\n" "${CROSS}"
    exit 1
  fi
}

user_create() {
  if [ $CUSTOM_USER ]; then
      printf "\n  %b Checking if user %s exists" "${INFO}" "${CUSTOM_USER}"
      if [ "${IS_LINUX}" = true ]; then
        if id "${CUSTOM_USER}" &>/dev/null; then
          printf "%b  %b User %s exists\n" "${OVER}" "${TICK}" "${CUSTOM_USER}"
        else
          printf "%b  %b User %s does not exist\n" "${OVER}" "${CROSS}" "${CUSTOM_USER}"
          exit 1
        fi
      elif [ "${IS_MACOS}" = true ]; then
        if dscl /Local/Default read /Users/"${TANGRAM_XTGMNODE_USER}" &>/dev/null; then
          printf "%b  %b User %s exists\n" "${OVER}" "${TICK}" "${CUSTOM_USER}"
        else
          printf "%b  %b User %s does not exist\n" "${OVER}" "${CROSS}" "${CUSTOM_USER}"
          exit 1
        fi
      fi
  else
      printf "\n  %b Checking if user %s exists" "${INFO}" "${TANGRAM_XTGMNODE_USER}"

      if [ "${IS_LINUX}" = true ]; then
        if id "${TANGRAM_XTGMNODE_USER}" &>/dev/null; then
          printf "%b  %b User %s exists\n" "${OVER}" "${TICK}" "${TANGRAM_XTGMNODE_USER}"
          USER_EXISTS=true
        fi
      elif [ "${IS_MACOS}" = true ]; then
        if dscl /Local/Default read /Users/"${TANGRAM_XTGMNODE_USER}" &>/dev/null; then
          printf "%b  %b User %s exists\n" "${OVER}" "${TICK}" "${TANGRAM_XTGMNODE_USER}"
          USER_EXISTS=true
        fi
      fi

      if [ ! "${USER_EXISTS}" = true ]; then
        printf "%b  %b User %s does not exist\n" "${OVER}" "${CROSS}" "${TANGRAM_XTGMNODE_USER}"
        printf "  %b Creating user %s" "${INFO}" "${TANGRAM_XTGMNODE_USER}"

        if [ "${IS_LINUX}" = true ]; then
          user_create_linux "${TANGRAM_XTGMNODE_GROUP}" "${TANGRAM_XTGMNODE_USER}"
        elif [ "${IS_MACOS}" = true ]; then
          user_create_macos "${TANGRAM_XTGMNODE_GROUP}" "${TANGRAM_XTGMNODE_USER}"
        fi

        printf "%b  %b Created user %s\n" "${OVER}" "${TICK}" "${TANGRAM_XTGMNODE_USER}"
      fi
  fi
  if [ $CUSTOM_GROUP ]; then
      printf "\n  %b Checking if group %s exists" "${INFO}" "${CUSTOM_GROUP}"
      if [ "${IS_LINUX}" = true ]; then
        if getent group "${CUSTOM_GROUP}" &>/dev/null; then
          printf "%b  %b Group %s exists\n" "${OVER}" "${TICK}" "${CUSTOM_GROUP}"
        else
          printf "%b  %b Group %s does not exist\n" "${OVER}" "${CROSS}" "${CUSTOM_GROUP}"
          exit 1
        fi
      elif [ "${IS_MACOS}" = true ]; then
          printf "%b  %b Custom groups not supported yet\n" "${OVER}" "${CROSS}"
          exit 1
      fi
  fi
}

install_archive() {
  printf "\n  %b Installing archive\n" "${INFO}"

  stop_service

  user_create

  if [ "${UPGRADE}" = true ]; then
      SAVE_DIR=/tmp/xtgmnode_data
      printf "  %b Upgrade requested - saving existing node data to %s" "${INFO}" "${SAVE_DIR}"
      mkdir -p ${SAVE_DIR}
      sudo cp ${TANGRAM_XTGMNODE_OPT_PATH}/appsettings.json ${SAVE_DIR}
      sudo cp -r ${TANGRAM_XTGMNODE_OPT_PATH}/keys ${SAVE_DIR}
      sudo cp -r ${TANGRAM_XTGMNODE_OPT_PATH}/storedb ${SAVE_DIR}
      printf "%b  %b Upgrade requested - saving existing node data to %s\n" "${OVER}" "${TICK}" "${SAVE_DIR}"
  fi;

  printf "  %b Unpacking archive to %s" "${INFO}" "${TANGRAM_XTGMNODE_TMP_PATH}"
  mkdir -p "${TANGRAM_XTGMNODE_TMP_PATH}"
  if [ "${IS_LINUX}" = true ]; then
    tar --overwrite -xf "${DOWNLOAD_FILE}" -C "${TANGRAM_XTGMNODE_TMP_PATH}"
  elif [ "${IS_MACOS}" = true ]; then
    tar -xf "${DOWNLOAD_FILE}" -C "${TANGRAM_XTGMNODE_TMP_PATH}"
  fi
  printf "%b  %b Unpacked archive to %s\n" "${OVER}" "${TICK}" "${TANGRAM_XTGMNODE_TMP_PATH}"

  printf "  %b Installing to %s" "${INFO}" "${TANGRAM_XTGMNODE_OPT_PATH}"
  sudo mkdir -p "${TANGRAM_XTGMNODE_OPT_PATH}"
  sudo cp -r "${TANGRAM_XTGMNODE_TMP_PATH}"* "${TANGRAM_XTGMNODE_OPT_PATH}"

  CUSER=${TANGRAM_XTGMNODE_USER}
  if [ $CUSTOM_USER ]; then
      CUSER=${CUSTOM_USER}
  fi
  CGROUP=${TANGRAM_XTGMNODE_GROUP}
  if [ $CUSTOM_GROUP ]; then
      CGROUP=${CUSTOM_GROUP}
  fi
  if [ "${UPGRADE}" = true ]; then
      printf "  %b Restoring saved node data" "${INFO}"
      SAVE_DIR=/tmp/xtgmnode_data
      sudo cp ${SAVE_DIR}/appsettings.json ${TANGRAM_XTGMNODE_OPT_PATH}
      sudo cp -r ${SAVE_DIR}/keys ${TANGRAM_XTGMNODE_OPT_PATH}
      sudo cp -r ${SAVE_DIR}/storedb ${TANGRAM_XTGMNODE_OPT_PATH}
      # Apply a new chmod/chown to the keys and database in case the user has changed
      sudo chmod -R 775 "${TANGRAM_XTGMNODE_OPT_PATH}/keys"
      sudo chown -R "${CUSER}":"${CGROUP}" "${TANGRAM_XTGMNODE_OPT_PATH}/keys"
      sudo chmod -R 775 "${TANGRAM_XTGMNODE_OPT_PATH}/storedb"
      sudo chown -R "${CUSER}":"${CGROUP}" "${TANGRAM_XTGMNODE_OPT_PATH}/storedb"
      printf "%b  %b Restored saved node data - %s can be removed if everything is okay\n" "${OVER}" "${TICK}" "${SAVE_DIR}"
  fi;
  sudo chmod 775 "${TANGRAM_XTGMNODE_OPT_PATH}"
  sudo chown "${CUSER}":"${CGROUP}" "${TANGRAM_XTGMNODE_OPT_PATH}"
  sudo chmod 664 "${TANGRAM_XTGMNODE_OPT_PATH}"/appsettings.json
  sudo chown "${CUSER}":"${CGROUP}" "${TANGRAM_XTGMNODE_OPT_PATH}"/appsettings.json

  printf "%b  %b Installed to %s\n" "${OVER}" "${TICK}" "${TANGRAM_XTGMNODE_OPT_PATH}"

  if [ "${IS_SKIP_CONFIG}" = true ]; then
    printf "  %b Skipping configuration util\n\n" "${CROSS}"
  else
    printf "  %b Running configuration util" "${INFO}"
    sudo -u "${CUSER}" "${TANGRAM_XTGMNODE_OPT_PATH}"xtgmnode --configure
    printf "%b  %b Run configuration util\n\n" "${OVER}" "${TICK}"
  fi

  if [ "${IS_NO_SERVICE}" = true ]; then
    printf "  %b Not installing service\n" "${CROSS}"
  else
    if [ "${IS_LINUX}" = true ]; then
      if [ "${INIT}" = "systemd" ]; then
        if [ "${IS_NON_INTERACTIVE}" = true ]; then
          printf "  %b Using default systemd service\n" "${TICK}"
          install_systemd_service
        else
          if whiptail --title "systemd service" --yesno "To run the node as a service, it is recommended to configure the node as a systemd service.\\n\\nWould you like to use the default systemd service configuration provided with tangram-xtgmnode?" "${7}" "${c}"; then
            printf "  %b Using default systemd service\n" "${TICK}"
            install_systemd_service
          else
            printf "  %b Not using default systemd service%s\n" "${CROSS}"
          fi
        fi
      elif [ "${INIT}" = "init" ]; then
        printf "  %b No tangram-xtgmnode init script available yet\n" "${CROSS}"

      else
        printf "\n"
        printf "  %b Unknown system %s. Please report this issue on\n" "${CROSS}" "${INIT}"
        printf "      https://github.com/tangramproject/tangram/issues/new"
      fi
    elif [ "${IS_MACOS}" = true ]; then
      if [ "${IS_NON_INTERACTIVE}" = true ]; then
        printf "  %b Using default launchd service\n" "${TICK}"
        install_launchd_service
      else
        if [ $(osascript -e 'button returned of (display dialog "To run the node as a service, it is recommended to configure the node as a launchd service. Would you like to use the default launchd service configuration provided with tangram-xtgmnode?" buttons {"No", "Yes"})') = 'Yes' ]; then
          printf "  %b Using default launchd service\n" "${TICK}"
          install_launchd_service
        else
          printf "  %b Not using default launchd service%s\n" "${CROSS}"
        fi
      fi
    fi
  fi
}


cleanup() {
  printf "\n"
  printf "  %b Cleaning up files" "${INFO}"
  rm -rf "${DOWNLOAD_PATH}"
  sudo rm -rf "${TANGRAM_XTGMNODE_TMP_PATH}"
  printf "%b  %b Cleaned up files\n" "${OVER}" "${TICK}"
}

finish() {
  printf "\n\n  %b Installation succesful\n\n" "${DONE}"
}

if [ "${IS_UNINSTALL}" = true ]; then
  printf "  %b Uninstalling\n\n" "${INFO}"

  stop_service

  if [ "${IS_LINUX}" = true ]; then
    if [ "${INIT}" = "systemd" ]; then
      if [ -f "${SYSTEMD_SERVICE_PATH}${TANGRAM_XTGMNODE_SYSTEMD_SERVICE}" ]; then
        if [ $(systemctl is-enabled "${TANGRAM_XTGMNODE_SYSTEMD_SERVICE}") = "enabled" ]; then
          printf "  %b Disabling service" "${INFO}"
          sudo systemctl disable "${TANGRAM_XTGMNODE_SYSTEMD_SERVICE}" >/dev/null 2>&1
          printf "%b  %b Disabled service\n" "${OVER}" "${TICK}"
        fi

        printf "  %b Removing service" "${INFO}"
        sudo rm -f "${SYSTEMD_SERVICE_PATH}${TANGRAM_XTGMNODE_SYSTEMD_SERVICE}"
        printf "%b  %b Removed service\n" "${OVER}" "${TICK}"

        printf "  %b Reloading systemd daemon" "${INFO}"
        sudo systemctl daemon-reload
        printf "%b  %b Reloading systemd daemon\n" "${OVER}" "${TICK}"
      fi
    fi
  elif [ "${IS_MACOS}" = true ]; then
    if [ -f "${LAUNCHD_SERVICE_PATH}${TANGRAM_XTGMNODE_LAUNCHD_SERVICE}" ]; then
      if [ sudo launchctl list | grep "${TANGRAM_XTGMNODE_LAUNCHD_SERVICE}" ]; then
        printf "  %b Unloading service" "${INFO}"
        sudo launchctl unload "${LAUNCHD_SERVICE_PATH}${TANGRAM_XTGMNODE_LAUNCHD_SERVICE}" >/dev/null 2>&1
        printf "%b  %b Unloaded service\n" "${OVER}" "${TICK}"
      fi

      printf "  %b Removing service" "${INFO}"
      sudo rm -f "${LAUNCHD_SERVICE_PATH}${TANGRAM_XTGMNODE_LAUNCHD_SERVICE}"
      printf "%b  %b Removed service\n" "${OVER}" "${TICK}"
    fi
  fi

  sudo rm -rf "${TANGRAM_XTGMNODE_OPT_PATH}"

  if [ "${IS_LINUX}" = true ]; then
    if getent passwd "${TANGRAM_XTGMNODE_USER}" >/dev/null; then
      printf "  %b Removing user" "${INFO}"
      sudo userdel "${TANGRAM_XTGMNODE_USER}" > /dev/null
      # group is remove implicitly
      printf "%b  %b Removed user\n" "${OVER}" "${TICK}"
    fi
  elif [ "${IS_MACOS}" = true ]; then
    if dscl /Local/Default read /Users/"${TANGRAM_XTGMNODE_USER}" &>/dev/null; then
      printf "  %b Removing user" "${INFO}"
      sudo dscl /Local/Default -delete /Users/"${TANGRAM_XTGMNODE_USER}" >/dev/null
      sudo dscl /Local/Default -delete /Groups/"${TANGRAM_XTGMNODE_GROUP}" >/dev/null
      printf "%b  %b Removed user\n" "${OVER}" "${TICK}"
    fi
  fi
  printf "\n\n  %b Uninstall successful\n\n" "${DONE}"

else
  install_info
  install_dependencies

  download_archive
  install_archive

  cleanup
  finish
fi
