#!/bin/bash

##########################################
#
# This script will copy all the required files into the correct locations on the server
# Config goes into: /usr/local/etc/scanoss/cryptography
# Logs go into: /var/log/scanoss/cryptography
# Service definition goes into: /etc/systemd/system
# Binary & startup º into: /usr/local/bin
#
################################################################

if [ "$1" = "-h" ] || [ "$1" = "-help" ] ; then
  echo "$0 [-help] [environment]"
  echo "   Setup and copy the relevant files into place on a server to run the SCANOSS CRYPTOGRAPHY API"
  echo "   [environment] allows the optional specification of a suffix to allow multiple services to be deployed at the same time (optional)"
  exit 1
fi

CONF_DIR=/usr/local/etc/scanoss/cryptography
LOGS_DIR=/var/log/scanoss/cryptography
CONF_DOWNLOAD=https://raw.githubusercontent.com/scanoss/cryptography/main/config/app-config-prod.json

ENVIRONMENT=""
FORCE_INSTALL=0

export SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

while getopts ":ye:" opt; do
  case $opt in
    y)
      FORCE_INSTALL=1
      ;;
    e)
      ENVIRONMENT="$OPTARG"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      ;;
  esac
done

shift $((OPTIND - 1))

# Makes sure the scanoss user exists
export RUNTIME_USER=scanoss
if ! getent passwd $RUNTIME_USER > /dev/null ; then
  echo "Runtime user does not exist: $RUNTIME_USER"
  echo "Please create using: useradd --system $RUNTIME_USER"
  exit 1
fi
# Also, make sure we're running as root
if [ "$EUID" -ne 0 ] ; then
  echo "Please run as root"
  exit 1
fi

if [ "$FORCE_INSTALL" -eq 1 ]; then
  echo "Forcing installation..."
else
  read -p "Install Cryptography API $ENVIRONMENT (y/n) [n]? " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Starting installation..."
  else
    echo "Stopping."
    exit 1
  fi
fi
# Setup all the required folders and ownership
echo "Setting up Cryptography API system folders..."
if ! mkdir -p "$CONF_DIR" ; then
  echo "mkdir failed"
  exti 1
fi
if ! mkdir -p "$LOGS_DIR" ; then
  echo "mkdir failed"
  exit 1
fi
if [ "$RUNTIME_USER" != "root" ] ; then
  export LOG_DIR=/var/log/scanoss
  echo "Changing ownership of $LOG_DIR to $RUNTIME_USER ..."
  if ! chown -R $RUNTIME_USER $LOG_DIR ; then
    echo "chown of $LOG_DIR to $RUNTIME_USER failed"
    exit 1
  fi
fi
# Setup the service on the system (defaulting to service name without environment)
SC_SERVICE_FILE="scanoss-cryptography-api.service"
SC_SERVICE_NAME="scanoss-cryptography-api"
if [ -n "$ENVIRONMENT" ] ; then
  SC_SERVICE_FILE="scanoss-cryptography-api-${ENVIRONMENT}.service"
  SC_SERVICE_NAME="scanoss-cryptography-api-${ENVIRONMENT}"
fi
export service_stopped=""
if [ -f "/etc/systemd/system/$SC_SERVICE_FILE" ] ; then
  echo "Stopping $SC_SERVICE_NAME service first..."
  if ! systemctl stop "$SC_SERVICE_NAME" ; then
    echo "service stop failed"
    exit 1
  fi
  export service_stopped="true"
fi
echo "Copying service startup config..."
if [ -f "$SCRIPT_DIR/$SC_SERVICE_FILE" ] ; then
  if ! cp "$SCRIPT_DIR/$SC_SERVICE_FILE" /etc/systemd/system ; then
    echo "service copy failed"
    exti 1
  fi
else 
  echo "No service file found at $SCRIPT_DIR/$SC_SERVICE_FILE"
fi
if ! cp $SCRIPT_DIR/scanoss-cryptography-api.sh /usr/local/bin ; then
  echo "Cryptography api startup script copy failed"
  exit 1
fi
if ! chmod +x /usr/local/bin/scanoss-cryptography-api.sh ; then
  echo "Cryptography api startup script permissions failed"
  exit 1
fi
# Copy in the configuration file if requested
CONF=app-config-prod.json
if [ -n "$ENVIRONMENT" ] ; then
  CONF="app-config-${ENVIRONMENT}.json"
fi
if [ -f "$SCRIPT_DIR/$CONF" ] ; then
  echo "Copying app config to $CONF_DIR ..."
  if ! cp "$SCRIPT_DIR/$CONF" "$CONF_DIR/" ; then
    echo "copy $CONF failed"
    exit 1
  fi
else
  if [ ! -f "$CONF_DIR/$CONF" ] ; then
    read -p "Download sample $CONF (y/n) [y]? " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]] ; then
      echo "Please put the config file into: $CONF_DIR/$CONF"
    elif ! curl $CONF_DOWNLOAD > "$CONF_DIR/$CONF" ; then
      echo "Warning: curl download failed"
    fi
  fi
fi
# Copy the binaries if requested
BINARY=scanoss-cryptography-api
if [ -f "$SCRIPT_DIR/$BINARY" ] ; then
  echo "Copying app binary to /usr/local/bin ..."
  if ! cp $SCRIPT_DIR/$BINARY /usr/local/bin ; then
    echo "copy $BINARY failed"
    echo "Please make sure the service is stopped: systemctl stop scanoss-cryptography-api"
    exit 1
  fi
  if ! chmod +x /usr/local/bin/$BINARY ; then
    echo "execution permission on $BINARY failed"
    echo "Please make sure the use can set the binary as executable: chmod +x /usr/local/bin/scanoss-cryptography-api"
  fi
else
  echo "Please copy the Cryptography API binary file into: /usr/local/bin/$BINARY"
fi
echo "Installation complete."
if [ "$service_stopped" == "true" ] ; then
  echo "Restarting service after install..."
  if ! systemctl start "$SC_SERVICE_NAME" ; then
    echo "failed to restart service"
    exit 1
  fi
  systemctl status "$SC_SERVICE_NAME"
fi
if [ ! -f "$CONF_DIR/$CONF" ] ; then
  echo
  echo "Warning: Please create a configuration file in: $CONF_DIR/$CONF"
  echo "A sample version can be downloaded from GitHub:"
  echo "curl $CONF_DOWNLOAD > $CONF_DIR/$CONF"
fi
echo
echo "Review service config in: $CONF_DIR/$CONF"
echo "Logs are stored in: $LOGS_DIR"
echo "Start the service using: systemctl start $SC_SERVICE_NAME"
echo "Stop the service using: systemctl stop $SC_SERVICE_NAME"
echo "Get service status using: systemctl status $SC_SERVICE_NAME"
echo "Count the number of running scans using: pgrep -P \$(pgrep -d, scanoss-cryptography-api) | wc -l"
echo