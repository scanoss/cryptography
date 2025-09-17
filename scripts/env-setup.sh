#!/bin/bash

##########################################
#
# This script will copy all the required files into the correct locations on the server
# Config goes into: /usr/local/etc/scanoss/cryptography
# Logs go into: /var/log/scanoss/cryptography
# Service definition goes into: /etc/systemd/system
# Binary & startup go into: /usr/local/bin
#
################################################################

show_help() {
  echo "$0 [-h|--help] [-f|--force] [environment]"
  echo "   Setup and copy the required files into place on a server to run the SCANOSS CRYPTOGRAPHY API"
  echo "   [environment] allows the optional specification of a suffix to allow multiple services"
  echo "   -f | --force   Run without interactive prompts (skip questions, skip SQLite, do not overwrite config)"
  exit 1
}

export BASE_C_PATH=/usr/local/etc/scanoss
export CONFIG_DIR="${BASE_C_PATH}/cryptography"
export LOGS_DIR=/var/log/scanoss/cryptography
export CONF_DOWNLOAD_URL=https://raw.githubusercontent.com/scanoss/cryptography/refs/heads/main/config/app-config-prod.json
export DB_PATH_BASE=/var/lib/scanoss
export SQLITE_PATH="${DB_PATH_BASE}/db/sqlite/cryptography"
export SQLITE_DB_NAME=crypto.sqlite
export TARGET_SQLITE_DB_NAME=db.sqlite

ENVIRONMENT=""
FORCE_INSTALL=0

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
export SCRIPT_DIR

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_help
      ;;
    -f|--force)
      FORCE_INSTALL=1
      shift
      ;;
    *)
      ENVIRONMENT="$1"
      shift
      ;;
  esac
done

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
  echo "[FORCE] Installing Cryptography API $ENVIRONMENT without prompts..."
else
  read -p "Install Cryptography API $ENVIRONMENT (y/n) [n]? " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Stopping."
    exit 1
  fi
fi

# Setup all the required folders and ownership
echo "Setting up Cryptography API system folders..."
mkdir -p "$CONFIG_DIR" || { echo "mkdir failed"; exit 1; }
mkdir -p "$LOGS_DIR" || { echo "mkdir failed"; exit 1; }

if [ "$RUNTIME_USER" != "root" ] ; then
  export LOG_DIR=/var/log/scanoss
  echo "Changing ownership of $LOG_DIR to $RUNTIME_USER ..."
  chown -R $RUNTIME_USER $LOG_DIR || { echo "chown of $LOG_DIR failed"; exit 1; }
fi

# Setup the service
SC_SERVICE_FILE="scanoss-cryptography-api.service"
SC_SERVICE_NAME="scanoss-cryptography-api"
if [ -n "$ENVIRONMENT" ] ; then
  SC_SERVICE_FILE="scanoss-cryptography-api-${ENVIRONMENT}.service"
  SC_SERVICE_NAME="scanoss-cryptography-api-${ENVIRONMENT}"
fi

service_stopped=""
if [ -f "/etc/systemd/system/$SC_SERVICE_FILE" ] ; then
  echo "Stopping $SC_SERVICE_NAME service first..."
  systemctl stop "$SC_SERVICE_NAME" || { echo "service stop failed"; exit 1; }
  service_stopped="true"
fi

echo "Copying service startup config..."
if [ -f "$SCRIPT_DIR/$SC_SERVICE_FILE" ] ; then
  cp "$SCRIPT_DIR/$SC_SERVICE_FILE" /etc/systemd/system || { echo "service copy failed"; exit 1; }
else 
  echo "No service file found at $SCRIPT_DIR/$SC_SERVICE_FILE"
fi

cp "$SCRIPT_DIR/scanoss-cryptography-api.sh" /usr/local/bin || { echo "Cryptography api startup script copy failed"; exit 1; }
chmod +x /usr/local/bin/scanoss-cryptography-api.sh

####################################################
#                   SETUP SQLITE DB                #
####################################################
if [ "$FORCE_INSTALL" -eq 1 ]; then
  echo "[FORCE] Skipping all SQLite DB setup."
else
  SQLITE_DB_PATH=""
  if [ -f "./$SQLITE_DB_NAME" ]; then
      SQLITE_DB_PATH="./$SQLITE_DB_NAME"
  elif [ -f "../$SQLITE_DB_NAME" ]; then
      SQLITE_DB_PATH="../$SQLITE_DB_NAME"
  fi

  mkdir -p "$SQLITE_PATH" || { echo "Error: Failed to create directory: $SQLITE_PATH"; exit 1; }
  SQLITE_TARGET_PATH="$SQLITE_PATH/$TARGET_SQLITE_DB_NAME"

  if [ -n "$SQLITE_DB_PATH" ]; then
      if [ -f "$SQLITE_TARGET_PATH" ]; then
          read -p "SQLite file found. Replace $SQLITE_TARGET_PATH? (n/y) [n]: " -n 1 -r
          echo
          if [[ "$REPLY" =~ ^[Yy]$ ]]; then
            cp "$SQLITE_DB_PATH" "$SQLITE_TARGET_PATH" || { echo "Error: Failed to copy SQLite database"; exit 1; }
          else
            echo "Skipping DB copy."
          fi
      else
          echo "Copying SQLite DB..."
          cp "$SQLITE_DB_PATH" "$SQLITE_TARGET_PATH" || { echo "Error: Failed to copy SQLite database"; exit 1; }
      fi
  else
    echo "Warning: No SQLite DB detected. Skipping DB setup."
  fi
fi

####################################################
#                  COPY CONFIG FILE                #
####################################################
TARGET_CONFIG_PATH="$CONFIG_DIR/$CONF"
CONF=app-config-prod.json
if [ -n "$ENVIRONMENT" ] ; then
  CONF="app-config-${ENVIRONMENT}.json"
fi

CONFIG_FILE_PATH=""
if [ -f "./$CONF" ]; then
    CONFIG_FILE_PATH="./$CONF"
elif [ -f "../$CONF" ]; then
    CONFIG_FILE_PATH="../$CONF"
fi

if [ -n "$CONFIG_FILE_PATH" ]; then
  if [ -f "$TARGET_CONFIG_PATH" ]; then
      if [ "$FORCE_INSTALL" -eq 1 ]; then
        echo "[FORCE] Config already exists at $TARGET_CONFIG_PATH. Skipping replacement."
      else
        read -p "Configuration file exists. Replace $TARGET_CONFIG_PATH? (y/n) [n]? " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
          cp "$CONFIG_FILE_PATH" "$CONFIG_DIR/" || { echo "Error: Failed to copy config file"; exit 1; }
        else
          echo "Skipping config file copy."
        fi
      fi
  else
      cp "$CONFIG_FILE_PATH" "$CONFIG_DIR/" || { echo "Error: Failed to copy config file"; exit 1; }
  fi
else
   if [ ! -f "$TARGET_CONFIG_PATH" ]; then
     if [ "$FORCE_INSTALL" -eq 1 ]; then
       echo "[FORCE] Downloading default config to $CONFIG_DIR/$CONF"
       curl -s "$CONF_DOWNLOAD_URL" > "$CONFIG_DIR/$CONF" || echo "Error: Failed to download configuration file"
     else
       read -p "Configuration file not found. Download example $CONF file? (n/y) [n]: " -n 1 -r
       echo
       if [[ $REPLY =~ ^[Yy]$ ]]; then
         curl -s "$CONF_DOWNLOAD_URL" > "$CONFIG_DIR/$CONF" || echo "Error: Failed to download configuration file"
       else
         echo "Warning: Please put the config file into: $CONFIG_DIR/$CONF"
       fi
     fi
   fi
fi

####################################################
#         CHANGE OWNERSHIP AND PERMISSIONS         #
####################################################
chown -R $RUNTIME_USER:$RUNTIME_USER "$BASE_C_PATH" || { echo "Error: chown failed"; exit 1; }
find "$CONFIG_DIR" -type d -exec chmod 0750 "{}" \;
find "$CONFIG_DIR" -type f -exec chmod 0600 "{}" \;
chown -R $RUNTIME_USER:$RUNTIME_USER "$DB_PATH_BASE"
find "$DB_PATH_BASE" -type d -exec chmod 0750 "{}" \;
find "$DB_PATH_BASE" -type f -exec chmod 0640 "{}" \;

# Copy the binary
BINARY=scanoss-cryptography-api
if [ -f "$SCRIPT_DIR/$BINARY" ] ; then
  echo "Copying app binary to /usr/local/bin ..."
  cp "$SCRIPT_DIR/$BINARY" /usr/local/bin || { echo "copy $BINARY failed"; exit 1; }
  chmod +x /usr/local/bin/$BINARY || echo "Warning: could not set executable permission on $BINARY"
else
  echo "Please copy the Cryptography API binary file into: /usr/local/bin/$BINARY"
fi

echo "Installation complete."
if [ "$service_stopped" == "true" ] ; then
  echo "Restarting service after install..."
  systemctl start "$SC_SERVICE_NAME" || { echo "failed to restart service"; exit 1; }
  systemctl status "$SC_SERVICE_NAME"
fi

if [ ! -f "$CONFIG_DIR/$CONF" ] ; then
  echo
  echo "Warning: Please create a configuration file in: $CONFIG_DIR/$CONF"
  echo "A sample version can be downloaded from GitHub:"
  echo "curl $CONF_DOWNLOAD_URL > $CONFIG_DIR/$CONF"
fi

echo
echo "Review service config in: $TARGET_CONFIG_PATH"
echo "Logs are stored in: $LOGS_DIR"
echo "Start the service using: systemctl start $SC_SERVICE_NAME"
echo "Stop the service using: systemctl stop $SC_SERVICE_NAME"
echo "Get service status using: systemctl status $SC_SERVICE_NAME"
echo "Count the number of running scans using: pgrep -P \$(pgrep -d, scanoss-cryptography-api) | wc -l"
