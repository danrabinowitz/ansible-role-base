#!/bin/bash
# This file is a modified version of cloud-init.yml.tpl.
# It is used on systems which don't use cloud-init.


# Exit immediately if any command fails.
set -e

# Print a message to stderr when attempting to expand a variable that is not set. Also, immediately exit.
set -u

# Cause pipelines to fail on the first command which fails instead of dying later on down the pipeline.
set -o pipefail

################################################################################
# Documentation and usage
function doc {
  >&2 cat << EOF
This script does the following:

1) Installs an ssh public key for provisioning
2) Installs tailscale
3) Uses a non_reusable_tailscale_auth_key, provided either via an ENV var or interactive prompt, to configure tailscale
4) Locks down ssh completely
5) Opens ssh from provisioner IP only, if a provisioner IP is provided via an ENV var
6) Starts ssh service

It does NOT set up wireguard, as that can be done via ansible, later.
It does NOT install homebrew on Mac.
EOF
}

function usage {
  if [ "$platform" = "MacOS" ]; then
    >&2 cat << EOF
To bootstrap a mac:
1) Install macOS
2) Connect to network
3) Create an account which will be the admin account and also used for provisioning.
4) Open Terminal and run this script
   curl -fsSL https://d2r.io/macos1 > run.sh
EOF
  else
    echo "Use cloud init to run:"
  fi
  cmd_usage
}

function cmd_usage {
  >&2 echo "provisioner_ip=[ip] [provisioner_username=[username]] bash run.sh"
  exit 1
}

################################################################################
# Define variable names
provisioner_username="${provisioner_username:-}"
provisioner_ip="${provisioner_ip:-}"
provisioner_authorized_key="${provisioner_authorized_key:-ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAZ0+EyH5FgErxe7B5Vd5NT18vlaBVPC1yt9hlwGCO2J dan@mbp}"
non_reusable_tailscale_auth_key="${non_reusable_tailscale_auth_key:-}"
################################################################################
# Define platform
function get_platform() {
  if [ "$(uname -s)" = "Darwin" ]; then
    echo "MacOS"
    return
  fi
  if [ -r '/etc/issue.net' ]; then
    local issue1
    issue1=$(cut -d' ' -f1 /etc/issue.net)
    if [ "$issue1" = "Raspbian" ] || [ "$issue1" = "Ubuntu" ]; then
      echo "$issue1"
      return
    fi
    return
  fi
  echo "UNKNOWN"
}

platform=$(get_platform)
################################################################################
# Validate params

# echo "Before running sudo, get the username of the current user."
if [ -z "$provisioner_username" ]; then
  >&2 echo "provisioner_username is not set. Checking to see if we can use the current user."
  user=$(whoami)
  if [ "$user" = "root" ]; then
    >&2 echo "provisioner_username is required"
    cmd_usage
  fi
  provisioner_username="$user"
fi
>&2 echo "Using provisioner_username=${provisioner_username}"

>&2 echo "Ensuring ${provisioner_username} has a home directory"
if [ "$platform" = "MacOS" ]; then
  home="/Users/${provisioner_username}"
else
  home="/home/${provisioner_username}"
fi

if [ ! -d "${home}" ]; then
  >&2 echo "ERROR: Home directory ${home} for ${provisioner_username} does not exist!"
  exit 2
fi

if [ -z "$provisioner_ip" ]; then
  >&2 echo "WARNING: provisioner_ip is not set. This will prevent ssh access from being enabled."
  # TODO: Add a flag like "provisioner_ip='SKIP'" to allow this script to continue without ssh?
  # For now though, just abort.
  cmd_usage
fi

# TODO: Maybe validate provisioner_ip?

################################################################################
# echo "Be sure we're running as root"
if [ $EUID != 0 ]; then
  >&2 echo "Not root. Trying again with sudo..."
  # set -x
  sudo \
    provisioner_username="$provisioner_username" \
    provisioner_ip="$provisioner_ip" \
    provisioner_authorized_key="$provisioner_authorized_key" \
    non_reusable_tailscale_auth_key="$non_reusable_tailscale_auth_key" \
    bash "$0" "$@";
  exit "$?";
fi

################################################################################
################################################################################
>&2 echo "TODO: Is there a way to lock down the firewall on MacOS before we proceed, so that only wg port is open?"

################################################################################
# umask
umask 077

################################################################################
>&2 echo "Creating ssh authorized keys file..."

mkdir -p "${home}/.ssh"
chown "$provisioner_username" "${home}/.ssh"
chmod 700 "${home}/.ssh"

echo "${provisioner_authorized_key}" > "${home}/.ssh/authorized_keys"
chown "$provisioner_username" "${home}/.ssh/authorized_keys"
chmod 600 "${home}/.ssh/authorized_keys"

################################################################################

if [ -z "$non_reusable_tailscale_auth_key" ]; then
  read -erp 'Non-reusable tailscale auth key: ' non_reusable_tailscale_auth_key
fi

>&2 echo "Installing tailscale..."
if [ "$platform" = "MacOS" ]; then
  >&2 echo "There are three tailscale variants on MacOS per https://tailscale.com/kb/1065/macos-variants/"
  >&2 echo "Here we use the 'tailscaled' variant."
  >&2 echo "The Mac App Store version has more features and auto-updates, but it can't run until you log in."
  >&2 echo "For some use cases, such as testing MacOS installs, this is not desirable."

set -x

  # Installation instructions for tailscaled variant: https://github.com/tailscale/tailscale/wiki/Tailscaled-on-macOS
  mkdir -p /usr/local/bin
  chown root /usr/local/bin
  chmod 755 /usr/local/bin

  os=$(uname -s | tr '[:upper:]' '[:lower:]')

  if [ "$(uname -m)" = "x86_64" ]; then
    arch="amd64"
  fi

  # osarch=$(echo "$(uname -s)-$(uname -m)" | tr '[:upper:]' '[:lower:]')
  osarch="$os-$arch"

  curl -fsSL "https://danrabinowitz01.sfo2.digitaloceanspaces.com/bootstrap/bin/${osarch}/tailscale" > /usr/local/bin/tailscale
  chmod 755 /usr/local/bin/tailscale

  curl -fsSL "https://danrabinowitz01.sfo2.digitaloceanspaces.com/bootstrap/bin/${osarch}/tailscaled" > /tmp/tailscaled
  chmod 755 /tmp/tailscaled
  /tmp/tailscaled install-system-daemon
  # Previous command creates /Library/LaunchDaemons/com.tailscale.tailscaled.plist which could be used to check if it worked.

  tailscale up --authkey="$non_reusable_tailscale_auth_key"
else
  >&2 echo "Not implemented yet"
  # curl -fsSL https://tailscale.com/install.sh | sh
  exit 3
fi

################################################################################
>&2 echo "Tightening and enabling firewall..."
if [ "$platform" = "MacOS" ]; then
  cat <<EOS >/etc/pf.conf

anchor "com.djrtechconsulting/*"
load anchor "com.djrtechconsulting" from "/etc/pf.anchors/com.djrtechconsulting"
EOS

  cat <<EOS >/etc/pf.anchors/com.djrtechconsulting
anchor "SSH"
load anchor "SSH" from "/etc/pf.rules/pfssh.rule"
EOS

  mkdir -p /etc/pf.rules
  cat <<EOS >/etc/pf.rules/pfssh.rule
block return in proto tcp from any to any port 22
EOS

  if [ -n "$provisioner_ip" ]; then
    cat <<EOS >>/etc/pf.rules/pfssh.rule
pass in inet proto tcp from ${provisioner_ip}/32 to any port 22 no state
EOS
  fi

  >&2 echo "Enabling firewall..."
  pfctl -f /etc/pf.conf && pfctl -E

  >&2 echo "Maybe run 'pfctl -sa' to check firewall rules"

  >&2 echo "Starting ssh..."
  systemsetup -setremotelogin on

else
  >&2 echo "Not implemented yet"
  exit 3

  ufw allow 51820/udp
fi

echo "Done. Proceed with provisioning."
