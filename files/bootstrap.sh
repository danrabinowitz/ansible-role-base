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
# Define variable names
userdata_wireguard_address="${userdata_wireguard_address:-}"
userdata_admin_username="${userdata_admin_username:-}"
wg_addr="${wg_addr:-}"
allow_ssh_from_provisioner="${allow_ssh_from_provisioner:-true}"
################################################################################
# PLATFORM
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
function display_steps {
  if [ "$platform" = "MacOS" ]; then
    echo "To bootstrap a mac:"
    echo "1) Install macOS"
    echo "   -> While macOS is installing, allocate an ip address for the new machine"
    echo "2) Connect to network"
    echo "3) Create an account which will be the admin account"
    echo "4) Open Terminal and run this script"
    echo "   curl -fsSL https://d2r.io/macos1 > run.sh"
    echo "   wg_addr=a.b.c.d bash run.sh"
  else
    echo "Use cloud init"
  fi
}

function usage {

  # echo "userdata_admin_username=my-admin-user userdata_wireguard_address=a.b.c.d run.sh"
  echo "USAGE: wg_addr=a.b.c.d bash run.sh"
  echo "-----"
  display_steps
  exit 1
}

# Validate params
# echo "Before running sudo, get the username of the current user."
if [ -z "$userdata_admin_username" ]; then
  user=$(whoami)
  if [ "$user" = "root" ]; then
    echo "userdata_admin_username is required"
    usage
  fi
  userdata_admin_username="$user"
fi
echo "Using userdata_admin_username=$userdata_admin_username"

if [ -z "$userdata_wireguard_address" ]; then
  if [ -z "$wg_addr" ]; then
    echo "wireguard address is required"
    usage
  fi
  userdata_wireguard_address="$wg_addr"
fi

# TODO: Update allow_ssh_from_provisioner to take an IP address or an empty string.
if [ ! "$allow_ssh_from_provisioner" = "true" ] && [ ! "$allow_ssh_from_provisioner" = "false" ]; then
  echo "allow_ssh_from_provisioner must be either true or false"
  usage
fi

echo "Be sure we're running as root"
if [ $EUID != 0 ]; then
  echo "Not root. Trying again with sudo..."
  set -x
  sudo \
    allow_ssh_from_provisioner="$allow_ssh_from_provisioner" \
    userdata_admin_username="$userdata_admin_username" \
    userdata_wireguard_address="$userdata_wireguard_address" \
    bash "$0" "$@";
  exit "$?";
fi
################################################################################
echo "Checking for home directory for ${userdata_admin_username}..."
if [ "$platform" = "MacOS" ]; then
  home="/Users/${userdata_admin_username}"
else
  home="/home/${userdata_admin_username}"
fi

if [ ! -d "${home}" ]; then
  echo "ERROR: Home directory for ${userdata_admin_username} does not exist!"
  exit 2
fi
################################################################################
echo "TODO: Is there a way to lock down the firewall on MacOS before we proceed, so that only wg port is open?"
################################################################################
echo "Creating ssh authorized keys file..."
mkdir -p "${home}/.ssh"
chown "$userdata_admin_username" "${home}/.ssh"
chmod 700 "${home}/.ssh"
# TODO: Extract key into a variable.
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAZ0+EyH5FgErxe7B5Vd5NT18vlaBVPC1yt9hlwGCO2J dan@mbp" > "${home}/.ssh/authorized_keys"
chown "$userdata_admin_username" "${home}/.ssh/authorized_keys"
chmod 600 "${home}/.ssh/authorized_keys"

echo "Installing wireguard..."
if [ "$platform" = "MacOS" ]; then
  echo "TODO: Explore installing wireguard-go on macOS without requiring homebrew."
  # /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
  curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh > /tmp/brew-install.sh
  chmod 755 /tmp/brew-install.sh
  su - "$userdata_admin_username" -c "echo | /tmp/brew-install.sh"
  arch=$(arch)
  if [ "$arch" = "i386" ]; then
    brew_exe="/usr/local/bin/brew"
  else
    brew_exe="/opt/homebrew/bin/brew"
  fi
  echo 'eval "$('"$brew_exe"' shellenv)"' >> "${HOME}/.zprofile"
  echo 'eval "$('"$brew_exe"' shellenv)"' >> "/var/root/.profile"
  eval "$(${brew_exe} shellenv)"
  su - "$userdata_admin_username" -c "brew install wireguard-tools socat"
  wg_dir="/usr/local/etc/wireguard"
  interface="utun0"
else
  if [ "$platform" = "Raspbian" ]; then
    echo "ufw is required, but not installed by default on Raspbian."
    apt install --yes ufw
  fi
  # Next two lines are needed only if ubuntu <= 19.04
  # add-apt-repository --yes ppa:wireguard/wireguard
  # apt-get update
  # apt install --yes wireguard-dkms wireguard-tools socat
  apt install --yes wireguard socat
  wg_dir="/etc/wireguard"
  interface="wg0"
fi

echo "Creating wireguard configuration..."
mkdir -p "$wg_dir" && chown root:wheel "$wg_dir" && chmod 700 "$wg_dir"
wg genkey | tee "${wg_dir}/privatekey" | wg pubkey > "${wg_dir}/publickey"
chmod 400 "${wg_dir}/privatekey"

cat <<EOF >${wg_dir}/${interface}.conf
[Interface]
ListenPort = 51820
SaveConfig = true
Address = ${userdata_wireguard_address}
EOF
echo "PrivateKey = $(cat ${wg_dir}/privatekey)" >> ${wg_dir}/${interface}.conf
cat <<EOF >>${wg_dir}/${interface}.conf

[Peer]
PublicKey = pz/hyQ8EKY7nSoaCFAgd7SIl3SFDnrb02CT32VksTg8=
AllowedIPs = 192.168.192.1
EOF

if [ "$platform" = "MacOS" ]; then
  echo "Sharing public key on wg port. Run this command to get it:"

  ip=$(ifconfig -au inet | grep inet | grep -v 127.0.0.1 | awk '{print $2}' | head -1)
  # ip=$(ifconfig en1 | grep 'inet ' | awk '{print $2}')
  echo "echo | socat udp4:${ip}:51820 -"
  cat ${wg_dir}/publickey| socat -u STDIN udp4-listen:51820
  echo "Shared. Now starting wg..."
  wg-quick up utun0

  echo "Block ssh"
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
  if [ "$allow_ssh_from_provisioner" = "true" ]; then
    cat <<EOS >>/etc/pf.rules/pfssh.rule
pass in inet proto tcp from 192.168.192.1/32 to any port 22 no state
EOS
  fi
  pfctl -f /etc/pf.conf && pfctl -E
  echo "Starting ssh"
  systemsetup -setremotelogin on
  echo "1) Update 'public_keys'"
  echo "2) Remove any old keys for this host."
  echo "3) Run 'make provisioner-wireguard'"
  echo "4) Provision the new macOS machine."
else
  ufw allow 51820/udp

  cat ${wg_dir}/publickey| socat -u STDIN udp4-listen:51820
  service wg-quick@${interface} start
  systemctl enable wg-quick@${interface}
fi

echo "Done"
