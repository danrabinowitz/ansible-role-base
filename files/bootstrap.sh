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
set +u
userdata_wireguard_address="$userdata_wireguard_address"
userdata_admin_username="$userdata_admin_username"
set -u
################################################################################

function display_steps {
  if [ "$(uname -s)" = "Darwin" ]; then
    echo "To bootstrap a mac:"
    echo "1) Install macOS"
    echo "   -> While macOS is installing, allocate an ip address for the new machine"
    echo "2) Connect to network"
    echo "3) Create an account which will be the admin account"
    echo "4) Open Terminal and run this script ( https://d2r.io/macos1 )"
    echo "   As root?"
  else
    echo "Use cloud init"
  fi
}
display_steps

function usage {
  echo "userdata_admin_username=my-admin-user userdata_wireguard_address=a.b.c.d bootstrap.sh"
  exit 1
}

# Validate params
echo "TODO: Add code to rerun as root if not root."

if [ -z "$userdata_admin_username" ]; then
  echo "userdata_admin_username is required"
  usage
fi

if [ -z "$userdata_wireguard_address" ]; then
  echo "userdata_wireguard_address is required"
  usage
fi
################################################################################
echo "Checking for home directory for ${userdata_admin_username}..."
if [ "$(uname -s)" = "Darwin" ]; then
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
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAZ0+EyH5FgErxe7B5Vd5NT18vlaBVPC1yt9hlwGCO2J dan@mbp" > "${home}/.ssh/authorized_keys"
chown "$userdata_admin_username" "${home}/.ssh"
chmod 600 "${home}/.ssh/authorized_keys"

echo "Installing wireguard..."
if [ "$(uname -s)" = "Darwin" ]; then
  echo "TODO: Explore installing wireguard-go on macOS without requiring homebrew."
  curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh > /tmp/brew-install.sh
  chmod 755 /tmp/brew-install.sh
  # /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
  # brew install wireguard-tools socat
  su - djr -c "/tmp/brew-install.sh && /usr/local/bin/brew install wireguard-tools socat"
  wg_dir="/usr/local/etc/wireguard"
  interface="utun0"
else
  # Next two lines are needed only if ubuntu <= 19.04
  # add-apt-repository --yes ppa:wireguard/wireguard
  # apt-get update
  # apt install --yes wireguard-dkms wireguard-tools socat
  apt install --yes wireguard socat
  wg_dir="/etc/wireguard"
  interface="wg0"
fi

echo "Creating wireguard configuration..."
mkdir -p "$wg_dir" && chown root:root "$wg_dir" && chmod 700 "$wg_dir"
wg genkey | tee "${wg_dir}/privatekey" | wg pubkey > "${wg_dir}/publickey"

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

if [ "$(uname -s)" = "Darwin" ]; then
  echo "Sharing public key on wg port..."
  cat ${wg_dir}/publickey| socat -u STDIN udp4-listen:51820
  echo "Shared. Now starting wg..."
  wg-quick up utun0
  cat <<EOS >/etc/pf.conf

block return in proto tcp from any to any port 22
pass in inet proto tcp from 192.168.192.1/32 to any port 22 no state
EOS
  pfctl -f /etc/pf.conf && pfctl -E
  echo "Starting ssh"
  systemsetup -setremotelogin on
else
  ufw allow 51820/udp

  cat ${wg_dir}/publickey| socat -u STDIN udp4-listen:51820
  service wg-quick@${interface} start
  systemctl enable wg-quick@${interface}
fi

echo "Done"