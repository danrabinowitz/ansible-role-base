#!/bin/bash

# Exit immediately if any command fails.
set -e

# Print a message to stderr when attempting to expand a variable that is not set. Also, immediately exit.
set -u

# Cause pipelines to fail on the first command which fails instead of dying later on down the pipeline.
set -o pipefail

set -x
################################################################################
run_function="${run_function:-main}"

################################################################################
# There are many options for disk encryption.
# Here we use LUKS for Full Disk Encryption. There is a nice overview of encryption strategies on the arch wiki here: https://wiki.archlinux.org/title/dm-crypt/Encrypting_an_entire_system#Overview
# For my purposes, it seems like LVM on LUKS will generally be most appropriate. See details here: https://wiki.archlinux.org/title/dm-crypt/Encrypting_an_entire_system#LVM_on_LUKS

# We're going for something like this:
# +-----------------------------------------------------------------------+ +----------------+
# | Logical volume 1      | Logical volume 2      | Logical volume 3      | | Boot partition |
# |                       |                       |                       | |                |
# | [SWAP]                | /                     | /home                 | | /boot          |
# |                       |                       |                       | |                |
# | /dev/MyVolGroup/swap  | /dev/MyVolGroup/root  | /dev/MyVolGroup/home  | |                |
# |_ _ _ _ _ _ _ _ _ _ _ _|_ _ _ _ _ _ _ _ _ _ _ _|_ _ _ _ _ _ _ _ _ _ _ _| | (may be on     |
# |                                                                       | | other device)  |
# |                         LUKS2 encrypted partition                     | |                |
# |                           /dev/sda1                                   | | /dev/sdb1      |
# +-----------------------------------------------------------------------+ +----------------+

# Note: Some other detailed notes are here: https://gist.github.com/huntrar/e42aee630bee3295b2c671d098c81268
# Also, a page here which might be nice: https://help.ubuntu.com/community/Full_Disk_Encryption_Howto_2019

# Note: There are multiple options for unlocking LUKS on system boot. Some options were discussed in the DO Slack on Oct 24, 2023. I saved a screenshot in my email with subject "How are you unlocking LUKS on headless homelab hardware?"
# Here are some options:
# 1) TPM + SecureBoot + weeks of research. Not at this time.
# 2) Keys on USB: 2FA is a cool idea. Might not be quite right for my needs.
# 3) dropbear-initramfs: https://www.cyberciti.biz/security/how-to-unlock-luks-using-dropbear-ssh-keys-remotely-in-linux/
# 4) clevis/tang: I don't think this would suit my needs.
# 5) virsh console / interactive serial: Nice and easy. Second choice, after dropbear-initramfs

# I'll use dropbear ssh.
# This may also be good: # https://blog.gradiian.io/migrating-to-cockpit-part-i/


# Option for remote devices: https://tavianator.com/2022/remote_reboots.html 
# https://github.com/mabels/initramfs-tools-tailscale


function lvm_on_luks {
  create_partitions
  create_luks_container
  create_logical_volumes
  format_filesystems
  mount_filesystems

  format_and_mount_boot_filesystem

  # For this next step, I'm not clear yet how much to use steps 4.4 and 4.5 from https://wiki.archlinux.org/title/dm-crypt/Encrypting_an_entire_system#LVM_on_LUKS versus steps 2 - 6 from https://www.cyberciti.biz/security/how-to-unlock-luks-using-dropbear-ssh-keys-remotely-in-linux/
  # Also, I'll need to choose between mkinitcpio vs dracut.
  # dracut is used by Fedora, RHEL, Gentoo, and Debian, among others. Arch uses mkinitcpio by default.
  recreate_initial_ramdisk_image

}

function create_partitions {
  root_partition_device="/dev/$(lsblk --list | grep 'part /$' | awk '{print $1}')"
  disk_device="/dev/$(lsblk -no pkname "$root_partition_device")"

  >&2 printf "Partitioning disk %s\n" "$disk_device"

  if [ -n "$VERBOSE" ]; then
    sgdisk "$disk_device" -p
  fi

  >&2 printf "Erasing partitions on disk\n"
  sgdisk "$disk_device" --zap-all
  sgdisk "$disk_device" --clear
  sgdisk "$disk_device" --verify

  if [ -n "$VERBOSE" ]; then
    sgdisk "$disk_device" -p
  fi

  create_partition "$disk_device" 1 "+200M" "8300" "Unencrypted Boot"
  create_partition "$disk_device" 15 ""      "8e00" "LUKS Encrypted for Linux LVM"

  if [ -n "$VERBOSE" ]; then
    sgdisk "$disk_device" -p
  fi

  LUKS_LVM_PART_INDEX=15
  LUKS_LVM_PART="${disk_device}${LUKS_LVM_PART_INDEX}"

  >&2 printf "Done partitioning disk\n"
}

function create_partition {
  local disk_device="$1"
  local id="$2"
  local size="$3"
  local typecode="$4"
  local name="$5"

  >&2 printf "Creating partition %s: %s\n" "$id" "$name"

  # This was 252 on ubuntu on a qemu machine.
  # Why? How do I know what number to use?
  local major_device_number="252"

  if [ ! -e "${disk_device}${id}" ]; then
    mknod "${disk_device}${id}" b "$major_device_number" "$id"
  fi

  if [ "$size" == "" ]; then
    sgdisk "$disk_device" --largest-new="$id"
  else
    sgdisk "$disk_device" --new="$id":0:"$size"
  fi
  sgdisk "$disk_device" --change-name="$id":"$name"
  sgdisk "$disk_device" --typecode="$id":"$typecode"
  if [ -n "$VERBOSE" ]; then
    sgdisk "$disk_device" --info="$id"
  fi
}

function create_luks_container {
  >&2 printf "TODO: ---------- Verify/Review/Change/Update the 'cryptsetup' options!\n"

  >&2 printf "Ready to create the LUKS encrypted container on %s. Please enter the chosen password twice.\n" "$LUKS_LVM_PART"

  # cryptsetup luksFormat /dev/sda1
  # cryptsetup -v -y luksFormat --type luks2 "$LUKS_LVM_PART"
  cryptsetup -v -y -c aes-xts-plain64 -s 512 -h sha512 -i 5000 --use-random luksFormat "$LUKS_LVM_PART"

  >&2 printf "Encrypted volume created. Ready to mount the unencrypted LVM device at /dev/mapper/cryptlvm ...\n"

  >&2 printf "\nPlease enter your password again to decrypt and to proceed with setup.\n"
  # cryptsetup open /dev/sda1 cryptlvm
  cryptsetup luksOpen "$LUKS_LVM_PART" cryptlvm

  # lvmdiskscan


}

################################################################################
function validate {
  kernel_v=$(uname -r)
  echo "Kernel version: $kernel_v"
}
################################################################################
# TODO: Consider using getopts instead of ENV vars

function main {
  validate # Ensure that arguments and parameters are present and valid
  lvm_on_luks

  >&2 printf "Done!\n"
}
################################################################################
function function_runner {

  >&2 printf "TODO: Abort unless Linux\n"

  case "$run_function" in
    main)
      main
      ;;

    *)
      >&2 printf "FATAL ERROR: Unknown function to run: %s\n" "$run_function"
      exit 1
      ;;
  esac
}
################################################################################
if [[ $UID -ne 0 ]]; then
  sudo -p 'Restarting as root, password: ' run_function="$run_function" bash "$0" "$@"
  exit $?
fi

function_runner
