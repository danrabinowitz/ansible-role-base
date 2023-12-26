#!/bin/bash

# Exit immediately if any command fails.
set -e

# Print a message to stderr when attempting to expand a variable that is not set. Also, immediately exit.
set -u

# Cause pipelines to fail on the first command which fails instead of dying later on down the pipeline.
set -o pipefail

# set -x
################################################################################
# This script is designed to be run in two cases:
# 1) from cloud-init, from a per-once script
# 2) manually, when setting up a new machine that doesn't use cloud-init

# NOTE: Do not write files under /tmp during boot because of a race with systemd-tmpfiles-clean that can cause temp files to get cleaned during the early boot process. Use /run/somedir instead to avoid race LP:1707222.
# ref: https://cloudinit.readthedocs.io/en/latest/topics/modules.html#write-files

# If running this manually, run something like this:
# curl -fsS --output /tmp/bootstrap2.sh "https://raw.githubusercontent.com/danrabinowitz/ansible-role-base/master/files/bootstrap2.sh" && tailscale_key="" bash /tmp/bootstrap2.sh
# or
# curl -fsS --output /tmp/bootstrap2.sh "https://raw.githubusercontent.com/danrabinowitz/ansible-role-base/master/files/bootstrap2.sh" && tailscale_key="" run_function="install_tailscale" bash /tmp/bootstrap2.sh

################################################################################
function install_tailscale {
  >&2 printf "Installing Tailscale...\n"

  if [ "$(lsb_release --id --short)" == "Ubuntu" ]; then
    codename=$(lsb_release --codename --short)

    # mkdir -p --mode=0755 /usr/share/keyrings

    # Get the tailscale keyring
    curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${codename}.noarmor.gpg" -o /usr/share/keyrings/tailscale-archive-keyring.gpg

    # Add the tailscale repository
    curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${codename}.tailscale-keyring.list" | tee /etc/apt/sources.list.d/tailscale.list

    apt-get update && apt-get -y install tailscale

  else
    >&2 printf "Unsupported OS\n"
    exit 1
  fi

  >&2 printf "Tailscale installed. Connecting...\n"
  tailscale up -authkey "$tailscale_key"
}

################################################################################
run_function="${run_function:-main}"
skip_tailscale="${skip_tailscale:-}"
tailscale_key="${tailscale_key:-}"

function validate {
  >&2 printf "Validating...\n"

  if [ -z "$skip_tailscale" ]; then
    >&2 printf "Validating: tailscale_key...\n"
    if [ -z "$tailscale_key" ]; then
      >&2 printf "FATAL ERROR: tailscale_key is required\n"
      exit 1
    fi
  fi
}

function secure {
  >&2 printf "Securing...\n"
}

function access {
  >&2 printf "Ensuring access...\n"

  if [ -z "$skip_tailscale" ]; then
    install_tailscale
  fi
}
################################################################################
# TODO: Consider using getopts instead of ENV vars

function main {
  # printf "Start: STDOUT\n"
  # >&2 printf "Start: STDERR\n"
  # console_tty="/dev/ttyAMA0"
  # printf "Start: Console\n" > "$console_tty"

  validate # Ensure that arguments and parameters are present and valid
  secure # Ensure that the system is locked down
  access # Ensure that admin access is configured

  >&2 printf "bootstrap: Done!\n"
}
################################################################################
function function_runner {

  case "$run_function" in
    main)
      main

      ;;

    install_tailscale)
      install_tailscale
      ;;

    *)
      >&2 printf "FATAL ERROR: Unknown function to run: %s\n" "$run_function"
      exit 1
      ;;
  esac
}
################################################################################
if [[ $UID -ne 0 ]]; then
  sudo -p 'Restarting as root, password: ' tailscale_key="$tailscale_key" run_function="$run_function" bash $0 "$@"
  exit $?
fi

function_runner
